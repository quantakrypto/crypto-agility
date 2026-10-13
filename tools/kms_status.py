"""Refresh internal trust status through authenticated AWS KMS; no signing."""
import argparse
import base64
import datetime as dt
import hashlib
from pathlib import Path
import re

from tools.attestation import _decode
from tools.mldsa import MLDSA65Algorithm
from tools.state import locked_document
from tools.tls_probe import _run_bounded
from tools.verifier import load_manifest, parse_time

SOURCE = 'aws-kms:DescribeKey+GetPublicKey'
ARN = re.compile(r'arn:aws:kms:([a-z]{2}-[a-z]+-\d):\d{12}:key/[a-f0-9-]{36}')


class KmsStatusUnavailable(ValueError):
    def __init__(self, checked_at):
        super().__init__('authenticated KMS check did not establish active status')
        self.checked_at = checked_at


def private_json(path):
    from tools.consumer import _directory, _read
    path = Path(path)
    with _directory(path.parent) as parent:
        return load_manifest(_read(parent, path.name, 1048576))


def _identity(arn, pin):
    if not isinstance(arn, str) or not ARN.fullmatch(arn) or not isinstance(pin, str) or not re.fullmatch('[a-f0-9]{64}', pin):
        raise ValueError('explicit KMS key ARN and SHA-256 SPKI pin required')


def aws_request(operation, arn, profile=None):
    region = ARN.fullmatch(arn)[1]
    # A fixed TLS endpoint overrides configurable service endpoints. Credentials
    # remain in their existing AWS environment/profile; never read/export them.
    args = ['aws', '--no-cli-pager', '--output', 'json', '--region', region,
            '--endpoint-url', 'https://kms.'+region+'.amazonaws.com',
            '--cli-connect-timeout', '5', '--cli-read-timeout', '10']
    if profile:
        if not re.fullmatch('[A-Za-z0-9_.-]{1,128}', profile):
            raise ValueError('invalid AWS profile name')
        args += ['--profile', profile]
    if operation not in ('describe-key', 'get-public-key'):
        raise ValueError('unsupported KMS status operation')
    code, raw = _run_bounded(args+['kms', operation, '--key-id', arn], 20, 65536)
    if code:
        raise ValueError('authenticated KMS status request failed')
    return load_manifest(raw)


def refresh(policy_path, output_path, *, profile=None, now=None):
    from tools.consumer import _directory
    now = now or dt.datetime.now(dt.timezone.utc)
    policy = private_json(policy_path)
    if set(policy) != {'version', 'keyArn', 'spkiSha256', 'ttlSeconds'} or type(policy['version']) is not int or policy['version'] != 1:
        raise ValueError('explicit KMS status policy required')
    _identity(policy['keyArn'], policy['spkiSha256'])
    ttl = policy['ttlSeconds']
    if type(ttl) is not int or not 60 <= ttl <= 3600 or now.tzinfo is None:
        raise ValueError('bounded status lifetime and aware clock required')
    output_path = Path(output_path)
    with _directory(output_path.parent):
        pass
    with locked_document(output_path) as (previous, save):
        if previous and now < parse_time(previous['checkedAt']):
            raise ValueError('KMS status clock rollback')
        stamp = lambda value: value.astimezone(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        receipt = {'version': 1, 'status': 'unknown', 'keyArn': policy['keyArn'], 'spkiSha256': policy['spkiSha256'],
                   'checkedAt': stamp(now), 'validUntil': stamp(now+dt.timedelta(seconds=ttl)), 'source': SOURCE}
        try:
            meta = aws_request('describe-key', policy['keyArn'], profile)['KeyMetadata']
            public = aws_request('get-public-key', policy['keyArn'], profile)
            if (meta['Arn'] != policy['keyArn'] or meta['KeyState'] != 'Enabled' or meta['Enabled'] is not True
                    or meta['KeySpec'] != 'ML_DSA_65' or meta['KeyUsage'] != 'SIGN_VERIFY'
                    or public['KeyId'] != policy['keyArn'] or public['KeySpec'] != 'ML_DSA_65'
                    or public['KeyUsage'] != 'SIGN_VERIFY' or public['SigningAlgorithms'] != ['ML_DSA_SHAKE_256']):
                raise ValueError('KMS status or algorithm mismatch')
            der = base64.b64decode(public['PublicKey'], validate=True)
            MLDSA65Algorithm().prepare_key(der)
            if hashlib.sha256(der).hexdigest() != policy['spkiSha256']:
                raise ValueError('KMS public key pin mismatch')
            receipt['status'] = 'active'
        except Exception:
            # API/process output can contain sensitive environment details. Persist
            # only an unknown status, never the exception or captured stderr.
            pass
        save(receipt)
        return receipt


def validate_status(spec, key_policy, now):
    if set(spec) != {'mode', 'receipt', 'withdrawal', 'keyArn', 'spkiSha256'} or spec['mode'] != 'aws-kms':
        raise ValueError('invalid KMS consumer policy')
    _identity(spec['keyArn'], spec['spkiSha256'])
    override = private_json(spec['withdrawal'])
    if (set(override) != {'version', 'withdrawn', 'reason'} or type(override['version']) is not int or override['version'] != 1
            or override['withdrawn'] is not False or not isinstance(override['reason'], str) or not 1 <= len(override['reason'].strip()) <= 2048):
        raise ValueError('local trust is withdrawn or unspecified')
    if not isinstance(key_policy, dict) or set(key_policy) != {'alg', 'format', 'publicKey'} or key_policy['alg'] != 'ML-DSA-65' or key_policy['format'] != 'spki-der':
        raise ValueError('pinned ML-DSA-65 trust required for KMS status')
    der = _decode(key_policy['publicKey'])
    MLDSA65Algorithm().prepare_key(der)
    if hashlib.sha256(der).hexdigest() != spec['spkiSha256']:
        raise ValueError('consumer public key pin mismatch')
    receipt = private_json(spec['receipt'])
    if (set(receipt) != {'version', 'status', 'keyArn', 'spkiSha256', 'checkedAt', 'validUntil', 'source'}
            or type(receipt['version']) is not int or receipt['version'] != 1
            or receipt['status'] not in ('active', 'unknown') or receipt['source'] != SOURCE
            or receipt['keyArn'] != spec['keyArn'] or receipt['spkiSha256'] != spec['spkiSha256']):
        raise ValueError('KMS receipt identity or status mismatch')
    checked, until = parse_time(receipt['checkedAt']), parse_time(receipt['validUntil'])
    if not checked <= now < until or not 0 < (until-checked).total_seconds() <= 3600:
        raise ValueError('KMS status receipt is stale, future or unbounded')
    if receipt['status'] != 'active':
        raise KmsStatusUnavailable(checked.timestamp())
    return checked.timestamp()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile')
    args = parser.parse_args()
    receipt = refresh(args.policy, args.output, profile=args.profile)
    print('KMS internal status: '+receipt['status'])
    return 0 if receipt['status'] == 'active' else 1


if __name__ == '__main__':
    raise SystemExit(main())
