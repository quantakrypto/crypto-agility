"""Offline adapter for qScan v1 manifests. Never upgrades static evidence to observation."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from tools.discovery import strict_json
from tools.verifier import parse_time

ROOT = Path(__file__).resolve().parents[1]
QSCAN_SOURCE_COMMIT = '6a81b5537eaedf61f259334b4e430e580c35942c'


def encode_manifest(manifest):
    """Deterministic JSON for fixed inputs, not a signature canonicalization scheme."""
    return (json.dumps(manifest, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n').encode('utf-8')


def convert_qscan(raw, *, repository, commit, profiles, expires_at):
    """Require operator identity/profile inputs; never infer runtime from source.

    Keep the exact original bytes as qscan-v1.json beside the result. The evidence
    digest covers those bytes, including qScan version, counts and policy. Binding
    checks catch accidental mismatches; unsigned source data is not authenticated.
    """
    if not isinstance(raw, bytes) or len(raw) > 1048576:
        raise ValueError('qScan input must be bytes, at most 1 MiB')
    source = strict_json(raw)
    schema = json.loads((ROOT / 'schema/crypto-agility.schema.json').read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(source)
    if source['generator']['name'] != 'qScan':
        raise ValueError('qScan generator required')
    if not repository or not commit or source['subject']['repository'] != repository or source['subject']['commit'] != commit:
        raise ValueError('qScan repository/commit binding mismatch or absent')
    if parse_time(expires_at) <= parse_time(source['generatedAt']):
        raise ValueError('expiry must follow source generation')
    subject = {'kind': 'repository', 'id': repository, 'commit': commit}
    eid = 'qscan-source'
    observed_at = source['generatedAt']
    observations = []
    families = source['cbomSummary']['algorithmFamilies']
    if len({f['family'] for f in families}) != len(families):
        raise ValueError('duplicate algorithm family')
    for i, family in enumerate(sorted(families, key=lambda f: f['family'])):
        if family['count'] <= 0:
            continue
        observations.append({'id': f'qscan-family-{i}', 'capability': 'source-uses:' + family['family'],
                             'value': 'supported', 'method': 'inferred', 'observedAt': observed_at, 'evidenceIds': [eid]})
    hybrid = source['posture']['hybridKexInUse']
    observations.append({'id': 'qscan-hybrid-declaration', 'capability': 'hybrid-key-establishment',
                         'value': 'unknown' if hybrid is None else ('supported' if hybrid else 'unsupported'),
                         'method': 'declared', 'observedAt': observed_at, 'evidenceIds': [eid]})
    output = {'version': 2, 'manifestType': 'crypto-agility', 'generatedAt': observed_at,
              'expiresAt': expires_at, 'subject': subject, 'observations': observations,
              'profiles': sorted(copy.deepcopy(profiles), key=lambda p: p['id']), 'migration': [],
              'evidence': [{'id': eid, 'subjectId': repository, 'mediaType': 'application/json',
                            'uri': 'file:qscan-v1.json', 'digest': {'algorithm': 'sha-256', 'value': hashlib.sha256(raw).hexdigest()}}]}
    schema = json.loads((ROOT / 'schema/crypto-agility-v2.schema.json').read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(output)
    if len({p['id'] for p in profiles}) != len(profiles):
        raise ValueError('duplicate profile ID')
    # Supplied profiles are declarations and cannot smuggle references to other
    # evidence. Runtime observations belong in the authenticated ingestion path.
    if any(p.get('evidenceIds') for p in profiles):
        raise ValueError('qScan profiles cannot claim runtime evidence')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--profiles', required=True, type=Path)
    parser.add_argument('--expires-at', required=True)
    args = parser.parse_args()
    if args.source.stat().st_size > 1048576 or args.profiles.stat().st_size > 1048576:
        parser.error('input size limit')
    try:
        output = convert_qscan(args.source.read_bytes(), repository=args.repository, commit=args.commit,
                               profiles=strict_json(args.profiles.read_bytes()), expires_at=args.expires_at)
        print(encode_manifest(output).decode('utf-8'), end='')
    except (ValueError, TypeError, KeyError, OSError, ValidationError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
