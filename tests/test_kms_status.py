"""Authenticated KMS status policy and pinned consumer integration."""
import base64
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools.mldsa import SPKI_PREFIX
import test_consumer as fixtures
NOW, put = fixtures.NOW, fixtures.put

ARN = 'arn:aws:kms:eu-central-1:123456789012:key/11111111-1111-4111-8111-111111111111'
DER = SPKI_PREFIX + bytes(1952)
PIN = hashlib.sha256(DER).hexdigest()
POLICY = {'version': 1, 'keyArn': ARN, 'spkiSha256': PIN, 'ttlSeconds': 1800}
DESCRIBE = {'KeyMetadata': {'Arn': ARN, 'KeyState': 'Enabled', 'Enabled': True, 'KeySpec': 'ML_DSA_65', 'KeyUsage': 'SIGN_VERIFY'}}
PUBLIC = {'KeyId': ARN, 'KeySpec': 'ML_DSA_65', 'KeyUsage': 'SIGN_VERIFY', 'SigningAlgorithms': ['ML_DSA_SHAKE_256'], 'PublicKey': base64.b64encode(DER).decode()}


class KmsStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.policy = self.root/'policy.json'
        self.output = self.root/'status.json'
        put(self.policy, json.dumps(POLICY).encode())

    def refresh(self, responses=None):
        from tools.kms_status import refresh
        responses = responses or [DESCRIBE, PUBLIC]
        with patch('tools.kms_status.aws_request', side_effect=responses):
            return refresh(self.policy, self.output, now=NOW)

    def test_pinned_active_status_is_short_lived_and_private(self):
        receipt = self.refresh()
        self.assertEqual(receipt['status'], 'active')
        self.assertEqual(receipt['keyArn'], ARN)
        self.assertEqual(receipt['spkiSha256'], PIN)
        self.assertEqual(receipt['validUntil'], '2026-10-12T00:30:00Z')
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_failure_overwrites_active_status_with_unknown(self):
        self.refresh()
        from tools.kms_status import refresh
        with patch('tools.kms_status.aws_request', side_effect=RuntimeError('DO NOT LOG CREDENTIALS')):
            receipt = refresh(self.policy, self.output, now=NOW)
        self.assertEqual(receipt['status'], 'unknown')
        self.assertNotIn('DO NOT LOG', self.output.read_text())

    def test_disabled_alias_wrong_arn_algorithm_and_pin_fail_closed(self):
        mutations = [('KeyState', 'Disabled'), ('Enabled', False), ('KeySpec', 'RSA_2048'), ('Arn', ARN+'other')]
        for name, value in mutations:
            with self.subTest(name=name):
                meta = copy.deepcopy(DESCRIBE)
                meta['KeyMetadata'][name] = value
                self.assertEqual(self.refresh([meta, PUBLIC])['status'], 'unknown')
        for field, value in [('KeyId', ARN+'other'), ('SigningAlgorithms', ['RSASSA_PSS_SHA_256']), ('PublicKey', base64.b64encode(DER[:-1]+b'x').decode())]:
            with self.subTest(field=field):
                public = dict(PUBLIC, **{field: value})
                self.assertEqual(self.refresh([DESCRIBE, public])['status'], 'unknown')

    def test_consumer_requires_fresh_receipt_matching_trust_and_local_override(self):
        from tools.consumer import _config
        fixture = fixtures.ConsumerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        receipt = self.refresh()
        status_path, withdrawal = fixture.root/'kms.json', fixture.root/'withdrawal.json'
        put(status_path, json.dumps(receipt).encode())
        put(withdrawal, b'{"version":1,"withdrawn":false,"reason":"operator allows internal monitoring"}')
        fixture.config['trust']['issuers']['observatory']['keys']['probe'] = {'alg': 'ML-DSA-65', 'format': 'spki-der', 'publicKey': base64.urlsafe_b64encode(DER).rstrip(b'=').decode()}
        fixture.config['keyStatus'] = {'mode': 'aws-kms', 'receipt': str(status_path), 'withdrawal': str(withdrawal), 'keyArn': ARN, 'spkiSha256': PIN}
        fixture.save_config()
        self.assertEqual(_config(fixture.config_path, NOW)['issuer'], 'observatory')
        with self.assertRaises(ValueError): _config(fixture.config_path, NOW+dt.timedelta(minutes=30))
        put(withdrawal, b'{"version":1,"withdrawn":true,"reason":"operator withdrew this key"}')
        with self.assertRaises(ValueError): _config(fixture.config_path, NOW)
        withdrawal.unlink()
        with self.assertRaises(OSError): _config(fixture.config_path, NOW)
        put(withdrawal, b'{"version":1,"withdrawn":false,"reason":"operator allows internal monitoring"}')
        newer = dict(receipt, status='unknown', checkedAt='2026-10-12T00:00:01Z')
        put(status_path, json.dumps(newer).encode())
        fixture.consumer().check(NOW+dt.timedelta(seconds=1))
        put(status_path, json.dumps(receipt).encode())
        rollback = fixture.consumer().check(NOW+dt.timedelta(seconds=2))
        self.assertEqual(rollback['assessment']['status'], 'invalid')
        self.assertIn('status rollback', rollback['assessment']['findings'][0]['message'])
        put(status_path, json.dumps(dict(receipt, checkedAt=newer['checkedAt'])).encode())
        tied = fixture.consumer().check(NOW+dt.timedelta(seconds=3))
        self.assertEqual(tied['assessment']['status'], 'invalid')
        put(status_path, json.dumps(dict(receipt, checkedAt='2026-10-12T00:00:02Z')).encode())
        later = fixture.consumer().check(NOW+dt.timedelta(seconds=4))
        self.assertNotEqual(later['assessment']['status'], 'invalid', later)

    def test_status_clock_rollback_and_unsafe_receipt_target_fail_closed(self):
        self.refresh()
        from tools.kms_status import refresh
        with self.assertRaises(ValueError): refresh(self.policy, self.output, now=NOW-dt.timedelta(seconds=1))
        self.output.unlink()
        self.output.symlink_to(self.policy)
        with self.assertRaises((OSError, ValueError)): refresh(self.policy, self.output, now=NOW)

    def test_consumer_rejects_rollback_of_previously_accepted_status_receipt(self):
        fixture = fixtures.ConsumerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        from tools.consumer import Consumer
        config = dict(fixture.config, _kmsCheckedAt=NOW.timestamp())
        consumer = Consumer(fixture.config_path, fixture.bundles, fixture.state)
        with patch('tools.consumer._config', return_value=config):
            consumer.check(NOW)
        config['_kmsCheckedAt'] -= 1
        with patch('tools.consumer._config', return_value=config):
            result = consumer.check(NOW)
        self.assertEqual(result['assessment']['status'], 'invalid')
        self.assertIn('status rollback', result['assessment']['findings'][0]['message'])


if __name__ == '__main__': unittest.main()
