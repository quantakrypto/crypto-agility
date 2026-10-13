"""Deployment boundary tests using the independent Node JWS fixture issuer."""
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlsplit
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)
SUBJECT = 'https://example.org'
TRANSCRIPT = b'CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nSignature type: RSA-PSS\nVerification: OK\nNegotiated TLS1.3 group: X25519MLKEM768\nDONE\n'


def issue(request):
    result = subprocess.run(['node', str(ROOT/'tests/fixtures/node_jws_issuer.mjs')], input=json.dumps(request), text=True, capture_output=True, check=True, timeout=15)
    return json.loads(result.stdout)


def put(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bundles, self.state = self.root/'bundles', self.root/'state'
        self.bundles.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        from tools.consumer import initialize_state
        initialize_state(self.state, NOW)
        self.config_path = self.root/'config.json'
        self.keys = issue({'operation': 'sign', 'header': {'alg': 'EdDSA', 'kid': 'probe', 'typ': 'pqc-observation+jwt'}, 'claims': {}})
        self.config = {'version': 1, 'issuer': 'observatory', 'subject': SUBJECT, 'audience': 'monitor', 'keyId': 'probe',
                       'keyStatus': {'status': 'active', 'checkedAt': NOW.isoformat().replace("+00:00", "Z"), 'validUntil': (NOW+dt.timedelta(hours=2)).isoformat().replace("+00:00", "Z"), 'source': 'fixture operator decision'},
                       'trust': {'issuers': {'observatory': {'keys': {'probe': self.keys['publicJwk']['x']}, 'subjects': [SUBJECT], 'audiences': ['monitor'], 'purposes': ['pqc-observation']}}}}
        self.save_config()
        self.select('first')

    def save_config(self):
        put(self.config_path, json.dumps(self.config).encode())

    def select(self, jti, group='X25519MLKEM768', subject=SUBJECT):
        manifest = json.loads((ROOT/'examples/crypto-agility-v2.json').read_bytes())
        manifest['subject'] = {'kind': 'origin', 'id': subject}
        raw = json.dumps(manifest).encode()
        transcript = TRANSCRIPT.replace(b'X25519MLKEM768', group.encode())
        claims = {'iss': 'observatory', 'sub': subject, 'aud': 'monitor', 'jti': jti, 'purpose': 'pqc-observation', 'iat': int(NOW.timestamp()), 'exp': int(NOW.timestamp())+3600,
                  'snapshotDigest': 'sha256:'+hashlib.sha256(raw).hexdigest(),
                  'observation': {'profile': 'openssl-tls13-v1', 'observedAt': NOW.isoformat().replace("+00:00", "Z"), 'endpoint': {'host': urlsplit(subject).hostname, 'port': urlsplit(subject).port or 443, 'address': '192.0.2.1'},
                                  'probe': {'name': 'openssl', 'version': 'OpenSSL 3.5.0', 'groups': [group], 'certificateValidation': 'pkix-hostname', 'exitCode': 0}, 'transcriptSha256': hashlib.sha256(transcript).hexdigest()}}
        token = issue({'operation': 'sign', 'privateJwk': self.keys['privateJwk'], 'header': {'alg': 'EdDSA', 'kid': 'probe', 'typ': 'pqc-observation+jwt'}, 'claims': claims})['token']
        values = {'manifest.json': raw, 'observation.jwt': token.encode(), 'transcript.txt': transcript}
        commitment = json.dumps({k: hashlib.sha256(v).hexdigest() for k, v in values.items()}, sort_keys=True, separators=(',', ':')).encode()
        identity = hashlib.sha256(commitment).hexdigest()
        directory = self.bundles/identity
        directory.mkdir(mode=0o700)
        for name, value in values.items():
            put(directory/name, value)
        put(self.bundles/'next', (identity+'\n').encode())
        os.replace(self.bundles/'next', self.bundles/'current')
        self.selected = directory

    def consumer(self):
        from tools.consumer import Consumer
        return Consumer(self.config_path, self.bundles, self.state)

    def test_signed_bundle_cache_restart_replay_and_expiry(self):
        consumer = self.consumer()
        report = consumer.check(NOW)
        self.assertEqual(report['measurements'][0]['status'], 'authenticated-observation', report)
        self.assertEqual(consumer.check(NOW)['measurements'][0]['status'], 'authenticated-observation')
        replay = self.consumer().check(NOW)
        self.assertIn({'code': 'measurement-rejected', 'ref': 'replay'}, replay['assessment']['findings'])
        expired = consumer.check(NOW+dt.timedelta(seconds=3601))
        self.assertIn('measurement-expired', [f['code'] for f in expired['assessment']['findings']])

    def test_switch_regression_and_failure_outbox_survive_repair(self):
        consumer = self.consumer()
        consumer.check(NOW)
        self.config_path.unlink()
        failed = consumer.check(NOW)
        delivery = [a['deliveryId'] for a in failed['changes']['alerts'] if a['type'] == 'monitor-failure'][0]
        self.save_config()
        self.select('classical', 'X25519')
        report = consumer.check(NOW)
        self.assertIn('tls-regression', [a['type'] for a in report['changes']['alerts']])
        self.assertIn(delivery, [a['deliveryId'] for a in report['changes']['alerts']])
        self.assertEqual((self.state/'state.json').stat().st_mode & 0o777, 0o600)

    def test_content_mutation_and_selector_traversal_fail_before_replay(self):
        put(self.selected/'transcript.txt', TRANSCRIPT+b'changed')
        self.assertEqual(self.consumer().check(NOW)['assessment']['status'], 'invalid')
        self.assertEqual(json.loads((self.state/'replay.json').read_bytes())['entries'], {})
        put(self.bundles/'current', b'../config.json')
        self.assertEqual(self.consumer().check(NOW)['assessment']['status'], 'invalid')

    def test_symlink_hardlink_and_public_files_rejected(self):
        target = self.selected/'manifest.json'
        original = target.read_bytes()
        target.unlink()
        external = self.root/'external'
        put(external, original)
        for kind in ('symlink', 'hardlink', 'public'):
            with self.subTest(kind=kind):
                if kind == 'symlink': target.symlink_to(external)
                elif kind == 'hardlink': os.link(external, target)
                else:
                    put(target, original)
                    target.chmod(0o644)
                self.assertEqual(self.consumer().check(NOW)['assessment']['status'], 'invalid')
                target.unlink()
        self.assertEqual(json.loads((self.state/'replay.json').read_bytes())['entries'], {})

    def test_operator_status_required_bounded_and_rechecked_after_cache(self):
        consumer = self.consumer()
        self.assertTrue(consumer.check(NOW)['measurements'])
        original = copy.deepcopy(self.config)
        for change in ({'status': 'unknown'}, {'validUntil': NOW.isoformat().replace("+00:00", "Z")}, {'checkedAt': (NOW+dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z")}, {'validUntil': (NOW+dt.timedelta(days=2)).isoformat().replace("+00:00", "Z")}, {'source': ''}):
            with self.subTest(change=change):
                self.config = copy.deepcopy(original)
                self.config['keyStatus'].update(change)
                self.save_config()
                self.assertEqual(consumer.check(NOW)['assessment']['status'], 'invalid')

    def test_subject_and_trust_scope_are_not_inferred_from_token(self):
        self.select('other-subject', subject='https://other.example')
        self.assertEqual(self.consumer().check(NOW)['assessment']['status'], 'invalid')
        self.assertEqual(json.loads((self.state/'replay.json').read_bytes())['entries'], {})
        self.config['trust']['issuers']['observatory']['subjects'].append('https://other.example')
        self.save_config()
        self.assertEqual(self.consumer().check(NOW)['assessment']['status'], 'invalid')

    def test_selector_switch_during_read_never_mixes_transactions(self):
        from tools import consumer as implementation
        old = self.selected.name
        self.select('second', 'X25519')
        new = self.selected.name
        put(self.bundles/'current', (old+'\n').encode())
        read = implementation._read
        def switch(directory, name, limit):
            raw = read(directory, name, limit)
            if name == 'manifest.json':
                put(self.bundles/'next', (new+'\n').encode())
                os.replace(self.bundles/'next', self.bundles/'current')
            return raw
        consumer = self.consumer()
        with patch.object(implementation, '_read', side_effect=switch):
            first = consumer.check(NOW)
        self.assertEqual(first['measurements'][0]['negotiatedGroup'], 'X25519MLKEM768', first)
        second = consumer.check(NOW)
        self.assertIn('tls-regression', [a['type'] for a in second['changes']['alerts']])

    def test_clock_rollback_rejected_across_restart_even_after_input_failure(self):
        self.config_path.unlink()
        self.consumer().check(NOW+dt.timedelta(seconds=5))
        self.save_config()
        report = self.consumer().check(NOW)
        self.assertEqual(report['assessment']['status'], 'invalid')
        self.assertIn('clock rollback', report['assessment']['findings'][0]['message'])
        self.assertEqual(json.loads((self.state/'replay.json').read_bytes())['entries'], {})

    def test_symlink_ancestor_rejected_and_unsafe_state_reports_nondurability(self):
        alias = self.root/'alias'
        alias.symlink_to(self.bundles, target_is_directory=True)
        from tools.consumer import Consumer
        self.assertEqual(Consumer(self.config_path, alias, self.state).check(NOW)['assessment']['status'], 'invalid')
        self.state.chmod(0o755)
        report = self.consumer().check(NOW)
        self.assertIn('deliveryPersistenceFailure', report['changes'])

    def test_unknown_repository_manifest_never_becomes_origin(self):
        # A correctly committed repository declaration is still the wrong subject kind.
        raw = (self.selected/'manifest.json').read_bytes()
        raw = raw.replace(b'"kind": "origin"', b'"kind": "repository"')
        values = {n: (raw if n == 'manifest.json' else (self.selected/n).read_bytes()) for n in ('manifest.json', 'observation.jwt', 'transcript.txt')}
        identity = hashlib.sha256(json.dumps({k: hashlib.sha256(v).hexdigest() for k, v in values.items()}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        directory = self.bundles/identity
        directory.mkdir(mode=0o700)
        for name, value in values.items(): put(directory/name, value)
        put(self.bundles/'current', (identity+'\n').encode())
        report = self.consumer().check(NOW)
        self.assertEqual(report['assessment']['status'], 'invalid')
        self.assertIn('explicitly declare', report['assessment']['findings'][0]['message'])

    def test_missing_initialized_state_never_resets_replay_protection(self):
        self.consumer().check(NOW)
        for name in ('replay.json', 'state.json', 'clock.json', 'initialized.json'):
            with self.subTest(name=name):
                path = self.state/name
                raw = path.read_bytes()
                path.unlink()
                report = self.consumer().check(NOW)
                self.assertEqual(report['assessment']['status'], 'invalid')
                self.assertFalse(path.exists(), 'lost state must not be recreated')
                put(path, raw)
        from tools.consumer import initialize_state
        with self.assertRaises(ValueError): initialize_state(self.state, NOW)

    def test_malformed_clock_cannot_clear_high_water_mark(self):
        for value in ({}, {'lastNow': True}, {'lastNow': float('nan')}):
            with self.subTest(value=value):
                raw = json.dumps(value).encode()
                put(self.state/'clock.json', raw)
                report = self.consumer().check(NOW)
                self.assertEqual(report['assessment']['status'], 'invalid')
                self.assertEqual((self.state/'clock.json').read_bytes(), raw)

    def test_cli_continues_reporting_missing_configuration_without_acknowledging(self):
        import sys
        self.config_path.unlink()
        result = subprocess.run([sys.executable, '-m', 'tools.consumer', '--config', str(self.config_path), '--bundles', str(self.bundles), '--state-directory', str(self.state), '--iterations', '2', '--interval', '1'], cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        reports = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(reports), 2)
        self.assertTrue(all(r['assessment']['status'] == 'invalid' for r in reports))
        self.assertEqual(reports[0]['changes']['alerts'][0]['deliveryId'], reports[1]['changes']['alerts'][0]['deliveryId'])

    def test_state_loss_after_precheck_never_recreates_replay_or_baseline(self):
        from tools import consumer as implementation
        self.consumer().check(NOW)
        read_bundle = implementation._bundle
        for name in ('replay.json', 'state.json'):
            with self.subTest(name=name):
                path = self.state/name
                raw = path.read_bytes()
                def lose_file(root):
                    values = read_bundle(root)
                    path.unlink()
                    return values
                with patch.object(implementation, '_bundle', side_effect=lose_file):
                    report = self.consumer().check(NOW)
                self.assertNotEqual(report.get('measurements', [{}])[0].get('status') if report.get('measurements') else None, 'authenticated-observation')
                self.assertFalse(path.exists(), 'transaction must not recreate missing initialized state')
                put(path, raw)

    def test_explicit_nondefault_tls_port_is_valid_for_local_bundle(self):
        subject = 'https://example.org:8443'
        self.config['subject'] = subject
        self.config['trust']['issuers']['observatory']['subjects'] = [subject]
        self.save_config()
        self.select('nondefault-port', subject=subject)
        report = self.consumer().check(NOW)
        self.assertEqual(report.get('measurements', [{}])[0].get('status'), 'authenticated-observation', report)

    def test_noncanonical_origin_policy_rejected(self):
        for subject in ('https://example.org/', 'https://example.org:443', 'https://Example.org', 'https://user@example.org', 'https://example.org?q=1', 'https://example.org#fragment'):
            with self.subTest(subject=subject):
                self.config['subject'] = subject
                self.config['trust']['issuers']['observatory']['subjects'] = [subject]
                self.save_config()
                self.assertEqual(self.consumer().check(NOW)['assessment']['status'], 'invalid')


if __name__ == '__main__':
    unittest.main()
