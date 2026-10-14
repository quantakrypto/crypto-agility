"""Independent Node/Python wire interoperability, strict trust and resource gates.

The Node fixture uses only Node crypto for signing; this proves JWS wire
interoperability, not independent truth of an issuer's TLS measurement.
"""
import base64
import concurrent.futures
import copy
import datetime as dt
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker
from tools.attestation import ReplayStore, verify_envelope
from tools.monitor import snapshot

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)
ISSUER, SUBJECT, AUDIENCE = 'https://collector.example', 'https://example.org', 'crypto-agility-test'
SCHEMA = json.loads((ROOT / 'schema/crypto-agility-v2.schema.json').read_text())
EXAMPLE = json.loads((ROOT / 'examples/crypto-agility-v2.json').read_text())
HEADER = {'alg': 'EdDSA', 'kid': 'test-key', 'typ': 'pqc-observation+jwt'}


def node(fixture, request):
    result = subprocess.run(['node', str(ROOT / 'tests/fixtures' / fixture)],
                            input=json.dumps(request), text=True, capture_output=True,
                            check=True, timeout=15, cwd=ROOT)
    return json.loads(result.stdout)


class CrossRuntimeJwsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.claims = {'iss': ISSUER, 'sub': SUBJECT, 'aud': AUDIENCE,
                      'iat': int(NOW.timestamp()) - 60, 'exp': int(NOW.timestamp()) + 600,
                      'jti': 'independent-node-statement', 'purpose': 'pqc-observation',
                      'observation': {'label': 'café • 測定', 'value': 'unknown'}}
        cls.issued = node('node_jws_issuer.mjs', {'operation': 'sign', 'header': HEADER, 'claims': cls.claims})
        cls.trust = {'issuers': {ISSUER: {'keys': {'test-key': cls.issued['publicJwk']['x']},
                      'subjects': [SUBJECT], 'audiences': [AUDIENCE], 'purposes': ['pqc-observation'],
                      'maxAgeSeconds': 3600, 'maxLifetimeSeconds': 3600}}}

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = ReplayStore(Path(self.directory.name) / 'replay.json')

    def issue(self, claims=None, header=None, payload_text=None):
        request = {'operation': 'sign', 'privateJwk': self.issued['privateJwk'],
                   'header': header or HEADER, 'claims': claims or self.claims}
        if payload_text is not None:
            request['payloadText'] = payload_text
        return node('node_jws_issuer.mjs', request)['token']

    def verify(self, token, **options):
        return verify_envelope(token, options.pop('trust', self.trust),
                               options.pop('subject', SUBJECT), now=options.pop('now', NOW),
                               expected_audience=AUDIENCE, replay_store=self.store, **options)

    def test_node_pretty_unicode_jws_verified_python_without_reserialization(self):
        result = self.verify(self.issued['token'])
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['claims'], self.claims)
        self.assertIn('not independent', result['limitation'])

    def test_python_jws_crypto_verified_by_independent_node(self):
        raw = base64.urlsafe_b64decode(self.issued['privateJwk']['d'] + '==')
        key = Ed25519PrivateKey.from_private_bytes(raw)
        token = jwt.encode(self.claims, key, algorithm='EdDSA', headers=HEADER)
        self.assertTrue(node('node_jws_issuer.mjs', {'operation': 'verify', 'token': token,
                                                  'publicJwk': self.issued['publicJwk']})['verified'])
        parts = token.split('.')
        replacement = dict(self.claims, sub='https://attacker.example')
        parts[1] = base64.urlsafe_b64encode(json.dumps(replacement).encode()).rstrip(b'=').decode()
        self.assertFalse(node('node_jws_issuer.mjs', {'operation': 'verify', 'token': '.'.join(parts),
                                                   'publicJwk': self.issued['publicJwk']})['verified'])

    def test_independently_signed_adversarial_claims_rejected(self):
        cases = {
            'expired': {'exp': int(NOW.timestamp())},
            'future': {'iat': int(NOW.timestamp()) + 1},
            'wrong-subject': {'sub': 'https://other.example'},
            'wrong-audience': {'aud': 'different-service'},
            'untrusted-issuer': {'iss': 'https://attacker.example'},
            'wrong-purpose': {'purpose': 'deployment-authorization'},
            'boolean-time': {'iat': True},
            'overlong-lifetime': {'exp': int(NOW.timestamp()) + 7200},
        }
        for name, changes in cases.items():
            with self.subTest(name=name):
                result = self.verify(self.issue(dict(self.claims, **changes)))
                self.assertFalse(result['verified'], result)
        # Rejections must not let an attacker consume an otherwise valid token.
        self.assertTrue(self.verify(self.issued['token'])['verified'])

    def test_signed_duplicate_claim_and_remote_key_headers_rejected(self):
        duplicate = json.dumps(self.claims)[:-1] + ', "sub": "https://example.org"}'
        self.assertFalse(self.verify(self.issue(payload_text=duplicate))['verified'])
        for addition in ({'jku': 'https://attacker.example/jwks'}, {'crit': ['b64']}, {'alg': 'HS256'}):
            with self.subTest(addition=addition):
                self.assertFalse(self.verify(self.issue(header={**HEADER, **addition}))['verified'])

    def test_atomic_replay_protection_across_concurrent_verifiers_and_restart(self):
        path = Path(self.directory.name) / 'replay.json'
        def accept(_):
            return verify_envelope(self.issued['token'], self.trust, SUBJECT, now=NOW,
                                   expected_audience=AUDIENCE, replay_store=ReplayStore(path))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(accept, range(8)))
        self.assertEqual(sum(result['verified'] for result in results), 1)
        self.assertEqual({result['reason'] for result in results if not result['verified']}, {'replay'})
        self.assertEqual(accept(None)['reason'], 'replay')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_new_jti_cannot_replace_newer_statement_with_older_issuance(self):
        self.assertTrue(self.verify(self.issued['token'])['verified'])
        earlier = dict(self.claims, jti='fresh-identifier-old-observation', iat=self.claims['iat'] - 1)
        self.assertEqual(self.verify(self.issue(earlier))['reason'], 'observation-rollback')

    def test_key_revocation_applies_without_network_or_cached_trust(self):
        trust = copy.deepcopy(self.trust)
        trust['issuers'][ISSUER]['revokedKeys'] = ['test-key']
        self.assertFalse(self.verify(self.issued['token'], trust=trust)['verified'])


class IndependentManifestConsumerTests(unittest.TestCase):
    def test_node_ajv_and_python_jsonschema_agree_on_structural_corpus(self):
        corpus = [{'id': 'example', 'manifest': copy.deepcopy(EXAMPLE), 'expected': True}]
        def case(name, change):
            manifest = copy.deepcopy(EXAMPLE)
            change(manifest)
            corpus.append({'id': name, 'manifest': manifest, 'expected': False})
        case('unknown-version', lambda x: x.update(version=3))
        case('unknown-field', lambda x: x.update(execute='rm'))
        case('non-utc-timestamp', lambda x: x.update(generatedAt='2026-10-11T10:00:00+01:00'))
        case('impossible-calendar-date', lambda x: x.update(generatedAt='2026-02-30T10:00:00Z'))
        case('too-many-profiles', lambda x: x.update(profiles=x['profiles'] * 33))
        case('empty-profiles', lambda x: x.update(profiles=[]))
        case('independent-verification-self-claim', lambda x: x['observations'][0].update(method='verified'))
        case('invalid-device-class', lambda x: x['profiles'][0].update(deviceClass='universal'))
        case('duplicate-algorithm', lambda x: x['profiles'][0].update(keyEstablishment=['X25519', 'X25519']))
        case('missing-evidence-subject', lambda x: x.update(evidence=[{
            'id': 'e', 'mediaType': 'application/json', 'digest': {'algorithm': 'sha-256', 'value': 'a' * 64}}]))
        case('wrong-digest-length', lambda x: x.update(evidence=[{
            'id': 'e', 'mediaType': 'application/json', 'subjectId': SUBJECT,
            'digest': {'algorithm': 'sha-384', 'value': 'a' * 64}}]))
        validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
        expected = [{'id': item['id'], 'valid': item['expected']} for item in corpus]
        python_results = [{'id': item['id'], 'valid': validator.is_valid(item['manifest'])} for item in corpus]
        node_results = node('node_manifest_consumer.mjs', {'schema': SCHEMA, 'cases': corpus})
        self.assertEqual(python_results, expected)
        self.assertEqual(node_results, expected)

    def test_maximum_profile_matrix_has_bounded_work_and_no_verified_claims(self):
        manifest = copy.deepcopy(EXAMPLE)
        template = manifest['profiles'][0]
        manifest['profiles'] = [{**template, 'id': f'profile-{i}',
                                 'endpointRole': 'client' if i < 32 else 'server'} for i in range(64)]
        # Remove now-dangling references, so this measures the supported matrix.
        manifest['migration'] = []
        start = time.monotonic()
        report = snapshot(manifest, SCHEMA, NOW)
        elapsed = time.monotonic() - start
        self.assertNotEqual(report['assessment']['status'], 'invalid')
        self.assertEqual(len(report['pairs']), 32 * 32)
        self.assertFalse(any(x['assessment']['status'] == 'verified' for x in report['pairs']))
        self.assertLess(elapsed, 5.0, f'64 profile assessment took {elapsed:.3f}s')


class LiveMeasurementPipelineTests(unittest.TestCase):
    """A real PKIX-validated loopback connection through independent JWS to state."""
    def test_live_tls_node_issuer_python_ingestion_monitor_expiry(self):
        import test_tls_live
        from tools.observatory_ingestion import ingest_measurement
        from tools.state import update_state

        fixture = test_tls_live.LiveTLSTests
        fixture.setUpClass()
        self.addCleanup(fixture.tearDownClass)
        result = fixture().run_connection('X25519', ['X25519'])
        self.assertTrue(result['certificateValidated'], result)
        self.assertFalse(result['hybridKexVerified'])
        subject = 'https://localhost:' + str(result['port'])
        now = dt.datetime.now(dt.timezone.utc)
        claims = {'iss': ISSUER, 'sub': subject, 'aud': AUDIENCE,
                  'iat': int(now.timestamp()), 'exp': int(now.timestamp()) + 60,
                  'jti': 'live-loopback-connection', 'purpose': 'pqc-observation',
                  'observation': result['evidence']}
        issued = node('node_jws_issuer.mjs', {'operation': 'sign', 'header': HEADER, 'claims': claims})
        trust = {'issuers': {ISSUER: {'keys': {'test-key': issued['publicJwk']['x']},
                 'subjects': [subject], 'audiences': [AUDIENCE], 'purposes': ['pqc-observation']}}}
        manifest = copy.deepcopy(EXAMPLE)
        manifest.update(generatedAt=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                        expiresAt=(now + dt.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        observations=[], migration=[])
        manifest['subject']['id'] = subject
        with tempfile.TemporaryDirectory() as directory:
            store = ReplayStore(Path(directory) / 'replay.json')
            ingested = ingest_measurement(issued['token'], result['transcript'].encode(), trust, subject,
                                          expected_audience=AUDIENCE, replay_store=store, now=now)
            self.assertTrue(ingested['accepted'], ingested)
            self.assertFalse(ingested['independentlyVerified'])
            first = snapshot(manifest, SCHEMA, now, authenticated_observations=[ingested])
            self.assertEqual(first['measurements'][0]['status'], 'authenticated-observation')
            self.assertFalse(first['measurements'][0]['independentlyVerified'])
            state = Path(directory) / 'monitor.json'
            update_state(state, first)
            later = now + dt.timedelta(seconds=61)
            stale = snapshot(manifest, SCHEMA, later, authenticated_observations=[ingested])
            delta = update_state(state, stale)
            self.assertEqual(stale['measurements'][0]['status'], 'stale')
            self.assertTrue(any(alert['type'] == 'verification-regression'
                                and alert['reason'] == 'measurement-expired' for alert in delta['alerts']), delta)
            self.assertTrue(all(alert['action'] and alert['id'] for alert in delta['alerts']))
            retained = state.read_bytes()
            replay = ingest_measurement(issued['token'], result['transcript'].encode(), trust, subject,
                                        expected_audience=AUDIENCE, replay_store=store, now=now)
            self.assertFalse(replay['accepted'])
            self.assertEqual(state.read_bytes(), retained)

            # Full monitor entry point: real discovery parsing/cache, exact snapshot
            # binding and evidence reuse. Only the HTTP transport is substituted.
            import hashlib
            from unittest.mock import patch
            from tools.discovery import DiscoveryClient
            from tools.monitor import run_once
            raw = json.dumps(manifest, indent=2).encode()
            bound_claims = dict(claims, jti='snapshot-bound-live-connection',
                                snapshotDigest='sha256:' + hashlib.sha256(raw).hexdigest())
            bound = node('node_jws_issuer.mjs', {'operation': 'sign', 'header': HEADER,
                         'claims': bound_claims, 'privateJwk': issued['privateJwk']})
            evidence = {'audience': AUDIENCE, 'replay_store': store}
            for name, data in [('token', bound['token'].encode()),
                               ('transcript', result['transcript'].encode()),
                               ('trust', json.dumps(trust).encode())]:
                evidence[name] = Path(directory) / name
                evidence[name].write_bytes(data)
            remote_state = Path(directory) / 'remote-monitor.json'
            client = DiscoveryClient(['https://manifest.example'])
            cache = {}
            def cycle(instant):
                return run_once(None, SCHEMA, remote_state, instant, discovery=client,
                                origin='https://manifest.example', expected_subject=subject,
                                evidence=evidence, measurement_cache=cache)
            with patch('tools.discovery._request') as transport:
                transport.return_value = (200, {'content-type': 'application/json',
                    'etag': '"snapshot-1"', 'cache-control': 'max-age=300'}, raw)
                initial = cycle(now)
                self.assertEqual(initial['measurements'][0]['status'], 'authenticated-observation', initial)
                cached = cycle(now + dt.timedelta(seconds=1))
                self.assertEqual(cached['measurements'][0]['status'], 'authenticated-observation', cached)
                self.assertEqual(transport.call_count, 1)
                expired_evidence = cycle(now + dt.timedelta(seconds=61))
                self.assertEqual(expired_evidence['measurements'][0]['status'], 'stale')
                self.assertIn('measurement-expired', {x['code'] for x in expired_evidence['assessment']['findings']})
                original = remote_state.read_bytes()
                transport.return_value = (304, {}, b'')
                expired_manifest = cycle(now + dt.timedelta(hours=2))
                self.assertEqual(expired_manifest['assessment']['status'], 'invalid')
                retained_baseline = json.loads(original)
                after_failure = json.loads(remote_state.read_bytes())
                bookkeeping = ('pendingAlerts', 'activeFailures')
                self.assertEqual({k: v for k, v in after_failure.items() if k not in bookkeeping},
                                 {k: v for k, v in retained_baseline.items() if k not in bookkeeping})
                self.assertTrue(any(a['type'] == 'monitor-failure' for a in after_failure['pendingAlerts']))
                self.assertEqual(expired_manifest['changes']['alerts'][0]['type'], 'monitor-failure')


if __name__ == '__main__':
    unittest.main()
