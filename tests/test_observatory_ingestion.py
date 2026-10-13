import base64
import copy
import datetime as dt
import hashlib
from pathlib import Path
import tempfile
import unittest
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.attestation import ReplayStore
from tools.observatory_ingestion import ingest_measurement

NOW = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)
TRANSCRIPT = b'CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nSignature type: RSA-PSS\nVerification: OK\nNegotiated TLS1.3 group: X25519MLKEM768\nDONE\n'


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.trust = {'issuers': {'observatory': {'keys': {'probe': base64.urlsafe_b64encode(public).rstrip(b'=').decode()},
                      'subjects': ['https://example.org'], 'audiences': ['monitor'], 'purposes': ['pqc-observation']}}}
        self.claims = {'iss': 'observatory', 'sub': 'https://example.org', 'aud': 'monitor', 'jti': 'measurement-1',
                       'purpose': 'pqc-observation', 'iat': int(NOW.timestamp()), 'exp': int(NOW.timestamp())+3600,
                       'observation': {'profile': 'openssl-tls13-v1', 'observedAt': NOW.isoformat(timespec='seconds').replace('+00:00', 'Z'),
                       'endpoint': {'host': 'example.org', 'port': 443, 'address': '192.0.2.1'},
                       'probe': {'name': 'openssl', 'version': 'OpenSSL 3.5.0', 'groups': ['X25519MLKEM768', 'X25519'],
                                 'certificateValidation': 'pkix-hostname', 'exitCode': 0},
                       'transcriptSha256': hashlib.sha256(TRANSCRIPT).hexdigest()}}
        self.store = ReplayStore(Path(self.temp.name)/'replay.json')

    def ingest(self, claims=None, transcript=TRANSCRIPT):
        token = jwt.encode(claims or self.claims, self.key, algorithm='EdDSA', headers={'typ': 'pqc-observation+jwt', 'kid': 'probe'})
        return ingest_measurement(token, transcript, self.trust, 'https://example.org', expected_audience='monitor', replay_store=self.store, now=NOW)

    def test_authenticated_measurement_is_not_independent_verification(self):
        result = self.ingest()
        self.assertTrue(result['accepted'], result)
        self.assertTrue(result['issuerAuthenticated'])
        self.assertTrue(result['observation']['hybridKexObserved'])
        self.assertFalse(result['independentlyVerified'])
        self.assertFalse(result['authenticationPqcVerified'])
        self.assertEqual(self.ingest()['reason'], 'replay')

    def test_rejects_tampered_transcript(self):
        self.assertFalse(self.ingest(transcript=TRANSCRIPT+b'!')['accepted'])

    def test_rejects_unbound_or_stale_measurements(self):
        mutations = [('endpoint', {'host': 'other.org', 'port': 443, 'address': '192.0.2.1'}),
                     ('observedAt', '2026-10-01T00:00:00Z'), ('observedAt', '2026-10-12T00:00:01Z'),
                     ('observedAt', '2026-10-12T00:00:00'), ('profile', 'legacy-database-row')]
        for i, (field, value) in enumerate(mutations):
            with self.subTest(field=field, value=value):
                claims = copy.deepcopy(self.claims)
                claims['jti'] = str(i)
                claims['observation'][field] = value
                self.assertFalse(self.ingest(claims)['accepted'])

    def test_signed_measurement_requires_whole_second_utc_profile(self):
        malformed = ('2026-10-12T00:00:00+00:00', '2026-10-12T01:00:00+01:00',
                     '2026-10-12T00:00:00.000Z', '2026-10-12T00:00:00',
                     '2026-10-12 00:00:00Z', '2026-10-12T00:00:60Z',
                     '2026-02-30T00:00:00Z', 1791763200)
        for i, value in enumerate(malformed):
            with self.subTest(value=value):
                claims = copy.deepcopy(self.claims)
                claims['jti'] = 'timestamp-' + str(i)
                claims['observation']['observedAt'] = value
                self.assertEqual(self.ingest(claims), {'accepted': False, 'reason': 'invalid-measurement'})
                self.assertEqual(self.ingest(claims)['reason'], 'replay')

    def test_rejects_nonvalidated_and_failed_probes(self):
        for i, (field, value) in enumerate([('exitCode', 1), ('exitCode', False), ('certificateValidation', 'disabled'), ('groups', ['X25519'])]):
            with self.subTest(field=field):
                claims = copy.deepcopy(self.claims)
                claims['jti'] = str(i)
                claims['observation']['probe'][field] = value
                self.assertFalse(self.ingest(claims)['accepted'])

    def test_legacy_unsigned_row_is_rejected(self):
        row = {'kexHybrid': True, 'kexGroup': 'X25519MLKEM768'}
        result = ingest_measurement(row, TRANSCRIPT, self.trust, 'https://example.org', expected_audience='monitor', replay_store=self.store, now=NOW)
        self.assertFalse(result['accepted'])

    def test_size_limit_before_signature(self):
        result = ingest_measurement('', b'x'*65537, self.trust, 'https://example.org', expected_audience='monitor', replay_store=self.store, now=NOW)
        self.assertEqual(result['reason'], 'invalid-transcript')

    def test_server_hello_without_completed_authentication_rejected(self):
        transcript = b'ServerHello: X25519MLKEM768\nHelloRetryRequest\n'
        claims = copy.deepcopy(self.claims)
        claims['observation']['transcriptSha256'] = hashlib.sha256(transcript).hexdigest()
        self.assertFalse(self.ingest(claims, transcript)['accepted'])

    def test_effective_validity_includes_local_freshness_policy(self):
        self.trust['issuers']['observatory']['maxAgeSeconds'] = 120
        result = self.ingest()
        self.assertEqual(result['validUntil'], int(NOW.timestamp())+120)
        self.assertLess(result['validUntil'], result['expiresAt'])

    def test_monitor_retains_trusted_hybrid_baseline_through_replayed_evidence(self):
        import json
        from tools.monitor import run_once
        root = Path(__file__).resolve().parents[1]
        directory = Path(self.temp.name)
        manifest = json.loads((root/'examples/crypto-agility-v2.json').read_text())
        manifest['subject']['id'] = 'https://example.org'
        raw = json.dumps(manifest).encode()
        manifest_path = directory/'manifest.json'
        manifest_path.write_bytes(raw)
        schema = json.loads((root/'schema/crypto-agility-v2.schema.json').read_text())
        claims = copy.deepcopy(self.claims)
        claims['snapshotDigest'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
        evidence = {'audience':'monitor','replay_store':self.store}
        for name, content in [('token',b''),('transcript',TRANSCRIPT),('trust',json.dumps(self.trust).encode())]:
            evidence[name] = directory/name
            evidence[name].write_bytes(content)
        def sign():
            evidence['token'].write_text(jwt.encode(claims,self.key,algorithm='EdDSA',headers={'typ':'pqc-observation+jwt','kid':'probe'}))
        sign()
        state = directory/'monitor.json'
        first = run_once(manifest_path,schema,state,NOW,evidence=evidence)
        self.assertTrue(first['measurements'][0]['hybridKexObserved'])
        replay = run_once(manifest_path,schema,state,NOW,evidence=evidence)
        self.assertEqual(replay['measurements'],[])
        self.assertIn({'code':'measurement-rejected','ref':'replay'},replay['assessment']['findings'])
        classical = TRANSCRIPT.replace(b'X25519MLKEM768',b'X25519')
        evidence['transcript'].write_bytes(classical)
        claims['jti'] = 'measurement-2'
        claims['observation']['transcriptSha256'] = hashlib.sha256(classical).hexdigest()
        sign()
        final = run_once(manifest_path,schema,state,NOW,evidence=evidence)
        self.assertFalse(final['measurements'][0]['hybridKexObserved'])
        self.assertIn('tls-regression',{alert['type'] for alert in final['changes']['alerts']})
