"""RFC9964 JWS interop: actual Node ML-DSA signer -> OpenSSL/PyJWT verifier."""
import base64
import copy
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.attestation import verify_envelope, ReplayStore, TOKEN_TYPE

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)


class MLDSATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('node'):
            raise RuntimeError('Node 24.6+ is required for ML-DSA interoperability')
        cls.claims = {'iss': 'authority', 'sub': 'https://example.org', 'aud': 'monitor',
                      'jti': 'mldsa-test', 'iat': int(NOW.timestamp())-30,
                      'exp': int(NOW.timestamp())+60, 'purpose': 'pqc-observation',
                      'observation': {'group': 'X25519MLKEM768'}, 'snapshotDigest': 'sha256:test'}
        cls.header = {'alg': 'ML-DSA-65', 'kid': 'kms-key', 'typ': TOKEN_TYPE}
        cls.fixture = cls.sign()

    @classmethod
    def sign(cls, **kwargs):
        request = dict(claims=cls.claims, header=cls.header, **kwargs)
        completed = subprocess.run(['node', str(ROOT/'tests/mldsa_sign.mjs')],
                                   input=json.dumps(request), text=True, capture_output=True,
                                   timeout=15, check=True)
        return json.loads(completed.stdout)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = ReplayStore(Path(self.directory.name)/'state.json')
        self.policy = {'keys': {'kms-key': {'alg': 'ML-DSA-65', 'format': 'spki-der',
                                          'publicKey': self.fixture['publicKey']}},
                       'subjects': ['https://example.org'], 'audiences': ['monitor'],
                       'purposes': ['pqc-observation']}
        self.trust = {'issuers': {'authority': self.policy}}

    def verify(self, token=None):
        return verify_envelope(token or self.fixture['token'], self.trust, 'https://example.org',
                               now=NOW, expected_audience='monitor', replay_store=self.store,
                               expected_snapshot='sha256:test')

    def test_node_signature_verifies_with_openssl_and_replay_fails(self):
        result = self.verify()
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['signingAlgorithm'], 'ML-DSA-65')
        self.assertEqual(self.verify()['reason'], 'replay')

    def test_tampered_signature_cannot_poison_replay(self):
        parts = self.fixture['token'].split('.')
        signature = bytearray(base64.urlsafe_b64decode(parts[2]+'='*(-len(parts[2])%4)))
        signature[42] ^= 1
        parts[2] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        self.assertFalse(self.verify('.'.join(parts))['verified'])
        self.assertTrue(self.verify()['verified'])

    def test_context_and_prehashed_messages_are_not_rfc9964(self):
        for mode in ('context', 'prehashed'):
            fixture = self.sign(mode=mode)
            self.policy['keys']['kms-key']['publicKey'] = fixture['publicKey']
            self.assertFalse(self.verify(fixture['token'])['verified'])

    def test_trust_algorithm_cannot_be_selected_by_token(self):
        self.policy['keys']['kms-key']['alg'] = 'EdDSA'
        self.assertEqual(self.verify()['reason'], 'key-algorithm-mismatch')
        self.policy['keys']['kms-key'] = base64.urlsafe_b64encode(b'x'*32).rstrip(b'=').decode()
        self.assertEqual(self.verify()['reason'], 'key-algorithm-mismatch')

    def test_wrong_spki_oid_trailing_bytes_and_short_signature_rejected(self):
        original = self.policy['keys']['kms-key']['publicKey']
        raw = bytearray(base64.urlsafe_b64decode(original+'='*(-len(original)%4)))
        for changed in (bytes(raw)+b'\x00', bytes(raw[:16])+b'\x11'+bytes(raw[17:]), bytes(raw[22:])):
            self.policy['keys']['kms-key']['publicKey'] = base64.urlsafe_b64encode(changed).rstrip(b'=').decode()
            self.assertFalse(self.verify()['verified'])
        self.policy['keys']['kms-key']['publicKey'] = original
        self.assertFalse(self.verify(self.fixture['token'].rsplit('.',1)[0]+'.YWJj')['verified'])

    def test_key_revocation_and_wrong_audience_fail_closed(self):
        self.policy['revokedKeys'] = ['kms-key']
        self.assertFalse(self.verify()['verified'])
        self.policy.pop('revokedKeys')
        self.policy['audiences'] = ['other']
        self.assertFalse(self.verify()['verified'])

    def test_missing_maintained_backend_is_not_success(self):
        with patch.dict(os.environ, {'OPENSSL_BINARY': '/nonexistent/openssl'}):
            self.assertFalse(self.verify()['verified'])
        self.assertTrue(self.verify()['verified'])
