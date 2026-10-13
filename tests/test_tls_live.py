"""Actual local TLS handshakes. Hybrid is REQUIRED when REQUIRE_HYBRID_TLS=1."""
import datetime as dt
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from tools.tls_probe import probe_openssl, _run_bounded

OPENSSL = os.environ.get('OPENSSL_BINARY', 'openssl')


class LiveTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which(OPENSSL):
            raise RuntimeError('OpenSSL is required for TLS interoperability tests')
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(days=1))
                .not_valid_after(now+dt.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
        (cls.root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        expired = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(days=2))
                   .not_valid_after(now-dt.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
        (cls.root/'expired.pem').write_bytes(expired.public_bytes(serialization.Encoding.PEM))
        (cls.root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_connection(self, server_groups, client_groups, *, trust=True, host='localhost', tls='-tls1_3', cert_name='cert.pem'):
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        log = tempfile.TemporaryFile()
        process = subprocess.Popen([OPENSSL, 's_server', '-accept', f'127.0.0.1:{port}', '-cert', str(self.root/cert_name),
                                    '-key', str(self.root/'key.pem'), tls, '-groups', server_groups, '-quiet', '-www'],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read().decode())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.05):
                        break
                except OSError:
                    time.sleep(.01)
            return probe_openssl(host, port, address='127.0.0.1', allow_private=True, groups=client_groups,
                                 cafile=self.root/cert_name if trust else None, openssl=OPENSSL)
        finally:
            process.terminate()
            process.wait(timeout=5)
            log.close()

    def test_classical_authenticated_connection(self):
        result = self.run_connection('X25519', ['X25519'])
        self.assertEqual(result['status'], 'verified-connection', result)
        self.assertFalse(result['hybridKexVerified'])
        self.assertIn(result['peerSignatureType'], ('RSA-PSS', 'rsa_pss_rsae_sha256'))

    def test_untrusted_certificate_rejected(self):
        result = self.run_connection('X25519', ['X25519'], trust=False)
        self.assertFalse(result['certificateValidated'])
        self.assertEqual(result['status'], 'failed')

    def test_hostname_mismatch_rejected(self):
        result = self.run_connection('X25519', ['X25519'], host='wrong.example')
        self.assertFalse(result['certificateValidated'])

    def test_tls12_server_rejected(self):
        result = self.run_connection('X25519', ['X25519'], tls='-tls1_2')
        self.assertEqual(result['status'], 'failed')

    def test_real_hybrid_and_fallback(self):
        code, output = _run_bounded([OPENSSL, 'list', '-tls1_3', '-tls-groups'], 5)
        if code != 0 or b'X25519MLKEM768' not in output:
            if os.environ.get('REQUIRE_HYBRID_TLS') == '1':
                self.fail('Required OpenSSL X25519MLKEM768 support is unavailable')
            self.skipTest('OpenSSL lacks X25519MLKEM768; CI requires OpenSSL 3.5+')
        hybrid = self.run_connection('X25519MLKEM768:X25519', ['X25519MLKEM768', 'X25519'])
        self.assertTrue(hybrid['hybridKexVerified'], hybrid)
        self.assertFalse(hybrid['authenticationPqcVerified'])
        fallback = self.run_connection('X25519', ['X25519MLKEM768', 'X25519'])
        self.assertTrue(fallback['classicalFallbackObserved'], fallback)
        self.assertFalse(fallback['hybridKexVerified'])
        denied = self.run_connection('X25519', ['X25519MLKEM768'])
        self.assertEqual(denied['status'], 'failed')

    def test_expired_trusted_certificate_rejected(self):
        result = self.run_connection('X25519', ['X25519'], cert_name='expired.pem')
        self.assertFalse(result['certificateValidated'])
        self.assertIn('expired', result['transcript'])

    def test_real_measurement_immediately_signed_and_ingested(self):
        import base64
        import jwt
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from tools.attestation import ReplayStore
        from tools.observatory_ingestion import ingest_measurement
        result = self.run_connection('X25519', ['X25519'])
        self.assertEqual(result['status'], 'verified-connection')
        self.assertRegex(result['evidence']['observedAt'], r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z$')
        subject = 'https://localhost:' + str(result['port'])
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        trust = {'issuers': {'local-test': {'keys': {'key': base64.urlsafe_b64encode(public).rstrip(b'=').decode()},
                          'subjects': [subject], 'audiences': ['test-monitor'], 'purposes': ['pqc-observation']}}}
        now = dt.datetime.now(dt.timezone.utc)
        claims = {'iss': 'local-test', 'sub': subject, 'aud': 'test-monitor', 'purpose': 'pqc-observation',
                  'jti': 'live-test', 'iat': int(now.timestamp()), 'exp': int(now.timestamp())+60, 'observation': result['evidence']}
        token = jwt.encode(claims, key, algorithm='EdDSA', headers={'typ': 'pqc-observation+jwt', 'kid': 'key'})
        accepted = ingest_measurement(token, result['transcript'].encode(), trust, subject,
                                      expected_audience='test-monitor', replay_store=ReplayStore(self.root/'live-replay.json'), now=now)
        self.assertTrue(accepted['accepted'], accepted)
        self.assertFalse(accepted['independentlyVerified'])
