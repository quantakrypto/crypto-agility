"""Real HTTPS transport on isolated loopback; production SSRF policy unchanged."""
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from tools.discovery import DiscoveryClient, _PinnedHTTPS, _request_in_worker


class HTTPSDiscoveryTests(unittest.TestCase):
    def test_real_https_200_conditional_304_and_unknown_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
            now = dt.datetime.now(dt.timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                           .public_key(key.public_key()).serial_number(x509.random_serial_number())
                           .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
                           .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
                           .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
            cert_path, key_path = root / 'ca.pem', root / 'key.pem'
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            manifest = json.loads((Path(__file__).resolve().parents[1] / 'examples/crypto-agility-v2.json').read_text())
            manifest['subject']['id'] = 'https://localhost'
            manifest['generatedAt'] = (now - dt.timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
            manifest['expiresAt'] = (now + dt.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
            body = json.dumps(manifest).encode()
            requests = []
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    requests.append((self.path, self.headers.get('If-None-Match')))
                    if self.headers.get('If-None-Match') == '"one"':
                        self.send_response(304)
                        self.send_header('ETag', '"one"')
                        self.end_headers()
                    else:
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('ETag', '"one"')
                        self.send_header('Content-Length', str(len(body)))
                        self.send_header('Cache-Control', 'max-age=0')
                        self.end_headers()
                        self.wfile.write(body)
                def log_message(self, *args):
                    pass
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
            server.socket = server_context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            trusted = ssl.create_default_context(cafile=str(cert_path))
            port = server.server_address[1]
            class LocalPinned(_PinnedHTTPS):
                trust_context = trusted
                def __init__(self, host, address, timeout):
                    super().__init__(host, address, timeout)
                    self._context = self.trust_context
                def connect(self):
                    raw = socket.create_connection((self.address, port), self.timeout)
                    try:
                        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                    except BaseException:
                        raw.close()
                        raise
            try:
                # These two patches are exclusively the test's loopback transport
                # injection. Production never permits loopback or arbitrary ports.
                with patch('tools.discovery._public_addresses', return_value=['127.0.0.1']), patch('tools.discovery._PinnedHTTPS', LocalPinned):
                    # Bypass process isolation only to retain the test injections;
                    # the unchanged request implementation does actual HTTPS I/O.
                    with patch('tools.discovery._request', side_effect=_request_in_worker):
                        client = DiscoveryClient(['https://localhost'])
                        first = client.fetch('https://localhost', 'https://localhost', now=now)
                        second = client.fetch('https://localhost', 'https://localhost', now=now)
                        self.assertEqual(first['source'], 'http')
                        self.assertEqual(second['source'], 'revalidated')
                        self.assertEqual(first['body'], body)
                        self.assertEqual(second['body'], body)
                    LocalPinned.trust_context = ssl.create_default_context()
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        _request_in_worker('localhost', {}, 3, 1048576)
                self.assertEqual(requests, [('/.well-known/crypto-agility.json', None), ('/.well-known/crypto-agility.json', '"one"')])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
