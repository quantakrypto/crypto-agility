"""RFC 9964 ML-DSA-65 JWS verification using the OpenSSL 3.5 provider.

The algorithm uses pure ML-DSA with an empty context, never HashML-DSA.
Only signature verification is exposed. Key provisioning remains out of band.
"""
import os
from pathlib import Path
import subprocess
import tempfile

from jwt.algorithms import Algorithm
from tools.tls_probe import _run_bounded

# RFC 9881 Sections 2/4: DER SubjectPublicKeyInfo for OID
# 2.16.840.1.101.3.4.3.18, absent parameters, 1952-byte public key.
# The fixed prefix checks key family/DER framing; OpenSSL parses/verifies the key.
SPKI_PREFIX = bytes.fromhex('308207b2300b0609608648016503040312038207a100')
PUBLIC_KEY_BYTES = 1952
SIGNATURE_BYTES = 3309


class MLDSA65Algorithm(Algorithm):
    """PyJWT algorithm adapter; every cryptographic operation is OpenSSL-owned."""
    def prepare_key(self, key):
        if (not isinstance(key, bytes) or len(key) != len(SPKI_PREFIX) + PUBLIC_KEY_BYTES
                or not key.startswith(SPKI_PREFIX)):
            raise ValueError('RFC9881 ML-DSA-65 SPKI DER key required')
        return key

    def verify(self, msg, key, sig):
        key = self.prepare_key(key)
        if not isinstance(msg, bytes) or len(msg) > 1048576 or len(sig) != SIGNATURE_BYTES:
            return False
        # OPENSSL_BINARY is operator configuration, never taken from token/policy.
        binary = os.environ.get('OPENSSL_BINARY', 'openssl')
        with tempfile.TemporaryDirectory(prefix='pqc-jws-') as directory:
            root = Path(directory)
            (root/'key.der').write_bytes(key)
            (root/'message').write_bytes(msg)
            (root/'signature').write_bytes(sig)
            # No digest or context option: OpenSSL's pure ML-DSA empty-context
            # defaults match RFC9964. Explicit default provider excludes plugins.
            try:
                code, _ = _run_bounded([
                    binary, 'pkeyutl', '-verify', '-rawin', '-pubin',
                    '-inkey', str(root/'key.der'), '-keyform', 'DER',
                    '-in', str(root/'message'), '-sigfile', str(root/'signature'),
                    '-provider', 'default', '-propquery', 'provider=default'], 5, 4096)
            except (OSError, ValueError, subprocess.SubprocessError):
                return False
            return code == 0

    def sign(self, msg, key):
        raise NotImplementedError('signing belongs to the configured authority')

    @staticmethod
    def to_jwk(key_obj, as_dict=False):
        raise NotImplementedError('use independently provisioned SPKI DER trust keys')

    @staticmethod
    def from_jwk(jwk):
        raise NotImplementedError('token-provided JWKs are not accepted')
