"""Parse OpenSSL summaries as observations, never as authenticated evidence.

Only the live collector can establish how OpenSSL was invoked. Imported text may
be fabricated; certificateVerified here describes the transcript's claim only.
"""
import re

HYBRID_GROUPS = frozenset({'X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024'})
CLASSICAL_GROUPS = frozenset({'X25519', 'X448', 'x448', 'prime256v1', 'secp256r1', 'secp384r1', 'secp521r1'})
MAX_TRANSCRIPT_BYTES = 65536


def _one(pattern, output):
    values = re.findall(pattern, output, re.MULTILINE | re.IGNORECASE)
    return values[0].strip() if len(values) == 1 else None


def parse_openssl_observation(output):
    if not isinstance(output, str) or len(output.encode('utf-8')) > MAX_TRANSCRIPT_BYTES:
        raise ValueError('invalid probe output')
    group = _one(r'^\s*(?:Negotiated TLS1\.3 group|Server Temp Key|Peer Temp Key):\s*([^\r\n,]+)', output)
    # ECDH is a key type, not a negotiated NamedGroup identifier.
    protocol = _one(r'^\s*Protocol(?: version)?\s*:\s*(\S+)\s*$', output)
    if protocol is None:
        protocol = _one(r'^New,\s*(TLSv[\d.]+), Cipher is \S+\s*$', output)
    cipher = _one(r'^\s*(?:Ciphersuite|Cipher)\s*:\s*(\S+)\s*$', output)
    if cipher is None:
        cipher = _one(r'^New,\s*TLSv[\d.]+, Cipher is (\S+)\s*$', output)
    verify = re.findall(r'^\s*Verify return code:\s*(\d+)[^\r\n]*$', output, re.M)
    brief_verify = re.findall(r'^Verification: OK\s*$', output, re.M)
    certificate_valid = ((len(verify) == 1 and verify[0] == '0') or
                         (not verify and len(brief_verify) == 1))
    failure = bool(re.search(r'verification error|verify error|alert |handshake failure|no peer certificate', output, re.I))
    completed = protocol == 'TLSv1.3' and cipher is not None and cipher not in ('0000', '(NONE)') and not failure
    certificate_valid = certificate_valid and not failure
    signature = _one(r'^\s*(?:Peer signature type|Signature type):\s*([^\r\n]+)', output)
    return {'tls13Observed': completed, 'protocol': protocol, 'cipher': cipher,
            'negotiatedGroup': group, 'hybridKexObserved': bool(completed and group in HYBRID_GROUPS),
            'certificateVerified': certificate_valid, 'peerSignatureType': signature,
            'authenticationPqcVerified': False,
            'status': 'observed' if completed and group and certificate_valid else 'unknown',
            'note': 'Transcript claims require authenticated provenance; this connection does not establish fleet posture or PQC authentication'}
