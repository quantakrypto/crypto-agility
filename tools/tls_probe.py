"""Bounded, authenticated TLS 1.3 measurement of explicitly authorized endpoints.

OpenSSL performs PKIX chain and DNS/IP identity validation and TLS negotiation.
No application request, session resumption, custom combiner or automatic downgrade.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
import re
import selectors
import socket
import ssl
import subprocess
import time
try:
    from tools.openssl_observation import parse_openssl_observation, HYBRID_GROUPS, CLASSICAL_GROUPS, MAX_TRANSCRIPT_BYTES
except ModuleNotFoundError:
    from openssl_observation import parse_openssl_observation, HYBRID_GROUPS, CLASSICAL_GROUPS, MAX_TRANSCRIPT_BYTES

DEFAULT_GROUPS = ('X25519MLKEM768', 'X25519', 'secp256r1')


def validate_endpoint(host, port=443, timeout=5):
    if (not isinstance(host, str) or not host or len(host) > 253 or
        type(port) is not int or not 1 <= port <= 65535 or
        type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30):
        raise ValueError('invalid probe parameters')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in host.split('.')):
            raise ValueError('host must be an ASCII DNS name or IP literal')


def _run_bounded(args, timeout, max_bytes=MAX_TRANSCRIPT_BYTES, *, diagnostics_only=False):
    """Read a bounded pipe incrementally; never shell out or buffer unlimited output."""
    with subprocess.Popen(args, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL if diagnostics_only else subprocess.PIPE,
                          stderr=subprocess.PIPE if diagnostics_only else subprocess.STDOUT,
                          env={**os.environ, 'LC_ALL': 'C'}) as proc:
        selector = selectors.DefaultSelector()
        selector.register(proc.stderr if diagnostics_only else proc.stdout, selectors.EVENT_READ)
        output = bytearray()
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('OpenSSL timeout')
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, min(4096, max_bytes + 1 - len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        break
                    output.extend(chunk)
                    if len(output) > max_bytes:
                        raise ValueError('OpenSSL output limit exceeded')
            proc.wait(timeout=max(0.001, deadline-time.monotonic()))
            return proc.returncode, bytes(output)
        finally:
            selector.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait()


def probe_openssl(host, port=443, timeout=5, *, groups=DEFAULT_GROUPS,
                  cafile=None, address=None, openssl='openssl', allow_private=False):
    """Use a pinned address; private networks require explicit local authorization.

    The caller must authorize the endpoint independently of a downloaded manifest.
    An unsupported hybrid group fails; it never silently retries classical groups.
    """
    validate_endpoint(host, port, timeout)
    if not isinstance(groups, (list, tuple)) or not groups or len(groups) > 16 or any(not isinstance(g, str) or g not in HYBRID_GROUPS | CLASSICAL_GROUPS for g in groups):
        raise ValueError('unrecognized TLS group')
    # Explicit address avoids resolver timeouts and records the actual probed endpoint.
    if address is None:
        raise ValueError('explicit resolved address required for bounded probe')
    ip = ipaddress.ip_address(address)
    if not allow_private and not ip.is_global:
        raise ValueError('non-public address requires explicit authorization')
    target = f'[{ip}]:{port}' if ip.version == 6 else f'{ip}:{port}'
    args = [openssl, 's_client', '-connect', target, '-servername', host, '-tls1_3',
            '-verify_return_error', '-brief', '-groups', ':'.join(groups)]
    try:
        ipaddress.ip_address(host)
        args += ['-verify_ip', host]
    except ValueError:
        args += ['-verify_hostname', host]
    if cafile:
        args += ['-CAfile', os.fspath(cafile)]
    version_code, version_bytes = _run_bounded([openssl, 'version'], timeout, 4096)
    if version_code:
        raise ValueError('cannot identify OpenSSL')
    code, raw = _run_bounded(args, timeout, diagnostics_only=True)
    parsed = parse_openssl_observation(raw.decode('utf-8', errors='strict'))
    verified = (code == 0 and parsed['status'] == 'observed' and
                parsed['negotiatedGroup'] in groups and parsed['peerSignatureType'] is not None)
    hybrid = verified and parsed['hybridKexObserved']
    classical = verified and parsed['negotiatedGroup'] in CLASSICAL_GROUPS
    observed_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    return {**parsed, 'host': host, 'port': port, 'address': str(ip), 'observedAt': observed_at,
            'status': 'verified-connection' if verified else 'failed',
            'certificateValidated': verified, 'hybridKexVerified': hybrid,
            'classicalFallbackObserved': bool(classical and any(g in HYBRID_GROUPS for g in groups)),
            'authentication': 'certificate-and-handshake-validated' if verified else 'unknown',
            'pqcVerified': False, 'independentlyVerified': False,
            'evidence': {'profile': 'openssl-tls13-v1', 'observedAt': observed_at,
                         'endpoint': {'host': host, 'port': port, 'address': str(ip)},
                         'probe': {'name': 'openssl', 'version': version_bytes.decode().strip(),
                                   'groups': list(groups), 'certificateValidation': 'pkix-hostname', 'exitCode': code},
                         'transcriptSha256': hashlib.sha256(raw).hexdigest()},
            'transcript': raw.decode(),
            'note': 'Verified connection is scoped to one address/time/configuration; PQC authentication and independent corroboration remain unverified'}


def probe(host, port=443, timeout=5):
    """Legacy system-ssl probe; cipher suites cannot identify hybrid key exchange."""
    validate_endpoint(host, port, timeout)
    context = ssl.create_default_context()
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            return {'host': host, 'port': port, 'protocol': connection.version(),
                    'cipher': connection.cipher()[0], 'certificateValidated': True,
                    'keyEstablishment': 'unknown', 'authentication': 'unknown', 'pqcVerified': False,
                    'note': 'TLS cipher suite does not identify the negotiated KEM or certificate signature'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('host')
    p.add_argument('--port', type=int, default=443)
    p.add_argument('--timeout', type=float, default=5)
    p.add_argument('--groups', default=':'.join(DEFAULT_GROUPS))
    p.add_argument('--cafile')
    p.add_argument('--address', required=True, help='explicit authorized IP address, resolved by operator')
    p.add_argument('--allow-private', action='store_true')
    a = p.parse_args()
    try:
        result = probe_openssl(a.host, a.port, a.timeout, groups=a.groups.split(':'),
                               cafile=a.cafile, address=a.address, allow_private=a.allow_private)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {'status': 'failed', 'reason': str(exc), 'pqcVerified': False}
    print(json.dumps(result, indent=2))
    return 0 if result.get('certificateValidated') else 1

if __name__ == '__main__':
    raise SystemExit(main())
