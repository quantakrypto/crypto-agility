"""Bounded HTTPS discovery. HTTP freshness never extends evidence freshness."""
from dataclasses import dataclass
import datetime as dt
from email.utils import parsedate_to_datetime
import http.client
import ipaddress
import json
import multiprocessing
from pathlib import Path
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from tools.verifier import parse_time, load_manifest

WELL_KNOWN = '/.well-known/crypto-agility.json'
SCHEMA = json.loads((Path(__file__).resolve().parents[1] / 'schema/crypto-agility-v2.schema.json').read_text())


# The same bounded parser is used by offline and remote consumers.
strict_json = load_manifest


def normalize_origin(origin):
    if not isinstance(origin, str) or not origin.isascii() or any(ord(c) < 33 or ord(c) == 127 for c in origin):
        raise ValueError('invalid origin')
    parts = urlsplit(origin)
    if (parts.scheme != 'https' or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path not in ('', '/') or parts.query or parts.fragment
            or parts.port not in (None, 443)):
        raise ValueError('HTTPS origin on port 443 required')
    host = parts.hostname.lower()
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host):
        raise ValueError('DNS hostname required')
    return 'https://' + host


def _public_addresses(host):
    answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ips = sorted({item[4][0] for item in answers})
    if not ips or len(ips) > 32:
        raise ValueError('invalid DNS address count')
    # Reject mixed public/private answers, mapped IPv6 and transition mechanisms.
    for value in ips:
        ip = ipaddress.ip_address(value)
        if not ip.is_global or ip.is_multicast or ip.is_reserved or getattr(ip, 'ipv4_mapped', None) or getattr(ip, 'sixtofour', None) or getattr(ip, 'teredo', None):
            raise ValueError('non-public network destination')
    return ips


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # Connect only to the vetted literal. SNI and certificate validation still
        # use the original hostname. Never resolve a second time or use proxies.
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _request_in_worker(host, headers, timeout, max_bytes):
    ips = _public_addresses(host)
    connection = _PinnedHTTPS(host, ips[0], timeout)
    deadline = time.monotonic() + timeout
    try:
        connection.request('GET', WELL_KNOWN, headers=headers)
        response = connection.getresponse()
        raw_headers = response.getheaders()
        result_headers = {}
        for key, value in raw_headers:
            key = key.lower()
            if key in result_headers:
                raise ValueError('duplicate HTTP response header')
            result_headers[key] = value
        if response.status != 200:
            return response.status, result_headers, b''
        if result_headers.get('content-encoding', 'identity').lower() != 'identity':
            raise ValueError('compressed response not accepted')
        length = result_headers.get('content-length')
        if length is not None and (not length.isdecimal() or int(length) > max_bytes):
            raise ValueError('response length limit')
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('response deadline')
            if connection.sock:
                connection.sock.settimeout(remaining)
            # read1 returns after one underlying read, so trickle traffic cannot
            # restart the total response deadline for each received byte.
            chunk = response.read1(min(65536, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise ValueError('response size limit')
        if length is not None and size != int(length):
            raise ValueError('truncated response')
        return response.status, result_headers, b''.join(chunks)
    finally:
        connection.close()


def _worker(pipe, host, headers, timeout, max_bytes):
    try:
        pipe.send(('ok', _request_in_worker(host, headers, timeout, max_bytes)))
    except Exception as exc:
        pipe.send(('error', type(exc).__name__ + ': ' + str(exc)))
    finally:
        pipe.close()


def _request(host, headers, timeout, max_bytes):
    # A process deadline bounds DNS, TLS, slow response headers, and body reads.
    # Socket timeouts alone do not bound trickle traffic or system DNS lookup.
    context = multiprocessing.get_context('spawn')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(send, host, headers, timeout, max_bytes), daemon=True)
    process.start()
    send.close()
    try:
        if not receive.poll(timeout):
            raise TimeoutError('HTTPS discovery total deadline')
        try:
            state, result = receive.recv()
        except EOFError as exc:
            raise ValueError('discovery worker exited without a response') from exc
        if state != 'ok':
            raise ValueError(result)
        return result
    finally:
        receive.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=1)
        if process.is_alive():
            process.kill()
            process.join(timeout=1)


@dataclass(frozen=True)
class _Entry:
    body: bytes
    headers: dict
    fresh_until: dt.datetime


class DiscoveryClient:
    """Explicit allowlist, memory-only cache; no network use until fetch().

    A scheduler may set force=True on a locally authenticated change hint. Hints
    never supply a URL or posture; refetch the configured origin instead.
    """
    def __init__(self, allowed_origins, *, timeout=10, max_bytes=1048576, max_age=300):
        self.allowed = frozenset(normalize_origin(x) for x in allowed_origins)
        if not self.allowed or len(self.allowed) > 256:
            raise ValueError('one to 256 origins required')
        if not 0 < timeout <= 60 or not 0 < max_bytes <= 1048576 or not 0 <= max_age <= 3600:
            raise ValueError('invalid resource limits')
        self.timeout, self.max_bytes, self.max_age = timeout, max_bytes, max_age
        self._cache = {}

    def _validate(self, body, subject, now):
        manifest = strict_json(body)
        try:
            Draft202012Validator(SCHEMA, format_checker=FormatChecker()).validate(manifest)
        except ValidationError as exc:
            raise ValueError('invalid manifest schema: ' + exc.message[:256]) from exc
        if manifest['subject']['id'] != subject:
            raise ValueError('subject mismatch')
        generated, expires = parse_time(manifest['generatedAt']), parse_time(manifest['expiresAt'])
        if generated > now + dt.timedelta(minutes=5) or expires <= now or expires <= generated:
            raise ValueError('manifest expired or future dated')
        return manifest

    def fetch(self, origin, expected_subject, *, now=None, force=False):
        origin = normalize_origin(origin)
        if origin not in self.allowed:
            raise ValueError('origin not allowed')
        now = now or dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            raise ValueError('timezone required')
        key = (origin, expected_subject)
        entry = self._cache.get(key)
        if entry and now < entry.fresh_until and not force:
            return {'manifest': self._validate(entry.body, expected_subject, now), 'source': 'cache', 'body': entry.body}
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity'}
        if entry:
            if entry.headers.get('etag'):
                headers['If-None-Match'] = entry.headers['etag']
            elif entry.headers.get('last-modified'):
                headers['If-Modified-Since'] = entry.headers['last-modified']
        status, received, body = _request(urlsplit(origin).hostname, headers, self.timeout, self.max_bytes)
        if status == 304:
            if not entry or not ('If-None-Match' in headers or 'If-Modified-Since' in headers):
                raise ValueError('unsolicited 304')
            body = entry.body
            received = {**entry.headers, **received}
        elif status != 200:
            # Includes every redirect. No stale-on-error and no destination follow.
            raise ValueError('unexpected HTTP status ' + str(status))
        if len(body) > self.max_bytes:
            raise ValueError('response size limit')
        if received.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
            raise ValueError('application/json required')
        manifest = self._validate(body, expected_subject, now)
        for name in ('etag', 'last-modified'):
            value = received.get(name, '')
            if len(value) > 512 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise ValueError('unsafe HTTP validator')
        directives = [x.strip().lower() for x in received.get('cache-control', '').split(',')]
        ttl = 0
        max_ages = [x.partition('=')[2].strip('"') for x in directives if x.startswith('max-age=')]
        if len(max_ages) == 1 and max_ages[0].isdecimal():
            age = received.get('age', '0')
            if age.isdecimal():
                current_age = int(age)
                if received.get('date'):
                    try:
                        server_date = parsedate_to_datetime(received['date'])
                        current_age = max(current_age, int((now - server_date).total_seconds()))
                    except (TypeError, ValueError, OverflowError):
                        current_age = self.max_age
                ttl = max(0, min(int(max_ages[0]), self.max_age) - current_age)
        if 'no-cache' in directives:
            ttl = 0
        if 'no-store' in directives:
            self._cache.pop(key, None)
        else:
            # One entry per allowed origin prevents attacker-controlled subjects
            # from growing the cache without bound.
            for old in list(self._cache):
                if old[0] == origin:
                    del self._cache[old]
            self._cache[key] = _Entry(body, dict(received), min(now + dt.timedelta(seconds=ttl), parse_time(manifest['expiresAt'])))
        return {'manifest': manifest, 'source': 'revalidated' if status == 304 else 'http', 'body': body}
