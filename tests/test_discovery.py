import copy
import datetime as dt
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from tools.discovery import DiscoveryClient, _public_addresses, normalize_origin, strict_json

NOW = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)
ORIGIN = 'https://example.com'
BASE = json.loads((Path(__file__).resolve().parents[1] / 'examples/crypto-agility-v2.json').read_text())


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = copy.deepcopy(BASE)
        self.manifest.update(generatedAt='2026-10-11T00:00:00Z', expiresAt='2026-10-13T00:00:00Z')
        self.subject = self.manifest['subject']['id']
        self.client = DiscoveryClient([ORIGIN])
        self.headers = {'content-type': 'application/json', 'etag': '"one"', 'cache-control': 'max-age=60'}

    def response(self, **headers):
        return 200, {**self.headers, **headers}, json.dumps(self.manifest).encode()

    @patch('tools.discovery._request')
    def test_cache_is_bounded_and_defensive(self, request):
        request.return_value = self.response()
        first = self.client.fetch(ORIGIN, self.subject, now=NOW)
        first['manifest']['subject']['id'] = 'mutated'
        self.assertEqual(self.client.fetch(ORIGIN, self.subject, now=NOW)['source'], 'cache')
        request.assert_called_once()

    @patch('tools.discovery._request')
    def test_conditional_get_and_304_preserves_expiry(self, request):
        request.return_value = self.response()
        self.client.fetch(ORIGIN, self.subject, now=NOW)
        request.return_value = 304, {}, b''
        result = self.client.fetch(ORIGIN, self.subject, now=NOW + dt.timedelta(seconds=61))
        self.assertEqual(result['source'], 'revalidated')
        self.assertEqual(request.call_args.args[1]['If-None-Match'], '"one"')
        self.assertEqual(result['manifest']['expiresAt'], self.manifest['expiresAt'])
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.client.fetch(ORIGIN, self.subject, now=NOW + dt.timedelta(days=2))

    @patch('tools.discovery._request')
    def test_last_modified_and_age(self, request):
        headers = {'content-type': 'application/json', 'last-modified': 'Sun, 11 Oct 2026 00:00:00 GMT', 'cache-control': 'max-age=60', 'age': '60'}
        request.return_value = 200, headers, json.dumps(self.manifest).encode()
        self.client.fetch(ORIGIN, self.subject, now=NOW)
        request.return_value = 304, {}, b''
        self.client.fetch(ORIGIN, self.subject, now=NOW)
        self.assertIn('If-Modified-Since', request.call_args.args[1])

    @patch('tools.discovery._request')
    def test_no_store(self, request):
        request.return_value = self.response(**{'cache-control': 'no-store,max-age=600'})
        self.client.fetch(ORIGIN, self.subject, now=NOW)
        self.client.fetch(ORIGIN, self.subject, now=NOW)
        self.assertNotIn('If-None-Match', request.call_args.args[1])
        self.assertEqual(len(self.client._cache), 0)

    @patch('tools.discovery._request')
    def test_change_hint_forces_configured_origin_only(self, request):
        request.return_value = self.response()
        self.client.fetch(ORIGIN, self.subject, now=NOW)
        request.return_value = 304, {}, b''
        self.assertEqual(self.client.fetch(ORIGIN, self.subject, now=NOW, force=True)['source'], 'revalidated')
        self.assertEqual(request.call_args.args[0], 'example.com')

    @patch('tools.discovery._request')
    def test_redirect_error_and_unsolicited_304_fail_closed(self, request):
        for status in [301, 302, 307, 308, 304, 404, 500]:
            request.return_value = status, {'location': 'https://127.0.0.1'}, b''
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.client.fetch(ORIGIN, self.subject, now=NOW)

    @patch('tools.discovery._request')
    def test_wrong_subject_media_type_and_unsafe_etag(self, request):
        request.return_value = self.response()
        with self.assertRaisesRegex(ValueError, 'subject'):
            self.client.fetch(ORIGIN, 'different', now=NOW)
        for headers in [{'content-type': 'text/html'}, {'etag': 'a\r\nX-injected: b'}]:
            request.return_value = self.response(**headers)
            with self.assertRaises(ValueError):
                self.client.fetch(ORIGIN, self.subject, now=NOW)

    @patch('tools.discovery._request')
    def test_size_invalid_json_and_time_limits(self, request):
        for body in [b'x' * 1048577, b'{"version":2,"version":2}', b'[' * 40 + b']' * 40, b'{"n":NaN}']:
            request.return_value = 200, self.headers, body
            with self.assertRaises(ValueError):
                self.client.fetch(ORIGIN, self.subject, now=NOW)
        with self.assertRaises(ValueError):
            self.client.fetch(ORIGIN, self.subject, now=NOW.replace(tzinfo=None))

    def test_bad_origins_and_allowlist(self):
        for origin in ['http://example.com', 'https://user@example.com', 'https://example.com/x', 'https://example.com:22', 'https://example.com?x', 'https://example.com\n', 'https://[::1]']:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                normalize_origin(origin)
        with self.assertRaisesRegex(ValueError, 'allowed'):
            self.client.fetch('https://other.com', self.subject, now=NOW)

    @patch('tools.discovery.socket.getaddrinfo')
    def test_private_mixed_and_transition_dns_rejected(self, dns):
        for ip in ['224.0.0.1', 'ff02::1', '127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '::ffff:8.8.8.8', '2002:0808:0808::1']:
            dns.return_value = [(2, 1, 6, '', ('8.8.8.8', 443)), (2, 1, 6, '', (ip, 443))]
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                _public_addresses('example.com')
        dns.return_value = [(2, 1, 6, '', ('8.8.8.8', 443))]
        self.assertEqual(_public_addresses('example.com'), ['8.8.8.8'])

    def test_json_nesting_and_duplicates(self):
        for raw in [b'[' * 1500 + b']' * 1500, b'{"x":1,"x":2}', b'{"x":Infinity}']:
            with self.assertRaises(ValueError):
                strict_json(raw)


def slow_worker(*args):
    import time
    time.sleep(10)


class TransportTests(unittest.TestCase):
    def test_total_deadline_terminates_blocked_worker(self):
        import multiprocessing
        import time
        from tools.discovery import _request
        real_context = multiprocessing.get_context('spawn')
        class Context:
            Pipe = staticmethod(real_context.Pipe)
            @staticmethod
            def Process(**kwargs):
                kwargs['target'] = slow_worker
                return real_context.Process(**kwargs)
        start = time.monotonic()
        with patch('tools.discovery.multiprocessing.get_context', return_value=Context()):
            with self.assertRaises(TimeoutError):
                _request('example.com', {}, 0.05, 1024)
        self.assertLess(time.monotonic() - start, 3)

    @patch('tools.discovery.socket.create_connection')
    @patch('tools.discovery.ssl.create_default_context')
    def test_connect_uses_vetted_ip_but_validates_hostname(self, context, connect):
        from tools.discovery import _PinnedHTTPS
        conn = _PinnedHTTPS('example.com', '8.8.8.8', 5)
        conn.connect()
        connect.assert_called_once_with(('8.8.8.8', 443), 5)
        context.return_value.wrap_socket.assert_called_once_with(connect.return_value, server_hostname='example.com')

    @patch('tools.discovery._PinnedHTTPS')
    @patch('tools.discovery._public_addresses', return_value=['8.8.8.8'])
    def test_transport_limits_and_closes(self, addresses, connection):
        from tools.discovery import _request_in_worker
        response = connection.return_value.getresponse.return_value
        response.status = 200
        cases = [([('Content-Length', '5000')], [b'']),
                 ([('Content-Encoding', 'gzip')], [b'']),
                 ([('Content-Type', 'application/json'), ('Content-Type', 'text/html')], [b'']),
                 ([], [b'x' * 1025]),
                 ([('Content-Length', '5')], [b'x', b''])]
        for headers, chunks in cases:
            response.getheaders.return_value = headers
            response.read1.side_effect = chunks
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                _request_in_worker('example.com', {}, 5, 1024)
            self.assertTrue(connection.return_value.close.called)


class MonitoringDiscoveryTests(unittest.TestCase):
    @patch('tools.discovery._request', return_value=(200, {'content-type': 'application/json'}, b'{"version":2}'))
    def test_remote_schema_failure_emits_monitor_alert(self, request):
        from tools.discovery import SCHEMA
        from tools.monitor import run_once
        report = run_once(None, SCHEMA, now=NOW, discovery=DiscoveryClient([ORIGIN]),
                          origin=ORIGIN, expected_subject=ORIGIN)
        self.assertEqual(report['assessment']['status'], 'invalid')
        self.assertEqual(report['changes']['alerts'][0]['type'], 'monitor-failure')
