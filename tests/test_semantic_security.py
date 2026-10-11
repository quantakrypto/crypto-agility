"""Meaningful acceptance tests at declaration, parser and local-file boundaries."""
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from tools.verifier import assess, load_manifest
from tools.compatibility import assess_pair
from tools.evidence import verify_local_evidence

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT/'schema/crypto-agility-v2.schema.json').read_text())
EXAMPLE = json.loads((ROOT/'examples/crypto-agility-v2.json').read_text())
NOW = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)

class SemanticSecurityTests(unittest.TestCase):
    def codes(self, m):
        return {f['code'] for f in assess(m, SCHEMA, NOW)['findings']}

    def test_stale_observation_not_refreshed_by_manifest(self):
        m = copy.deepcopy(EXAMPLE)
        m['generatedAt'] = '2026-10-12T00:00:00Z'
        m['observations'][0]['observedAt'] = '2026-10-01T00:00:00Z'
        self.assertIn('stale-observation', self.codes(m))

    def test_contradictory_assertions_not_silently_selected(self):
        m = copy.deepcopy(EXAMPLE)
        m['observations'].append(dict(m['observations'][0], id='conflict', value='unsupported'))
        self.assertIn('conflicting-observations', self.codes(m))

    def test_exception_cannot_suppress_finding(self):
        m = copy.deepcopy(EXAMPLE)
        m['exceptions'] = [{'findingId':'fallback-risk','reason':'ignore','expiresAt':'2026-10-11T00:00:00Z'}]
        self.assertTrue({'fallback-risk','expired-exception','unowned-exception'} <= self.codes(m))

    def test_missing_evidence_subject_rejected(self):
        m = copy.deepcopy(EXAMPLE)
        m['evidence'] = [{'id':'e','mediaType':'application/json','digest':{'algorithm':'sha-256','value':'a'*64}}]
        self.assertIn('schema', self.codes(m))

    def test_profile_bound(self):
        m = copy.deepcopy(EXAMPLE)
        m['profiles'] = [dict(m['profiles'][0], id=str(i)) for i in range(65)]
        self.assertEqual(assess(m, SCHEMA, NOW)['status'], 'invalid')

    def test_invalid_calendar_time_rejected(self):
        m = copy.deepcopy(EXAMPLE)
        m['generatedAt'] = '2026-02-31T00:00:00Z'
        self.assertEqual(assess(m, SCHEMA, NOW)['status'], 'invalid')

    def test_strict_json(self):
        for data in ('{"version":2,"version":1}', '{"x":NaN}', '['*17+']'*17, ' '*1048577):
            with self.subTest(data=data[:30]), self.assertRaises(ValueError):
                load_manifest(data)
        self.assertEqual(load_manifest('{"x":"[[[[\\\""}'), {'x':'[[[["'})

    def test_no_self_verified_method(self):
        m = copy.deepcopy(EXAMPLE)
        m['observations'][0]['method'] = 'verified'
        self.assertEqual(assess(m, SCHEMA, NOW)['status'], 'invalid')

    def test_every_device_class_uses_capabilities_not_label(self):
        server = {'endpointRole':'server','protocol':'TLS 1.3','keyEstablishment':['X25519MLKEM768'],'authentication':['ECDSA']}
        for device in ('browser','server','mobile','network','iot','embedded','industrial','desktop','other'):
            client = dict(server, endpointRole='client', deviceClass=device)
            with self.subTest(device=device):
                self.assertEqual(assess_pair(client,server)['status'],'declared-compatible')
                client['constraints'] = ['offline or insufficient RAM; requires device test']
                self.assertEqual(assess_pair(client,server)['status'],'unknown')

    def test_gateway_is_only_single_hop(self):
        c={'endpointRole':'client','protocol':'TLS 1.3','keyEstablishment':['X25519'],'authentication':['ECDSA']}
        result=assess_pair(c,dict(c,endpointRole='gateway',deviceClass='network'))
        self.assertEqual(result['scope'],'single-hop')
        self.assertEqual(result['status'],'declared-compatible')

    def test_origin_binding_and_serialization(self):
        m=copy.deepcopy(EXAMPLE)
        m['subject']['kind']='origin'
        for subject in ('https://EXAMPLE.org','https://example.org/','https://example.org:443','https://user@example.org','https://example.org:8443'):
            m['subject']['id']=subject
            self.assertIn('invalid-origin',self.codes(m))
        m['subject']['id']='https://example.org'
        result=assess(m,SCHEMA,NOW,expected_subject='https://other.org')
        self.assertIn('subject-mismatch',{f['code'] for f in result['findings']})

    def test_absent_algorithm_inventory_is_unknown(self):
        client = {'endpointRole':'client','protocol':'TLS 1.3','keyEstablishment':[],'authentication':['ECDSA']}
        self.assertEqual(assess_pair(client,dict(client,endpointRole='server'))['status'],'unknown')

    def test_file_unsafe_paths_symlink_fifo_and_size(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'data').write_bytes(b'x'*20)
            (root/'link').symlink_to(root/'data')
            os.mkfifo(root/'pipe')
            for uri in ('file:link','file:pipe','file:../data','file:/data','file:%2e%2e/data','file:data#ignored','file:data'):
                item = {'id':'x','uri':uri,'digest':{'algorithm':'sha-256','value':hashlib.sha256(b'x'*20).hexdigest()}}
                with self.subTest(uri=uri):
                    self.assertEqual(verify_local_evidence({'evidence':[item]},root,max_bytes=10)[0]['status'],'rejected')
