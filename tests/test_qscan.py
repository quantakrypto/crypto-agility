import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.qscan import convert_qscan, encode_manifest, QSCAN_SOURCE_COMMIT
from tools.evidence import verify_local_evidence

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT / 'tests/fixtures/qscan-v1.json').read_bytes()
PROFILE = {'id': 'source-project', 'deviceClass': 'server', 'endpointRole': 'server', 'protocol': 'unknown',
           'keyEstablishment': [], 'authentication': [], 'fallback': 'unknown'}
ARGS = {'repository': 'quantakrypto/test-fixture', 'commit': '1' * 40, 'profiles': [PROFILE], 'expires_at': '2026-10-13T00:00:00Z'}


class QscanTests(unittest.TestCase):
    def test_reproducible_and_honest_output(self):
        first = convert_qscan(RAW, **ARGS)
        self.assertEqual(encode_manifest(first), encode_manifest(convert_qscan(RAW, **ARGS)))
        self.assertEqual(first['generatedAt'], '2026-10-11T00:00:00Z')
        methods = {o['capability']: o['method'] for o in first['observations']}
        self.assertEqual(methods['source-uses:RSA'], 'inferred')
        self.assertEqual(methods['hybrid-key-establishment'], 'declared')
        self.assertNotIn('observed', methods.values())
        self.assertEqual(first['evidence'][0]['digest']['value'], hashlib.sha256(RAW).hexdigest())
        self.assertNotIn('attestation', first)

    def test_exact_bytes_evidence_and_tamper(self):
        manifest = convert_qscan(RAW, **ARGS)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'qscan-v1.json'
            source.write_bytes(RAW)
            self.assertEqual(verify_local_evidence(manifest, folder)[0]['status'], 'digest-valid')
            source.write_bytes(RAW + b' ')
            self.assertEqual(verify_local_evidence(manifest, folder)[0]['status'], 'digest-mismatch')

    def test_no_mutation_or_invented_runtime_profile(self):
        before = copy.deepcopy(ARGS)
        convert_qscan(RAW, **ARGS)
        self.assertEqual(ARGS, before)
        with self.assertRaises(ValueError):
            convert_qscan(RAW, **{**ARGS, 'profiles': [{**PROFILE, 'evidenceIds': ['qscan-source']}]})

    def test_identity_expiry_and_duplicate_rejected(self):
        for changes in [{'repository': 'other'}, {'commit': 'bad'}, {'expires_at': '2026-10-10T00:00:00Z'}, {'profiles': [PROFILE, PROFILE]}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                convert_qscan(RAW, **{**ARGS, **changes})
        for raw in [b'{"version":1,"version":1}', b' ' * 1048577]:
            with self.assertRaises(ValueError):
                convert_qscan(raw, **ARGS)

    def test_absence_and_unknown_do_not_prove_security(self):
        source = json.loads(RAW)
        source['posture']['hybridKexInUse'] = None
        source['cbomSummary']['algorithmFamilies'] = []
        result = convert_qscan(json.dumps(source).encode(), **ARGS)
        self.assertEqual(len(result['observations']), 1)
        self.assertEqual(result['observations'][0]['value'], 'unknown')

    def test_real_pinned_qscan_interoperability(self):
        configured = os.environ.get('QSCAN_ROOT')
        if not configured:
            if os.environ.get('REQUIRE_QSCAN_INTEROP') == '1':
                self.fail('QSCAN_ROOT required for integration acceptance')
            self.skipTest('set QSCAN_ROOT to pinned pqc-tools checkout for real integration')
        checkout = Path(configured).resolve()
        head = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
        self.assertEqual(head, QSCAN_SOURCE_COMMIT, 'interop producer must use pinned source')
        command = ['node', str(ROOT / 'tests/qscan_interop.mjs')]
        first = subprocess.check_output(command, cwd=ROOT, timeout=60)
        second = subprocess.check_output(command, cwd=ROOT, timeout=60)
        self.assertEqual(first, second, 'real producer must be reproducible for fixed inputs')
        produced = convert_qscan(first, **ARGS)
        self.assertTrue(any(o['capability'] == 'source-uses:RSA' for o in produced['observations']))
        self.assertEqual(encode_manifest(produced), encode_manifest(convert_qscan(second, **ARGS)))
