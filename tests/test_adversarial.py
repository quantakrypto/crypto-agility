"""Adversarial and regression tests for the offline assessment boundary."""
import copy
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from tools.monitor import snapshot
from tools.verifier import assess
from tools.state import update_state

ROOT=Path(__file__).resolve().parents[1]
SCHEMA=json.loads((ROOT/"schema/crypto-agility-v2.schema.json").read_text())
EXAMPLE=json.loads((ROOT/"examples/crypto-agility-v2.json").read_text())
NOW=dt.datetime(2026,10,12,tzinfo=dt.timezone.utc)

class AdversarialTests(unittest.TestCase):
 def test_invalid_profile_type_does_not_crash_monitor(self):
  m=copy.deepcopy(EXAMPLE);m["profiles"]="malicious"
  report=snapshot(m,SCHEMA,NOW)
  self.assertEqual(report["assessment"]["status"],"invalid")
  self.assertEqual(report["pairs"],[])
 def test_invalid_evidence_structure(self):
  m=copy.deepcopy(EXAMPLE);m["evidence"]={"not":"an array"}
  self.assertEqual(assess(m,SCHEMA,NOW)["status"],"invalid")
 def test_future_generated_at(self):
  m=copy.deepcopy(EXAMPLE);m["generatedAt"]="2027-01-01T00:00:00Z";m["expiresAt"]="2027-01-02T00:00:00Z"
  self.assertIn("future-manifest",{f["code"] for f in assess(m,SCHEMA,NOW)["findings"]})
 def test_duplicate_ids(self):
  m=copy.deepcopy(EXAMPLE);m["profiles"].append(copy.deepcopy(m["profiles"][0]))
  self.assertIn("duplicate-id",{f["code"] for f in assess(m,SCHEMA,NOW)["findings"]})
 def test_missing_evidence_reference(self):
  m=copy.deepcopy(EXAMPLE);m["observations"][0]["evidenceIds"]=["nonexistent"]
  self.assertIn("missing-evidence",{f["code"] for f in assess(m,SCHEMA,NOW)["findings"]})
 def test_unsupported_version(self):
  m=copy.deepcopy(EXAMPLE);m["version"]=3
  self.assertEqual(assess(m,SCHEMA,NOW)["status"],"invalid")
 def test_invalid_state_is_not_persisted(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"state.json"
   update_state(p,{"subject":"a","assessment":{"status":"unverified","findings":[]},"pairs":[]})
   original=p.read_bytes()
   with self.assertRaises(ValueError):
    update_state(p,{"subject":"a","assessment":{"status":"invalid","findings":[]},"pairs":[]})
   self.assertEqual(p.read_bytes(),original)

if __name__=="__main__":
 unittest.main()
