import copy, datetime as dt, json, unittest
from pathlib import Path
from tools.verifier import assess
ROOT=Path(__file__).resolve().parents[1]
S=json.loads((ROOT/"schema/crypto-agility-v2.schema.json").read_text())
M=json.loads((ROOT/"examples/crypto-agility-v2.json").read_text())
NOW=dt.datetime(2026,10,12,tzinfo=dt.timezone.utc)
def codes(m,now=NOW): return {x["code"] for x in assess(m,S,now)["findings"]}
class Tests(unittest.TestCase):
 def test_unsubstantiated(self):
  m=copy.deepcopy(M);m["observations"][0]["method"]="observed"
  self.assertIn("unsubstantiated-observation",codes(m))
 def test_expired(self): self.assertIn("expired",codes(M,dt.datetime(2026,11,1,tzinfo=dt.timezone.utc)))
 def test_missing_profile(self):
  m=copy.deepcopy(M);m["migration"][0]["profileIds"].append("missing")
  self.assertIn("missing-profile",codes(m))
 def test_wrong_subject(self):
  m=copy.deepcopy(M);m["evidence"]=[{"id":"x","mediaType":"application/json","subjectId":"wrong","digest":{"algorithm":"sha-256","value":"a"*64}}]
  self.assertIn("subject-mismatch",codes(m))
 def test_invalid_digest(self):
  m=copy.deepcopy(M);m["evidence"]=[{"id":"x","mediaType":"application/json","digest":{"algorithm":"sha-256","value":"ABC"}}]
  self.assertIn("schema",codes(m))
 def test_deployment(self):
  m=copy.deepcopy(M);m["migration"][0]["status"]="deployed"
  self.assertIn("unsubstantiated-deployment",codes(m))
if __name__=="__main__":unittest.main()
