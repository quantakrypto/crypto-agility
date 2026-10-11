import hashlib, json, tempfile, unittest
from pathlib import Path
from tools.evidence import verify_local_evidence
from tools.compatibility import assess_pair

class Tests(unittest.TestCase):
 def test_digest_verified(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,"a.txt").write_bytes(b"example")
   e={"id":"a","uri":"file:a.txt","digest":{"algorithm":"sha-256","value":hashlib.sha256(b"example").hexdigest()}}
   self.assertEqual(verify_local_evidence({"evidence":[e]},d)[0]["status"],"digest-valid")
 def test_digest_mismatch(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,"a.txt").write_bytes(b"wrong")
   e={"id":"a","uri":"file:a.txt","digest":{"algorithm":"sha-256","value":hashlib.sha256(b"expected").hexdigest()}}
   self.assertEqual(verify_local_evidence({"evidence":[e]},d)[0]["status"],"digest-mismatch")
 def test_traversal_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   e={"id":"a","uri":"file:../secret","digest":{"algorithm":"sha-256","value":"a"*64}}
   self.assertEqual(verify_local_evidence({"evidence":[e]},d)[0]["status"],"rejected")
 def test_compatibility_is_not_proof(self):
  c={"endpointRole":"client","protocol":"TLS 1.3","keyEstablishment":["X25519MLKEM768"],"authentication":["ECDSA"]}
  s={"endpointRole":"server","protocol":"TLS 1.3","keyEstablishment":["X25519MLKEM768"],"authentication":["ECDSA"]}
  self.assertEqual(assess_pair(c,s)["status"],"declared-compatible")
 def test_mismatch(self):
  c={"endpointRole":"client","protocol":"TLS 1.3","keyEstablishment":["X25519"],"authentication":["ECDSA"]}
  s={"endpointRole":"server","protocol":"TLS 1.3","keyEstablishment":["X25519MLKEM768"],"authentication":["ECDSA"]}
  self.assertEqual(assess_pair(c,s)["status"],"incompatible")
