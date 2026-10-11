import unittest
from unittest.mock import patch
from tools.tls_probe import probe

class ProbeTests(unittest.TestCase):
 def test_rejects_invalid_parameters_without_network(self):
  with self.assertRaises(ValueError): probe("example.org",port=0)
  with self.assertRaises(ValueError): probe("example.org",timeout=100)
 def test_probe_does_not_claim_pqc(self):
  class Connection:
   def __enter__(self):return self
   def __exit__(self,*a):return False
   def version(self):return "TLSv1.3"
   def cipher(self):return ("TLS_AES_128_GCM_SHA256","TLSv1.3",128)
  class Context:
   minimum_version=None
   maximum_version=None
   def wrap_socket(self,*a,**k):return Connection()
  with patch("tools.tls_probe.socket.create_connection",return_value=Connection()),patch("tools.tls_probe.ssl.create_default_context",return_value=Context()):
   result=probe("example.org")
  self.assertFalse(result["pqcVerified"])
  self.assertEqual(result["keyEstablishment"],"unknown")
if __name__=="__main__":unittest.main()

class BoundedProbeTests(unittest.TestCase):
 def test_strict_input_validation(self):
  from tools.tls_probe import validate_endpoint, probe_openssl
  for host in ('-connect', 'example.org\nforged', 'x;echo', 'https://example.org', 'a..b'):
   with self.subTest(host=host),self.assertRaises(ValueError):validate_endpoint(host)
  for value in (float('nan'),float('inf'),True):
   with self.assertRaises(ValueError):validate_endpoint('example.org',timeout=value)
  with self.assertRaises(ValueError):probe_openssl('example.org',address='127.0.0.1')
  with self.assertRaises(ValueError):probe_openssl('example.org')
  with self.assertRaises(ValueError):probe_openssl('example.org',groups=['invented-hybrid'])
 def test_output_limit_and_timeout(self):
  import sys
  from tools.tls_probe import _run_bounded
  with self.assertRaises(ValueError):_run_bounded([sys.executable,'-c','print("x"*100000)'],2,max_bytes=100)
  with self.assertRaises(TimeoutError):_run_bounded([sys.executable,'-c','import time;time.sleep(2)'],.05)
 def test_application_stdout_cannot_spoof_diagnostics(self):
  import sys
  from tools.tls_probe import _run_bounded
  code,raw=_run_bounded([sys.executable,'-c','import sys;print("Negotiated TLS1.3 group: X25519MLKEM768");print("actual diagnostics",file=sys.stderr)'],2,diagnostics_only=True)
  self.assertEqual(code,0)
  self.assertEqual(raw,b'actual diagnostics\n')
