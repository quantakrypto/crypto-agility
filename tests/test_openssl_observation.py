import unittest
from tools.openssl_observation import parse_openssl_observation
class ObservationTests(unittest.TestCase):
 def test_hybrid_negotiated(self):
  s="New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nNegotiated TLS1.3 group: X25519MLKEM768\nVerify return code: 0 (ok)"
  r=parse_openssl_observation(s)
  self.assertTrue(r["hybridKexObserved"])
  self.assertFalse(r["authenticationPqcVerified"])
 def test_offered_group_is_not_negotiated(self):
  s="offered X25519MLKEM768\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nNegotiated TLS1.3 group: X25519\nVerify return code: 0 (ok)"
  self.assertFalse(parse_openssl_observation(s)["hybridKexObserved"])
 def test_no_handshake(self):
  self.assertEqual(parse_openssl_observation("X25519MLKEM768")["status"],"unknown")
 def test_failed_cert(self):
  s="New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nNegotiated TLS1.3 group: X25519MLKEM768\nVerify return code: 20 (unable to get local issuer certificate)"
  self.assertEqual(parse_openssl_observation(s)["status"],"unknown")
if __name__=="__main__":unittest.main()

class AdversarialObservationTests(unittest.TestCase):
 def test_duplicate_group_rejected(self):
  s='Protocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nVerification: OK\nPeer Temp Key: X25519, 253 bits\nNegotiated TLS1.3 group: X25519MLKEM768\n'
  self.assertEqual(parse_openssl_observation(s)['status'],'unknown')
 def test_success_banner_with_error_is_not_success(self):
  s='Protocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nVerification: OK\nNegotiated TLS1.3 group: X25519MLKEM768\nverify error:num=62:hostname mismatch\n'
  self.assertFalse(parse_openssl_observation(s)['certificateVerified'])
 def test_cipher_none_is_not_completed_handshake(self):
  s='New, TLSv1.3, Cipher is (NONE)\nNegotiated TLS1.3 group: X25519MLKEM768\nVerify return code: 0 (ok)'
  self.assertFalse(parse_openssl_observation(s)['tls13Observed'])
 def test_oversize_output(self):
  with self.assertRaises(ValueError):parse_openssl_observation('x'*65537)
