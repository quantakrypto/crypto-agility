import base64
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.attestation import ReplayStore, TOKEN_TYPE, verify_envelope

NOW = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = ReplayStore(Path(self.directory.name) / "replay.json")
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.policy = {"keys": {"probe-1": base64.urlsafe_b64encode(public).rstrip(b"=").decode()},
                       "subjects": ["https://example.org"], "audiences": ["monitor"],
                       "purposes": ["pqc-observation"]}
        self.trust = {"issuers": {"probe": self.policy}}
        self.claims = {"iss": "probe", "sub": "https://example.org", "aud": "monitor", "jti": "one",
                       "iat": int(NOW.timestamp()) - 30, "exp": int(NOW.timestamp()) + 60,
                       "purpose": "pqc-observation", "observation": {"group": "X25519MLKEM768"}}

    def sign(self, claims=None, header=None):
        return jwt.encode(claims or self.claims, self.key, algorithm="EdDSA",
                          headers=header or {"kid": "probe-1", "typ": TOKEN_TYPE})

    def verify(self, token=None, **kwargs):
        options = dict(now=NOW, expected_audience="monitor", replay_store=self.store)
        options.update(kwargs)
        return verify_envelope(token or self.sign(), self.trust, "https://example.org", **options)

    def test_valid_and_durable_replay_rejection(self):
        self.assertTrue(self.verify()["verified"])
        self.store = ReplayStore(self.store.path)
        self.assertEqual(self.verify()["reason"], "replay")

    def test_unknown_issuer_key_and_revocation(self):
        for change, reason in [({"iss": "attacker"}, "untrusted-issuer"), ({"sub": "other"}, "scope-mismatch")]:
            self.assertEqual(self.verify(self.sign(dict(self.claims, **change)))["reason"], reason)
        self.policy["revokedKeys"] = ["probe-1"]
        self.assertEqual(self.verify()["reason"], "untrusted-key")

    def test_local_authorization_required(self):
        self.policy["subjects"] = ["https://other.example"]
        self.assertEqual(self.verify()["reason"], "issuer-not-authorized")

    def test_freshness_and_integer_time(self):
        now = int(NOW.timestamp())
        for changes in ({"exp": now}, {"iat": now + 1}, {"iat": now - 5000},
                        {"exp": now + 4000}, {"nbf": now + 1}, {"iat": True}, {"exp": "9999999999"}):
            with self.subTest(changes=changes):
                self.assertFalse(self.verify(self.sign(dict(self.claims, **changes)))["verified"])

    def test_wrong_purpose_audience_type_and_alg(self):
        self.assertFalse(self.verify(self.sign(dict(self.claims, aud="other")))["verified"])
        self.assertFalse(self.verify(self.sign(dict(self.claims, purpose="other")))["verified"])
        for header in ({"kid": "probe-1", "typ": "JWT"},
                       {"kid": "probe-1", "typ": TOKEN_TYPE, "jku": "https://attacker"},
                       {"kid": "probe-1", "typ": TOKEN_TYPE, "crit": ["custom"]}):
            self.assertFalse(self.verify(self.sign(header=header))["verified"])
        unsigned = jwt.encode(self.claims, "", algorithm="none", headers={"kid": "probe-1", "typ": TOKEN_TYPE})
        self.assertFalse(self.verify(unsigned)["verified"])

    def test_tamper_duplicate_json_and_size(self):
        token = self.sign().split(".")
        token[1] = base64.urlsafe_b64encode(b'{"iss":"probe","iss":"attacker"}').rstrip(b"=").decode()
        self.assertFalse(self.verify(".".join(token))["verified"])
        self.assertFalse(self.verify("a" * 1048577)["verified"])
        self.assertFalse(self.verify("malformed")["verified"])

    def test_bad_signature_does_not_poison_replay(self):
        token = self.sign().split(".")
        token[2] = base64.urlsafe_b64encode(b"x" * 64).rstrip(b"=").decode()
        self.assertFalse(self.verify(".".join(token))["verified"])
        self.assertTrue(self.verify()["verified"])

    def test_snapshot_scope_binding(self):
        token = self.sign(dict(self.claims, snapshotDigest="sha256:a", scope="tls-endpoint"))
        self.assertFalse(self.verify(token, expected_snapshot="sha256:b")["verified"])
        self.assertTrue(self.verify(token, expected_snapshot="sha256:a", expected_claims={"scope": "tls-endpoint"})["verified"])

    def test_replay_policy_mandatory(self):
        self.assertFalse(self.verify(replay_store=None)["verified"])
        self.assertFalse(self.verify(expected_audience=None)["verified"])

    def test_new_jti_cannot_roll_back_issuance(self):
        self.assertTrue(self.verify()["verified"])
        token = self.sign(dict(self.claims, jti="older", iat=self.claims["iat"] - 1))
        self.assertEqual(self.verify(token)["reason"], "observation-rollback")

    def test_malformed_policy_and_empty_replay_state_rejected(self):
        self.policy["subjects"] = "prefix-https://example.org-suffix"
        self.assertEqual(self.verify()["reason"], "invalid-trust-policy")
        self.policy["subjects"] = ["https://example.org"]
        self.store.path.write_text("{}")
        self.store.path.chmod(0o600)
        self.assertFalse(self.verify()["verified"])

    def test_replay_capacity_and_clock_rollback_fail_closed(self):
        self.store.max_entries = 1
        self.assertTrue(self.verify()["verified"])
        self.assertFalse(self.verify(self.sign(dict(self.claims, jti="two")))["verified"])
        self.assertFalse(self.verify(self.sign(dict(self.claims, jti="three")), now=NOW-dt.timedelta(seconds=1))["verified"])

    def test_expired_entries_are_pruned(self):
        self.store.max_entries = 1
        self.assertTrue(self.verify()["verified"])
        later = NOW + dt.timedelta(seconds=100)
        claims = dict(self.claims, jti="two", iat=int(later.timestamp()), exp=int(later.timestamp())+60)
        self.assertTrue(self.verify(self.sign(claims), now=later)["verified"])

    def test_corrupt_or_insecure_state_fails_closed(self):
        self.store.path.write_text("not json")
        self.store.path.chmod(0o600)
        self.assertFalse(self.verify()["verified"])
        self.store.path.write_text("{}")
        self.store.path.chmod(0o644)
        self.assertFalse(self.verify()["verified"])


if __name__ == "__main__":
    unittest.main()
