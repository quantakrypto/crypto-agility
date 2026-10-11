"""Strict observation JWT profile over RFC 7515/7519/8037/9964 (PyJWT).

Ed25519 is classical; RFC9964 ML-DSA-65 is post-quantum. Neither establishes an independent
measurement, a certificate, or proof of post-quantum authentication. Never fetch
keys supplied by a token. Local policy removal revokes an issuer or key.
"""
import base64
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tools.mldsa import MLDSA65Algorithm

jwt.register_algorithm("ML-DSA-65", MLDSA65Algorithm())
try:
    from tools.state import canonical, locked_document
except ModuleNotFoundError:
    from state import canonical, locked_document

MAX_TOKEN_BYTES = 1048576
TOKEN_TYPE = "pqc-observation+jwt"  # local profile, not an IANA registration


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(dt.timezone.utc)


def _decode(segment):
    if not isinstance(segment, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError("invalid base64url")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
        raise ValueError("noncanonical base64url")
    return raw


def _object(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate JSON member")
            obj[key] = value
        return obj
    def reject_constant(value):
        raise ValueError("non-JSON number")
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant)
    if not isinstance(obj, dict):
        raise ValueError("JSON object required")
    return obj


def load_trust(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_TOKEN_BYTES + 1)
    if len(raw) > MAX_TOKEN_BYTES:
        raise ValueError("trust configuration too large")
    value = _object(raw)
    if not isinstance(value.get("issuers"), dict):
        raise ValueError("issuers required")
    return value


class ReplayStore:
    """Persistent, bounded, atomic jti consumption. Deletion requires rebootstrap.

    Fresh IDs do not permit an older issuance time to replace a newer statement
    for the same issuer/subject/audience/purpose. A clock rollback fails closed.
    """
    def __init__(self, path, max_entries=10000):
        self.path = Path(path)
        self.max_entries = max_entries

    def consume(self, claims, now):
        identity = hashlib.sha256(canonical([claims[k] for k in ("iss", "aud", "jti")])).hexdigest()
        scope = hashlib.sha256(canonical([claims[k] for k in ("iss", "sub", "aud", "purpose")])).hexdigest()
        with locked_document(self.path) as (previous, save):
            state = previous if previous is not None else {"version": 1, "lastNow": now, "entries": {}, "latest": {}}
            if (state.get("version") != 1 or not isinstance(state.get("entries"), dict)
                    or not isinstance(state.get("latest"), dict)):
                raise ValueError("invalid replay state")
            if now < state["lastNow"]:
                raise ValueError("replay store clock rollback")
            state["entries"] = {key: expiry for key, expiry in state["entries"].items() if expiry > now}
            if identity in state["entries"]:
                return False, "replay"
            if claims["iat"] < state["latest"].get(scope, -1):
                return False, "observation-rollback"
            if len(state["entries"]) >= self.max_entries or (scope not in state["latest"] and len(state["latest"]) >= self.max_entries):
                raise ValueError("replay store capacity exceeded")
            state["lastNow"] = now
            state["entries"][identity] = claims["exp"]
            state["latest"][scope] = claims["iat"]
            save(state)
            return True, "accepted"


def verify_envelope(envelope, trust_keys, expected_subject,
                    expected_purpose="pqc-observation", now=None, *,
                    expected_audience=None, replay_store=None, expected_snapshot=None,
                    expected_claims=None):
    """Verify a compact JWS against operator policy, then atomically consume jti.

    Required claims: iss/sub/aud/iat/exp/jti/purpose/observation. Aud is one string.
    Only locally pinned Ed25519 or ML-DSA-65 keys, never publisher key URLs.
    Caller-specific signed bindings can be required with expected_claims.
    Consuming a valid token followed by rejecting measurement semantics is safe:
    the issuer must produce a new observation, never reuse that token's jti.
    """
    def reject(reason):
        return {"verified": False, "reason": reason}
    if expected_audience is None or replay_store is None:
        return reject("audience-and-replay-policy-required")
    if not isinstance(envelope, str) or len(envelope) > MAX_TOKEN_BYTES:
        return reject("invalid-envelope")
    try:
        instant = now or dt.datetime.now(dt.timezone.utc)
        if instant.tzinfo is None:
            return reject("timezone-required")
        seconds = instant.timestamp()
        pieces = envelope.split(".")
        if len(pieces) != 3:
            return reject("invalid-envelope")
        header, untrusted = _object(_decode(pieces[0])), _object(_decode(pieces[1]))
        signature = _decode(pieces[2])
        if (set(header) != {"alg", "kid", "typ"} or header["alg"] not in ("EdDSA", "ML-DSA-65")
                or header["typ"] != TOKEN_TYPE or not isinstance(header["kid"], str)
                or len(signature) != (64 if header["alg"] == "EdDSA" else 3309)):
            return reject("unsupported-header")
        required = ("iss", "sub", "aud", "iat", "exp", "jti", "purpose", "observation")
        if any(name not in untrusted for name in required):
            return reject("missing-claim")
        for name in ("iss", "sub", "aud", "jti", "purpose"):
            if not isinstance(untrusted[name], str) or not 1 <= len(untrusted[name]) <= 2048:
                return reject("invalid-claim")
        if not isinstance(untrusted["observation"], dict):
            return reject("invalid-observation")
        policy = trust_keys.get("issuers", {}).get(untrusted["iss"])
        if not isinstance(policy, dict) or policy.get("disabled", False):
            return reject("untrusted-issuer")
        for name in ("subjects", "audiences", "purposes", "revokedKeys"):
            values = policy.get(name, [] if name == "revokedKeys" else None)
            if not isinstance(values, list) or any(not isinstance(x, str) or not x for x in values):
                return reject("invalid-trust-policy")
        if not isinstance(policy.get("keys"), dict) or type(policy.get("disabled", False)) is not bool:
            return reject("invalid-trust-policy")
        key_bytes = policy["keys"].get(header["kid"])
        if key_bytes is None or header["kid"] in policy.get("revokedKeys", []):
            return reject("untrusted-key")
        if (expected_subject not in policy.get("subjects", [])
                or expected_audience not in policy.get("audiences", [])
                or expected_purpose not in policy.get("purposes", [])):
            return reject("issuer-not-authorized")
        # Historical string entries authorize EdDSA only, never another algorithm.
        if isinstance(key_bytes, str):
            key_policy = {"alg": "EdDSA", "format": "raw", "publicKey": key_bytes}
        elif isinstance(key_bytes, dict) and set(key_bytes) == {"alg", "format", "publicKey"}:
            key_policy = key_bytes
        else:
            return reject("invalid-trust-policy")
        if key_policy["alg"] != header["alg"]:
            return reject("key-algorithm-mismatch")
        if header["alg"] == "EdDSA":
            if key_policy["format"] != "raw":
                return reject("invalid-trust-policy")
            key = Ed25519PublicKey.from_public_bytes(_decode(key_policy["publicKey"]))
        else:
            if key_policy["format"] != "spki-der":
                return reject("invalid-trust-policy")
            key = _decode(key_policy["publicKey"])
        claims = jwt.decode(envelope, key, algorithms=[key_policy["alg"]],
                            issuer=untrusted["iss"], audience=expected_audience,
                            options={"verify_iat": False, "verify_exp": False,
                                     "verify_nbf": False, "strict_aud": True})
        if claims["sub"] != expected_subject or claims["purpose"] != expected_purpose:
            return reject("scope-mismatch")
        for name in ("iat", "exp", "nbf"):
            if name in claims and (type(claims[name]) is not int or claims[name] < 0):
                return reject("invalid-time")
        age = policy.get("maxAgeSeconds", 3600)
        lifetime = policy.get("maxLifetimeSeconds", 3600)
        if type(age) is not int or type(lifetime) is not int or not 0 < age <= 604800 or not 0 < lifetime <= 604800:
            return reject("invalid-trust-policy")
        if (claims["iat"] > seconds or claims["exp"] <= seconds
                or claims["exp"] <= claims["iat"] or seconds - claims["iat"] > age
                or claims["exp"] - claims["iat"] > lifetime
                or claims.get("nbf", claims["iat"]) > seconds):
            return reject("stale-or-future")
        bindings = dict(expected_claims or {})
        if expected_snapshot is not None:
            bindings["snapshotDigest"] = expected_snapshot
        if any(claims.get(name) != value for name, value in bindings.items()):
            return reject("binding-mismatch")
        accepted, reason = replay_store.consume(claims, seconds)
        if not accepted:
            return reject(reason)
        return {"verified": True, "reason": "signature-scope-freshness-and-replay-valid",
                "claims": claims, "signingAlgorithm": "Ed25519" if header["alg"] == "EdDSA" else "ML-DSA-65",
                "limitation": "Authenticated issuer statement; not independent measurement or proof of endpoint authentication"}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, jwt.PyJWTError):
        return reject("invalid-signature-claims-or-policy")
    except OSError:
        return reject("replay-state-unavailable")
