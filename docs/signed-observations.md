# Signed observation profile

The reference implementation uses compact JWS (RFC 7515), JWT claims (RFC 7519), Ed25519 JOSE signing (RFC 8037), ML-DSA-65 (RFC 9964), and PyJWT with RFC 8725 validation safeguards. It signs the exact encoded JWS bytes, not a custom canonical JSON representation. Ed25519 is classical; ML-DSA-65 is post-quantum. Both authenticate the issuer's statement, not the truth of a measurement, PQC authentication, or fleet coverage.

This is a local reference application profile, not a registered media type or a required Internet-Draft wire format. Other attestation systems need their own explicitly selected, independently reviewed verifier. Unsupported formats fail closed; existing unsigned telemetry cannot become trusted merely by importing it.

## Contract

The protected header is exactly `alg` (`EdDSA` or `ML-DSA-65`), `kid`, and `typ: pqc-observation+jwt`. Required claims are `iss`, `sub`, `aud` (one string), `iat`, `exp` (integer NumericDate), `jti`, `purpose: pqc-observation`, and an `observation` object. Optional `nbf` is checked. The verifier rejects duplicate JSON members, unsupported headers, embedded key sources, future issuance, expired or excessively old statements, and signatures from unconfigured keys.

`verify_envelope` requires a local trust configuration, expected subject, expected audience and persistent `ReplayStore`. `expected_claims` can require additional signed scope/policy bindings; `expected_snapshot` binds `snapshotDigest` to the caller's independently calculated value. The monitor requires `sha256:<lowercase hex>` over the exact received manifest bytes. No canonicalization is implied. The measurement signs the transcript digest and endpoint/probe metadata; see `observatory-integration.md`.

An operator provisions a configuration of this shape (the public-key placeholder must be replaced by an independently authenticated, unpadded base64url 32-byte key):

```json
{
  "issuers": {
    "https://collector.example": {
      "keys": {"collector-2026": "REPLACE_WITH_TRUSTED_ED25519_PUBLIC_KEY"},
      "subjects": ["https://service.example"],
      "audiences": ["local-monitor"],
      "purposes": ["pqc-observation"],
      "maxAgeSeconds": 3600,
      "maxLifetimeSeconds": 3600,
      "revokedKeys": []
    }
  }
}
```

Subject/audience/purpose matching is exact, with no wildcard or substring matching. Remove an issuer/key, set issuer `disabled: true`, or add its key ID to `revokedKeys` to revoke trust. The verifier never obtains keys from token URLs. The local policy is operator-controlled, not an authenticated online revocation service. Issuer age and lifetime limits default to 3600 seconds and cannot exceed 604800 seconds. No future-issuance clock tolerance is granted.

## ML-DSA key and algorithm policy

For an existing AWS KMS `ML_DSA_65` key, pin the independently authenticated public key returned by `GetPublicKey`. Each `keys[kid]` value uses this explicit shape:

```json
{"alg":"ML-DSA-65","format":"spki-der","publicKey":"BASE64URL_UNPADDED_TRUSTED_DER"}
```

The DER SubjectPublicKeyInfo must match RFC 9881: OID `2.16.840.1.101.3.4.3.18`, absent parameters, and a 1952-byte public key. Signature length is 3309 bytes. An EdDSA string key never authorizes ML-DSA, and an explicit algorithm mismatch fails before signature verification. Explicit EdDSA keys may use the same object shape with `alg: EdDSA` and `format: raw`.

[RFC 9964 Section 5](https://www.rfc-editor.org/rfc/rfc9964.html#section-5) requires pure ML-DSA with an empty context; HashML-DSA and nonempty contexts are rejected. KMS signs the exact ASCII JWS signing input with `SigningAlgorithm: ML_DSA_SHAKE_256`, `MessageType: RAW`. Its input limit is 4096 bytes: a producer using RAW must reject larger signing inputs, not silently prehash them. AWS also defines compatible external-mu signing, but the RAW producer does not need it. The signing input includes the protected header and payload, not the signature.

Python cryptography 46 has no ML-DSA API. A PyJWT algorithm adapter delegates to OpenSSL 3.5's maintained default provider via `pkeyutl -verify -rawin`, with a 5-second deadline and 4096-byte diagnostic limit. Set `OPENSSL_BINARY` locally to the tested OpenSSL binary. Tokens cannot select binaries or providers. The reference test build pins OpenSSL 3.5.9. Backend absence fails verification.

Primary sources: [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html), [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html), [AWS KMS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html), [AWS ML-DSA/JWT integration](https://aws.amazon.com/blogs/security/how-to-create-post-quantum-signatures-using-aws-kms-and-ml-dsa/), and [OpenSSL ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/).

## Replay, storage and monitoring

The replay store atomically consumes `(issuer, audience, jti)` until expiry and pins the latest issuance time for each issuer/subject/audience/purpose. Older issuance is rejected even with a new ID. There are at most 10000 active tokens and 10000 pinned scopes by default; scope pins do not expire. Capacity fails closed rather than discarding anti-rollback history. Plan separate stores for bounded fleets; deliberate rebootstrap requires a fresh trusted baseline.

POSIX state files are owner-only, reject symbolic links/nonregular files, serialize writers, and use unique atomic replacement with file and directory fsync. Keep state in an owner-controlled directory. These controls cannot defend against the account owner/root, deleted state, or a rolled-back filesystem backup. Protect backups and do not delete replay state to recover a rejected token.

The monitor's process-local cache reuses a previously authenticated result only while exact token, transcript, manifest, audience, subject and trust-policy bytes remain unchanged. Effective validity is the earliest of token expiry, issuer maximum age, and measurement maximum age. Each check reevaluates validity. After a restart the producer must provide a fresh token ID; replayed input is rejected. A token whose signature passes but measurement semantics fail is consumed; a correction requires a new ID. This prevents retry ambiguity from being treated as new evidence.

`python -m tools.monitor MANIFEST --state STATE --token TOKEN --transcript LOG --trust TRUST --audience local-monitor --replay-state REPLAY --iterations 0` repeats local checks. Set `--interval` (minimum 1 second), or use a supervisor for one-shot checks. Replace `MANIFEST` with `--origin https://service.example --subject https://service.example` for allowlisted HTTPS discovery with bounded conditional caching. Discovery failure preserves the previous monitoring baseline.

Alerts include stable IDs, severity and a concrete action; they cover new findings, removed coverage, TLS hybrid-to-classical changes and expired/lost authenticated evidence. With `--state`, pending alerts are saved atomically alongside the baseline and returned on subsequent checks until acknowledged. A failed output write or process restart therefore does not discard an undelivered alert. Each pending occurrence has a `deliveryId`; after confirmed destination delivery, run `python -m tools.monitor --state STATE --ack-alert DELIVERY_ID` (repeat `--ack-alert` for multiple receipts). A repeated acknowledgment is harmless and cannot acknowledge a later recurrence of the same stable alert ID. JSON output alone is not a delivery receipt: the supervisor must route alerts, confirm delivery, and acknowledge them. The [persistent consumer and delivery adapter](consumer-deployment.md) implement this operational path; [implementation status](implementation-status.md) records observed deployment acceptance.

Rejected or missing measurements remain absent from the current report. The state separately retains the last authenticated measurements as historical regression baselines, so rejected evidence cannot hide a subsequent hybrid-to-classical change. These retained measurements never establish current assurance. Pending alerts and historical baselines share the bounded state file; exceeding its size limit fails closed and requires operator recovery rather than silently discarding history.

## Interoperability boundary

Tests use independent Node `crypto` JWS issuance and Python verification, including real local TLS evidence. Every deployment requires a compatible issuer, authorized collector keys and operational monitoring; production acceptance for the deployed own-origin path is documented separately. No private signing-service source or keys are included in this repository.
