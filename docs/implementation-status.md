# Implementation and acceptance

This branch implements reference tooling. It does not certify a deployment.
The workflow tests the PR head commit explicitly, not only GitHub's merge ref,
and retains logs and draft renderings as `validation-<commit>` artifacts.

| Requirement | Reference implementation and evidence | Remaining acceptance boundary |
| --- | --- | --- |
| Authenticated ingestion | JWS issuer policy, endpoint/subject binding, transcript digest, provenance and freshness; ingestion and live pipeline tests | Companion Observatory collector/exporter and existing authority bridge are under test; deployment, production identity and fresh signed output remain unverified |
| TLS hybrid and fallback | Mandatory local OpenSSL 3.5.9 handshakes; hybrid, classical, deny-classical, invalid CA, wrong name, expired certificate, TLS 1.2 rejection | Tests cover the pinned TLS stack and fixture endpoints, not every provider, client or CDN edge |
| Signed attestations | Standard compact JWS/JWT, explicit algorithm policy, trusted issuer/key allowlists, revocation, audience, expiry, durable replay state; independent Node/OpenSSL/Python wire tests | RFC 9964 ML-DSA-65 support reuses the existing authority key; Existing-key KMS canary verified in website Actions; signed production deployment remains unverified |
| Compatibility | Conservative profile comparison across supported device classes, per-hop scope and constraint handling | Declared compatibility is not execution on browsers, mobile hardware, gateways or constrained devices; no fleet enrollment/coverage claim |
| Monitoring | Repeated assessments, stable actionable alert IDs, expiry/regression detection, atomic owner-only state, concurrent-writer and symlink tests | Operator must deploy supervisor and route alerts; state deletion/rollback by its owner requires operational recovery |
| Discovery | HTTPS certificate validation, origin allowlist, pinned public IP, total deadline/size limits, ETag/Last-Modified, no stale-on-error | Optional change notifications only trigger a snapshot refresh; no unnecessary feed protocol |
| qScan | Pinned real qScan v1 producer/scan, repeatable bytes and v2 adapter with exact evidence digest and repository/commit binding | Native qScan remains v1; this PR supplies the tested adapter rather than changing its release |
| Tests | Unit, adversarial, real TLS, Node/Python interoperability, qScan integration, concurrency and bounded performance gates | Structural schema and JWS interoperability do not establish independent full semantic implementations or device interoperability |
| Draft | Self-contained -02 XML, Markdown, schema, examples and offline text/HTML rendering | Internet-Draft submission checks and independent IETF-area review remain a separate gate |

## Scope and necessity

Keep discovery small. No custom signature envelope, bespoke Merkle construction,
new hybrid combiner, public feed hash chain, remediation executor or universal
readiness score is required. A fresh HTTP representation does not refresh evidence.
A signed observation authenticates its collector; independent verification must
be reported separately. The manifest never supplies its own trust policy.

## Reproduce

Install `requirements.txt` and `npm ci --ignore-scripts`. Build OpenSSL with
`bash scripts/build-test-openssl.sh build/openssl`. Check out pqc-tools at
`6a81b5537eaedf61f259334b4e430e580c35942c`, run `npm ci --ignore-scripts` and
`npm run build` there, then:

```sh
OPENSSL_BINARY="$PWD/build/openssl/apps/openssl" \
REQUIRE_HYBRID_TLS=1 REQUIRE_QSCAN_INTEROP=1 \
QSCAN_ROOT="$PWD/build/pqc-tools" \
python scripts/check-tests.py
```

Hosted CI must pass on the exact published commit. Local passing tests are not a
substitute. Merge and IETF submission remain blocked while the requested production
and interoperability acceptance boundaries above are unresolved.

## Production validation follow-up (2026-10-11)

The supplied PR heads and their hosted checks were verified before changes. Independent engineering and security review found monitor alert-loss and baseline-loss failure paths; the monitor now retains pending delivery IDs until explicit acknowledgment and preserves historical authenticated measurements across rejected evidence, without presenting them as current assurance.

An isolated candidate collector on the existing host passed its typecheck and real TLS tests. At 18:03:23 UTC, it observed certificate-validated TLS 1.3 with X25519MLKEM768 for `https://quantakrypto.com`. The separately fetched exact manifest bytes hashed to `sha256:e36400bf76ac5c48791e85fa629fc0a220d032359ed06a8117480346eea0e443`. That record is unsigned, is not a completed manifest-bound issuance, and expires for export after one hour. The existing scheduler was not switched to the candidate.

The deployed website still has legacy issuer jobs that fetch and overwrite its published ledger. Their history is not yet a single serialized durable observation ledger. The documented key-revocation endpoint returned HTTP 404; matching historical/live public keys and a valid root signature do not establish current non-revocation. No production consumer trust policy, persistent supervisor/replay/outbox deployment or confirmed alert receipt has been accepted. These gates block merge and full deployment even when fixture and hosted tests pass. Device compatibility remains unknown or declared wherever representative execution evidence is absent.

The existing-key KMS canary succeeded in [website Actions run 38162473186](https://github.com/quantakrypto/website/actions/runs/38162473186) at website commit `36f64b7705d3f152f3780093f96a8fe4da7f0e37`. It matched the historical online key SPKI fingerprint, requested a bounded RAW signature and verified it locally. Legacy issuance was skipped; no token or ledger entry was created. This verifies existing-key signing access and continuity, not non-revocation, authorized observation issuance or a deployed consumer.
