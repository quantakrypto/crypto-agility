# Implementation and acceptance

The v2 reference implementation is merged at `7b79cd2`. It does not certify a deployment. The workflow tests the PR head commit explicitly, not only GitHub's merge ref, and retains logs and draft renderings as `validation-<commit>` artifacts. Production receipts below distinguish the deployed collector and legacy issuer from the remaining standard-JWS acceptance work.

| Requirement | Reference implementation and evidence | Remaining acceptance boundary |
| --- | --- | --- |
| Authenticated ingestion | JWS issuer policy, endpoint/subject binding, transcript digest, provenance and freshness; ingestion and live pipeline tests | Existing scheduled Observatory collector deployed at `238860e`; its full production run retained 203 certificate-validated records, all unsigned. Authenticated handoff, authorized subjects, exact manifest binding and standard-JWS output remain unverified |
| TLS hybrid and fallback | Mandatory local OpenSSL 3.5.9 handshakes; hybrid, classical, deny-classical, invalid CA, wrong name, expired certificate, TLS 1.2 rejection | Tests cover the pinned TLS stack and fixture endpoints, not every provider, client or CDN edge |
| Signed attestations | Standard compact JWS/JWT, explicit algorithm policy, trusted issuer/key allowlists, revocation, audience, expiry, durable replay state; independent Node/OpenSSL/Python wire tests | RFC 9964 ML-DSA-65 support reuses the existing authority key. Real KMS canary and legacy production issuance passed; authoritative current key status and standard-JWS observation issuance remain unverified |
| Compatibility | Conservative profile comparison across supported device classes, per-hop scope and constraint handling | Declared compatibility is not execution on browsers, mobile hardware, gateways or constrained devices; no fleet enrollment/coverage claim |
| Monitoring | Repeated assessments, stable actionable alert IDs, expiry/regression detection, atomic owner-only state, concurrent-writer and symlink tests | Operator must deploy supervisor and route alerts; state deletion/rollback by its owner requires operational recovery |
| Discovery | HTTPS certificate validation, origin allowlist, pinned public IP, total deadline/size limits, ETag/Last-Modified, no stale-on-error | Optional change notifications only trigger a snapshot refresh; no unnecessary feed protocol |
| qScan | Pinned real qScan v1 producer/scan, repeatable bytes and v2 adapter with exact evidence digest and repository/commit binding | Native qScan remains v1; the merged reference implementation supplies the tested adapter rather than changing its release |
| Tests | Unit, adversarial, real TLS, Node/Python interoperability, qScan integration, concurrency and bounded performance gates | Structural schema and JWS interoperability do not establish independent full semantic implementations or device interoperability |
| Draft | Self-contained -02 XML, Markdown, schema, examples and offline text/HTML rendering | Internet-Draft submission checks and independent IETF-area review remain a separate gate |

## Scope and necessity

Keep discovery small. No custom signature envelope, bespoke Merkle construction, new hybrid combiner, public feed hash chain, remediation executor or universal readiness score is required. A fresh HTTP representation does not refresh evidence. A signed observation authenticates its collector; independent verification must be reported separately. The manifest never supplies its own trust policy.

## Reproduce

Install `requirements.txt` and `npm ci --ignore-scripts`. Build OpenSSL with `bash scripts/build-test-openssl.sh build/openssl`. Check out pqc-tools at `6a81b5537eaedf61f259334b4e430e580c35942c`, run `npm ci --ignore-scripts` and `npm run build` there, then:

```sh
OPENSSL_BINARY="$PWD/build/openssl/apps/openssl" \
REQUIRE_HYBRID_TLS=1 REQUIRE_QSCAN_INTEROP=1 \
QSCAN_ROOT="$PWD/build/pqc-tools" \
python scripts/check-tests.py
```

Hosted CI must pass on the exact published commit. Local passing tests are not a substitute. The implementation PRs have merged; unresolved production and interoperability boundaries remain acceptance and IETF-submission gates.

## Production validation receipts (2026-10-11)

The original implementation changes merged as crypto-agility `7b79cd2`, Observatory `238860e`, Authority `55ff0fd` and website `c5cdbe0`. Independent engineering and security review corrected monitor alert-loss and baseline-loss failure paths: pending delivery IDs require explicit acknowledgment, and rejected evidence cannot erase the historical authenticated baseline or turn it into current assurance.

The existing Observatory timer and service were updated to `238860e`; no second scheduler was created. Its full run from 18:41:47 to 19:00:31 UTC completed with exit status 0 and refreshed all 271 database rows. It retained 203 certificate-validated collector records in an owner-only directory (0700) with owner-only files (0600); filename and transcript hashes were checked. All 203 records remain unsigned. Successful collection and local hashes do not establish an authenticated signing handoff, subject authorization or exact manifest-bound issuance.

The stricter TLS 1.3/certificate-validation methodology changed the measured web denominator from 70 to 66 while the hybrid count stayed at 48: `48/70` became `48/66`. This is a methodology effect, not adoption growth. The basic website methodology disclosure is live. The explicit cutover-date disclosure is tracked in [website PR #276](https://github.com/quantakrypto/website/pull/276). Device compatibility remains unknown or declared wherever representative execution evidence is absent.

The existing-key KMS canary succeeded in [website Actions run 38162473186](https://github.com/quantakrypto/website/actions/runs/38162473186) at website commit `36f64b7705d3f152f3780093f96a8fe4da7f0e37`. It matched the historical online key SPKI fingerprint, requested a bounded RAW signature and verified it locally. Legacy issuance was skipped; no token or ledger entry was created. This demonstrates signing access and key continuity, not non-revocation or authorized observation issuance.

### Durable legacy issuance

[Website PR #286](https://github.com/quantakrypto/website/pull/286) merged as `b37e956`. Its [CI run](https://github.com/quantakrypto/website/actions/runs/38165662878), [deployment](https://github.com/quantakrypto/website/actions/runs/38165903487) and [production SEO/JSON-LD checks](https://github.com/quantakrypto/website/actions/runs/38166157610) succeeded. The two legacy website writers now share one serialized durable authority at `/var/lib/quantakrypto-attestation`; the public ledger is a replica, and recovery journals and per-subject artifact state survive website asset swaps.

Authenticated migration preserved the existing 51-entry ledger with full-file SHA-256 `3c0262b8b37edb4c1e8e3f81d254f907c35c759287fe3fafb507a4afab99f765`. Real production issuance increased the ledger to 52 entries, giving full-file SHA-256 `0ab2c5823eeb2d717f6e70c2c3695a04ded4810d28e8b17426ab9126c69c9bb0`. The canonical and served ledgers and all three artifact replicas matched, and no pending journal remained. The public legacy ML-DSA signature verified against SPKI pin `33698c1c345d1df7a5308c513ee5c3925bc7f31c12aeb883549430a6d8f7cc80`.

These receipts cover the legacy writers only. Legacy v1 signs the qScan logical content hash and readiness value; retained byte checksums are storage checks, not signed exact manifest/evidence bindings. The standard-JWS exporter has not been integrated with this shared transaction, and a source attestation does not prove the corresponding build is the live runtime.

### Remaining acceptance gates

- Establish authoritative current key status. The documented revocation endpoint returned HTTP 404; a matching public key, valid historical certificate and working KMS signing access do not prove non-revocation.
- Complete the standard-JWS collector handoff, authenticated source identity, authorized subject policy, exact manifest binding and integration with the same durable issuer ledger. Recollect fresh evidence before issuance; retained unsigned records are not a substitute.
- Deploy and verify consumer trust, persistent monitor/replay state and delivery acknowledgment. Establish the intended alert destination and verify actionable receipt there.
- Demonstrate independent complete consumer interoperability and obtain independent IETF-area feedback. Node/Python wire tests and declared compatibility are narrower evidence.

No IETF submission has occurred. The merged code, deployed collector and successful legacy issuance do not close these remaining gates.
