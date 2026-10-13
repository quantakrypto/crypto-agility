# Implementation and acceptance

The v2 reference implementation and persistent consumer are merged. The workflow tests the PR head commit explicitly and retains logs and draft renderings as `validation-<commit>` artifacts. The [consumer runtime checks](https://github.com/quantakrypto/crypto-agility/actions/runs/38382277746) passed on `7c0c43cc54c721b8a835ebaf6241cb735d4b9f7e`, merged as `3a459dd`. Production receipts below are dated observations, not a certification of every deployment or device.

| Requirement | Reference implementation and evidence | Remaining acceptance boundary |
| --- | --- | --- |
| Authenticated ingestion | JWS issuer policy, endpoint/subject binding, transcript digest, provenance and freshness; ingestion and live pipeline tests | October 13 own-origin observations authenticate in the deployed consumer; independent verification checked the public JWS, exact manifest/transcript bytes and ledger binding. Historical full-panel telemetry remains unsigned |
| TLS hybrid and fallback | Mandatory local OpenSSL 3.5.9 handshakes; hybrid, classical, deny-classical, invalid CA, wrong name, expired certificate, TLS 1.2 rejection | Tests cover the pinned TLS stack and fixture endpoints, not every provider, client or CDN edge |
| Signed attestations | Standard compact JWS/JWT, explicit algorithm policy, trusted issuer/key allowlists, revocation, audience, expiry, durable replay state; independent Node/OpenSSL/Python wire tests | Existing-key RFC 9964 ML-DSA-65 issuance and fresh authenticated KMS status passed. Internal key-status policy is not public root-signed nonrevocation or independent measurement truth |
| Compatibility | Conservative profile comparison across supported device classes, per-hop scope and constraint handling | Declared compatibility is not execution on browsers, mobile hardware, gateways or constrained devices; no fleet enrollment/coverage claim |
| Monitoring | Repeated assessments, stable actionable alert IDs, expiry/regression detection, atomic owner-only state, concurrent-writer and symlink tests | Deployed consumer passed singleton, restart/replay rejection and fresh-bundle recovery; alert timer is enabled; retained production alerts obtained persisted provider delivery receipts before acknowledgment |
| Discovery | HTTPS certificate validation, origin allowlist, pinned public IP, total deadline/size limits, ETag/Last-Modified, no stale-on-error | Optional change notifications only trigger a snapshot refresh; no unnecessary feed protocol |
| qScan | Pinned real qScan v1 producer/scan, repeatable bytes and v2 adapter with exact evidence digest and repository/commit binding | Native qScan remains v1; the merged reference implementation supplies the tested adapter rather than changing its release |
| Tests | Unit, adversarial, real TLS, Node/Python interoperability, qScan integration, concurrency and bounded performance gates | Structural schema and JWS interoperability do not establish independent full semantic implementations or device interoperability |
| Draft | Self-contained -02 XML, Markdown, schema, examples and offline text/HTML rendering | Formal submission checks are distinct from project interoperability and review goals; see IETF readiness |

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

Hosted CI must pass on the exact published commit. Local passing tests are not a substitute. The implementation PRs have merged. Project acceptance boundaries and formal Internet-Draft submission preparation are tracked separately in [ietf-readiness.md](ietf-readiness.md).

## Historical production validation receipts (2026-10-11)

These paragraphs preserve what was established on October 11. Statements about work not yet integrated describe that date; the October 13 section below supersedes their operational status.

The original public implementation changes merged as crypto-agility `7b79cd2` and Observatory `238860e`. Independent engineering and security review corrected monitor alert-loss and baseline-loss failure paths: pending delivery IDs require explicit acknowledgment, and rejected evidence cannot erase the historical authenticated baseline or turn it into current assurance.

The existing Observatory timer and service were updated to `238860e`; no second scheduler was created. Its full run from 18:41:47 to 19:00:31 UTC completed with exit status 0 and refreshed all 271 database rows. It retained 203 certificate-validated collector records in an owner-only directory (0700) with owner-only files (0600); filename and transcript hashes were checked. All 203 records remain unsigned. Successful collection and local hashes do not establish an authenticated signing handoff, subject authorization or exact manifest-bound issuance.

The stricter TLS 1.3/certificate-validation methodology changed the measured web denominator from 70 to 66 while the hybrid count stayed at 48: `48/70` became `48/66`. This is a methodology effect, not adoption growth. The basic website methodology disclosure is live. The explicit cutover-date disclosure is now visible in the [website metrics methodology](https://quantakrypto.com/observatory/methodology). Device compatibility remains unknown or declared wherever representative execution evidence is absent.

The existing-key KMS canary succeeded on October 11. It matched the historical online key SPKI fingerprint, requested a bounded RAW signature and verified it locally. Legacy issuance was skipped; no token or ledger entry was created. This demonstrates signing access and key continuity, not non-revocation or authorized observation issuance.

### Durable legacy issuance

The two legacy website writers were integrated with one serialized durable authority. The public ledger is a replica, and recovery journals and per-subject artifact state survive website asset swaps.

Authenticated migration preserved the existing 51-entry ledger with full-file SHA-256 `3c0262b8b37edb4c1e8e3f81d254f907c35c759287fe3fafb507a4afab99f765`. Real production issuance increased the ledger to 52 entries, giving full-file SHA-256 `0ab2c5823eeb2d717f6e70c2c3695a04ded4810d28e8b17426ab9126c69c9bb0`. The canonical and served ledgers and all three artifact replicas matched, and no pending journal remained. The public legacy ML-DSA signature verified against SPKI pin `33698c1c345d1df7a5308c513ee5c3925bc7f31c12aeb883549430a6d8f7cc80`.

These receipts cover the legacy writers only. Legacy v1 signs the qScan logical content hash and readiness value; retained byte checksums are storage checks, not signed exact manifest/evidence bindings. The standard-JWS exporter has not been integrated with this shared transaction, and a source attestation does not prove the corresponding build is the live runtime.

## Current production validation (2026-10-13)

The deployed consumer authenticated fresh own-origin observations at 12:11:23 UTC, after a controlled restart at 12:15:06 UTC, and following a website deployment at 12:28:06 UTC. The observations reported certificate-validated TLS 1.3 with `X25519MLKEM768`. They bind the exact [origin manifest](https://quantakrypto.com/.well-known/crypto-agility-origin.json) bytes, whose SHA-256 was `6fe2a44b51dc117818eec67b685d288d24a1caafeede7ebda24965f968cc2d26`. This explicit origin declaration is separate from the existing qScan repository declaration; neither is silently reinterpreted as the other.

The standard observation issuer uses the existing signing identity and one serialized durable ledger shared with legacy issuance. Fresh authenticated KMS status, an independently pinned public key, explicit subject/audience authorization and a separate local withdrawal decision govern the consumer. The earlier status-read permission failure was resolved and the actual signing environment passed its status preflight. This internal operational policy does not establish public root-signed nonrevocation, an independent collector, PQC certificate authentication or device interoperability.

The production supervisor rejected a concurrent second process. Restart rejected the already-consumed observation as replay, retained the historical authenticated baseline and pending alerts, and then accepted the second fresh bundle without resetting state. All three replay entries persisted. A labeled delivery test obtained a durable provider-reported delivered receipt before acknowledgment; this is not proof of inbox visibility or human action. The consumer and alert timer are enabled. At 12:29:34 UTC the timer persisted matching provider-reported delivered receipts for all three retained production alerts before acknowledging their exact occurrences; the pending outbox was empty and historical receipts remained retained. An initial public artifact HTTP 404 was corrected before the independent public verification below.

An independent read-only verification at 12:28:46 UTC checked the [public observation JWS](https://quantakrypto.com/.well-known/observations/eb01a9bbbb9fac37b1e7f215c8dc1608715f1f89616f7953c3947429daf17d7f/observation.jwt), [captured manifest](https://quantakrypto.com/.well-known/observations/eb01a9bbbb9fac37b1e7f215c8dc1608715f1f89616f7953c3947429daf17d7f/manifest.json), [TLS transcript](https://quantakrypto.com/.well-known/observations/eb01a9bbbb9fac37b1e7f215c8dc1608715f1f89616f7953c3947429daf17d7f/transcript.txt) and [public ledger](https://quantakrypto.com/.well-known/attestation-ledger.jsonl) against the pinned key and native consumer report. The signed observation used ledger index 62 in the 63-entry ledger; the previously captured 56-entry prefix was unchanged. This independently verifies the signature and byte bindings, not the truth of a measurement performed by the same operator. These live URLs advance with later observations; the times and index above identify this receipt.

The assessment remains `needs-review` because fallback behavior is declared unknown. Representative browser, mobile, gateway and constrained-device measurements have not been established; those compatibility claims remain unknown or declared. The 203 historical full-panel collector records described above remain unsigned; these new own-origin observations do not retroactively authenticate them. A configured refresh interval is not evidence that the scheduler has actually maintained that cadence.

### Remaining project acceptance and quality goals

- Retain the observed production safeguards: public artifact byte binding, owner-private persistent state, local withdrawal, and acknowledgment only after confirmed provider delivery. These passed the dated checks above and require continued operation.
- Observe continued freshness and automatic refresh behavior without weakening expiry, replay or local-withdrawal checks.
- Demonstrate independent complete consumer interoperability and obtain independent IETF-area feedback. These are project quality goals, not formal prerequisites imposed by the individual Internet-Draft upload process.
- Recheck the final candidate's renderings, idnits diagnostics and current submission requirements before any submission. No -02 submission or IETF endorsement is claimed.
