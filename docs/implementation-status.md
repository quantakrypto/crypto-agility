# Implementation and operational assurance

The reference implementation provides bounded manifest discovery and assessment, authenticated collector ingestion, declared compatibility comparison and persistent monitoring. Its tests exercise the contract with actual TLS handshakes, independently generated JWS, multiple runtimes and a pinned qScan producer. Passing those tests establishes the tested behavior, not comprehensive security or certification of a deployment.

## Implementation boundary

| Component | Implemented behavior | Assurance limit |
| --- | --- | --- |
| Manifest assessment | Bundled schema, bounded parsing, subject/reference checks, timestamps, contradictions and migration evidence requirements | `unverified` means no structural or semantic finding, not verified security |
| TLS collection | TLS 1.3 negotiation, selected group, certificate and reference-identity validation, bounded exact transcript | One address, time and probe configuration; no fleet coverage or PQC certificate authentication |
| Signed observations | Pinned Ed25519 or ML-DSA-65 policy, subject/audience/purpose binding, exact manifest/transcript digests, freshness and replay rejection | Authenticates a collector statement; no independent proof that the measurement is true |
| Compatibility | Conservative protocol and algorithm intersection, explicit constraints and single-hop scope | Device labels and declared compatibility do not establish runtime interoperability |
| Persistent consumer | Immutable complete bundles, separate local trust/status, singleton supervision, durable replay/clock/baseline state | Owner/root compromise or state rollback requires explicit operational recovery |
| Alert delivery | Persistent occurrence and send intent, bounded provider requests, exact receipt matching before acknowledgment | Provider-reported delivery is not proof of inbox visibility or human response |
| Discovery | Allowlisted HTTPS, validated certificates, pinned public IP, bounded conditional caching, no stale-on-error | Fresh HTTP responses never refresh evidence validity |
| qScan integration | Deterministic adapter for supported producer format with exact source bytes and repository/commit binding | Source scan findings remain inferred; no deployed device or live TLS assurance |

The standalone verifier does not fetch or authenticate evidence. Signed evidence ingestion and the persistent consumer apply explicit additional policies. The collector profile requires whole-second UTC timestamps; manifest timestamps separately allow up to six fractional digits. Consumer acceptance never elevates a declared capability to independently verified runtime behavior.

## Observed deployment acceptance

The following receipt is scoped to the October 13, 2026 checks and the deployed own-origin observation path. It is not a continuous availability guarantee. The deployed consumer uses an independently pinned key, explicit origin/subject/audience authorization, fresh authenticated internal KMS status and a separate local withdrawal decision. Internal status is not public root-signed nonrevocation. Existing signing and publication share one serialized durable issuer ledger with preserved history.

At 12:28:46 UTC, independent read-only verification checked the [public observation JWS](https://quantakrypto.com/.well-known/observations/eb01a9bbbb9fac37b1e7f215c8dc1608715f1f89616f7953c3947429daf17d7f/observation.jwt), [captured manifest](https://quantakrypto.com/.well-known/observations/eb01a9bbbb9fac37b1e7f215c8dc1608715f1f89616f7953c3947429daf17d7f/manifest.json), [TLS transcript](https://quantakrypto.com/.well-known/observations/eb01a9bbbb9fac37b1e7f215c8dc1608715f1f89616f7953c3947429daf17d7f/transcript.txt) and [public ledger](https://quantakrypto.com/.well-known/attestation-ledger.jsonl) against the pinned key and native consumer report. The observation reported certificate-validated TLS 1.3 with `X25519MLKEM768`, used ledger index 62 in a 63-entry ledger and preserved the previously captured 56-entry prefix. The [origin declaration](https://quantakrypto.com/.well-known/crypto-agility-origin.json) had SHA-256 `6fe2a44b51dc117818eec67b685d288d24a1caafeede7ebda24965f968cc2d26`. These URLs advance with later observations; the receipt time and index identify this check. The explicit origin declaration is a deployment-specific separate resource, not a replacement discovery suffix or a reinterpretation of a repository manifest.

The persistent consumer rejected a concurrent second process and rejected an already-consumed JWT after restart. It preserved its trusted historical baseline and pending alerts, then recovered current authentication from a fresh bundle without clearing replay state. Three replay entries persisted during acceptance. Consumer and alert timer were enabled and active. At 12:29:34 UTC the delivery timer persisted matching provider-reported delivered receipts for all three retained production alerts before exact acknowledgment; the pending outbox was empty and receipt history remained available. Independent delivery review confirmed these observations.

The assessment remains `needs-review` because fallback behavior is declared unknown. Representative browser, mobile, gateway and constrained-device measurements are absent, so those compatibility claims remain unknown or declared. Public full-panel telemetry is not authenticated merely because the own-origin path is signed. The [published methodology](https://quantakrypto.com/observatory/methodology) discloses TLS 1.3 and certificate-validation requirements; changed measurement eligibility must not be presented as adoption growth. A configured refresh interval is not evidence of sustained automatic scheduling.

Deployment claims must identify the tested runtime and observed evidence. Every release requires exact-tree checks and deployment verification.

## Reproduce required checks

Install `requirements.txt` and `npm ci --ignore-scripts`. Build OpenSSL with `bash scripts/build-test-openssl.sh build/openssl`. Check out pqc-tools at `6a81b5537eaedf61f259334b4e430e580c35942c`, run `npm ci --ignore-scripts` and `npm run build` there, then:

```sh
OPENSSL_BINARY="$PWD/build/openssl/apps/openssl" \
REQUIRE_HYBRID_TLS=1 REQUIRE_QSCAN_INTEROP=1 \
QSCAN_ROOT="$PWD/build/pqc-tools" \
python scripts/check-tests.py
python -m tools.render_draft --check
```

Hosted CI tests the exact committed tree and retains logs and rendered draft artifacts. Required runtimes must be present; fixture success is not a production receipt. The [public validation workflow](https://github.com/quantakrypto/crypto-agility/actions/workflows/verify-v2.yml) records exact-commit results and artifacts.

## Ongoing assurance and submission

Continue monitoring freshness, public byte binding, local withdrawal, persistent state and delivery acknowledgments. Independent complete semantic implementations, representative device execution and IETF-area feedback are valuable project quality goals; wire interoperability and source review do not establish them. These goals are distinct from formal individual Internet-Draft upload requirements, which are described in [IETF readiness](ietf-readiness.md). No IETF endorsement is implied by implementation, deployment or submission.
