# Crypto-Agility Manifest

A discoverable JSON contract for declared cryptographic capabilities, migration plans and evidence references at `/.well-known/crypto-agility.json`. This is an individual Internet-Draft proposal, not an IETF standard. A declaration, digest, signature or compatibility result does not prove comprehensive security or quantum resistance.

## Current contract

The [authoritative RFCXML](draft/draft-acosta-crypto-agility-manifest-03.xml), [readable specification](draft/draft-acosta-crypto-agility-manifest-03.md), [JSON Schema](schema/crypto-agility-v2.schema.json), [minimal example](examples/minimal-v2.json) and [complete example](examples/crypto-agility-v2.json) define the contract with `version: 2`. The Internet-Draft revision suffix and the JSON contract version are separate identifiers. Consumers reject unsupported versions; the [qScan adapter](docs/qscan-integration.md) explicitly handles supported input with `version: 1` without treating source declarations as runtime evidence.

A manifest identifies one independently authorized subject. It contains generation and expiry timestamps, declared endpoint profiles, observations and migration records, with optional evidence, policies and exceptions. Evidence is bound to its exact bytes and subject. Declarations, authenticated collector statements and independent measurements are distinct assurance levels. Key establishment and authentication are assessed separately. The contract grants no authority to change a system.

## Reference components

| Component | Responsibility |
| --- | --- |
| `tools.verifier` | Bounded schema and semantic assessment; no implicit trust or passing security certification |
| `tools.tls_probe` | Actual TLS 1.3 negotiation with certificate and reference-identity validation |
| `tools.observatory_ingestion` | Authenticated collector provenance, endpoint, transcript and freshness checks |
| `tools.attestation` | Compact JWS verification, explicit issuer/key/subject/audience/purpose policy and durable replay rejection |
| `tools.discovery` | Allowlisted HTTPS retrieval, bounded conditional caching and exact response bytes |
| `tools.qscan` | Deterministic offline adaptation of supported qScan source evidence |
| `tools.monitor` | Repeated assessment, historical regression baseline and durable alert occurrences |
| `tools.consumer` | Immutable bundle selection, local trust/status enforcement and persistent supervision |
| `tools.kms_status` | Bounded authenticated internal key-status refresh using an existing identity |
| `tools.alert_delivery` | Persistent delivery intent, provider receipt verification and exact acknowledgment |

The reference signature profile supports Ed25519 and ML-DSA-65 under independently provisioned algorithm/key policies. Ed25519 is classical. A hybrid TLS exchange does not establish post-quantum certificate authentication. Declared compatibility is a conservative profile comparison, not representative device execution or fleet certification.

## Use and validation

Install `requirements.txt` and `npm ci --ignore-scripts`, then follow [implementation status](docs/implementation-status.md) for the complete required test environment. A deterministic example assessment is:

```sh
python -m tools.verifier examples/crypto-agility-v2.json --now 2026-10-12T00:00:00Z
python -m tools.render_draft --check
xml2rfc --no-network --text draft/draft-acosta-crypto-agility-manifest-03.xml
```

The example intentionally reports fallback risks and exits 1. Read [runtime evidence](docs/runtime-evidence.md), [signed observations](docs/signed-observations.md), [collector integration](docs/observatory-integration.md), [consumer deployment](docs/consumer-deployment.md) and the [security review](docs/security-review.md) before relying on evidence. Production acceptance and its limits are in [implementation status](docs/implementation-status.md); submission status and requirements are in [IETF readiness](docs/ietf-readiness.md).

Code, schemas and examples use Apache-2.0. Internet-Drafts carry IETF Trust provisions (`trust200902`). Author contact: `leon@quantakrypto.com`. See [CONTRIBUTING.md](CONTRIBUTING.md).
