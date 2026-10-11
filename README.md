# Crypto-Agility Manifest

An individual Internet-Draft for discovering declared cryptographic capabilities at
`/.well-known/crypto-agility.json`. This is a proposal, not an IETF standard.
A manifest is a claim. Neither a digest, a signature nor a compatibility result
proves that a system is secure or quantum resistant.

## Version 2 candidate

The [-02 XML](draft/draft-acosta-crypto-agility-manifest-02.xml) is authoritative for
the v2 candidate. The [readable draft](draft/draft-acosta-crypto-agility-manifest-02.md),
[JSON Schema](schema/crypto-agility-v2.schema.json) and
[example](examples/crypto-agility-v2.json) accompany it. Version 1 remains unchanged
for existing qScan producers. Unknown versions require an explicit consumer upgrade.

The core describes subjects, capabilities, device profiles, evidence and migration
status. It separates declarations, observations and independent verification.
Optional evidence collection and monitoring belong to implementations, not a new
cryptographic protocol. The draft does not authorize configuration changes.

## Reference tools

- `tools.verifier`: bounded schema and semantic assessment, with no implicit trust
- `tools.tls_probe`: real TLS 1.3 negotiation through OpenSSL, certificate and hostname
  validation, negotiated group and peer signature reporting
- `tools.observatory_ingestion`: signed collector evidence, endpoint binding,
  transcript digest, freshness and provenance validation
- `tools.attestation`: compact JWS/JWT verification with pinned issuer policy,
  explicit audience and purpose, expiry and persistent replay rejection
- `tools.discovery`: bounded HTTPS discovery and conditional caching
- `tools.qscan`: deterministic offline adaptation of existing qScan v1 output
- `tools.monitor`: repeated assessment, regression alerts and protected local state

Ed25519 in the reference JWS profile is classical. A TLS hybrid key exchange does
not establish post-quantum authentication. Device compatibility is a conservative
comparison of declarations, not a device certification or fleet measurement.

## Validation

```sh
python -m pip install -r requirements.txt
npm ci --ignore-scripts
python -m unittest discover -s tests -v
python -m tools.verifier examples/crypto-agility-v2.json --now 2026-10-12T00:00:00Z
xml2rfc --no-network --text draft/draft-acosta-crypto-agility-manifest-02.xml
```

The example intentionally reports fallback risks and the verifier exits 1.
Hosted CI requires actual hybrid TLS and pinned qScan interoperability; missing
runtimes are failures there. It retains logs, the exact tested commit and rendered
draft artifacts. See [implementation status](docs/implementation-status.md) for
acceptance evidence and [IETF readiness](docs/ietf-readiness.md) for submission gates.

No production deployment or Internet-Draft submission is implied by passing the
reference tests. In particular, legacy unsigned measurements cannot be relabeled
as authenticated evidence.

Code is Apache-2.0. Internet-Drafts carry IETF Trust provisions (`trust200902`).
Author contact: `leon@quantakrypto.com`. See [CONTRIBUTING.md](CONTRIBUTING.md).
