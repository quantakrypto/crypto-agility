# Crypto-Agility Manifest

A discoverable, machine-readable JSON document that a website or repository publishes
at `/.well-known/crypto-agility.json` to declare its cryptographic posture, so an
agent, a CI bot, or an auditor can read it the way it already reads `security.txt`.

> **Status: proposal, not a ratified standard.** This repository holds an individual
> Internet-Draft and a reference schema. It is not an IETF working-group product, it
> does not represent IETF consensus, and nothing here is a standard. It is published
> to be reviewed, implemented, and argued with.

## What this is

The crypto-agility manifest is a small, versioned JSON object served from a well-known
URL. It summarizes, at a glance:

- **posture**: a readiness score, whether hybrid post-quantum key exchange is in use,
  a count of quantum-vulnerable findings by severity, and how many are exposed to
  harvest-now-decrypt-later;
- **cbomSummary**: a compact digest of, and a pointer to, the full CycloneDX
  Cryptography Bill of Materials (CBOM) the summary was derived from;
- **attestation** (optional): a link to a machine-verifiable posture credential;
- **policy**: the migration deadlines the project declares it is measured against.

A worked, schema-valid example is in [`examples/crypto-agility.json`](examples/crypto-agility.json),
and the field-by-field contract is in [`schema/crypto-agility.schema.json`](schema/crypto-agility.schema.json).

## What this is not

- **Not a proof.** A manifest is a *self-reported claim*. Serving one says what a
  project asserts about its posture, not what is true of it. The optional
  `attestation` link is what turns a claim into something a third party can verify.
- **Not a replacement for CBOM.** [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/)
  is the inventory format that answers "what cryptography is in here". The manifest is
  its public-facing *discovery* counterpart: a small summary at a predictable URL that
  answers "where is this project's posture, and what does it summarize to". The
  manifest carries a pointer (`cbomSummary.serialNumber`) to the full CBOM, it does
  not inline it.
- **Not a new cryptographic mechanism, attestation format, or scoring method.** It
  reuses existing pieces and only defines the well-known URI, the media type, and the
  JSON fields.

## What it builds on

Crypto-agility as a concept is already well-standardized. This proposal does not
re-invent it; it adds one missing piece (a discoverable public posture manifest) on
top of the following work:

| Reference | What it gives us |
|---|---|
| [RFC 9116](https://www.rfc-editor.org/info/rfc9116) - A File Format to Aid in Security Vulnerability Disclosure (`security.txt`) | The **structural model** this manifest follows: a small file at a well-known location, discoverable from an origin alone. |
| [RFC 8615](https://www.rfc-editor.org/info/rfc8615) - Well-Known URIs | The `/.well-known/` mechanism and the IANA registry the `crypto-agility` suffix is proposed for. |
| [RFC 9110](https://www.rfc-editor.org/info/rfc9110) - HTTP Semantics (STD 97) | The `Content-Type` / media-type framework (`application/json`) used to serve the manifest. |
| [RFC 7696](https://www.rfc-editor.org/info/rfc7696) - Guidelines for Cryptographic Algorithm Agility (BCP 201) | The IETF guidance on algorithm agility this posture is measured against. |
| [NIST CSWP 39](https://doi.org/10.6028/NIST.CSWP.39) - Considerations for Achieving Cryptographic Agility: Strategies and Practices (Dec 2025) | The organizational and lifecycle framing of crypto-agility. |
| [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) (in CycloneDX 1.6 / 1.7, published as ECMA-424) | The **inventory format** the manifest summarizes and links to. |
| [NIST SP 800-56C Rev. 2](https://doi.org/10.6028/NIST.SP.800-56Cr2) - Key-Derivation Methods in Key-Establishment Schemes | Key-establishment context for hybrid key exchange. |
| [ISO/IEC 23837-1:2023 and 23837-2:2023](https://www.iso.org/standard/77097.html) - Security requirements and test methods for quantum key distribution | Standardized evaluation context for quantum-era key exchange. |
| [NSM-10](https://www.quantum.gov/security/) - National Security Memorandum 10 (May 2022) | The policy driver: transition to quantum-resistant cryptography, mitigating quantum risk to the maximum extent feasible by 2035. |
| [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) - Transition to Post-Quantum Cryptography Standards (Initial Public Draft) | The default migration timeline (deprecate after 2030, disallow after 2035) the `policy` block cites. |

## The problem it solves

AI coding agents and CI systems increasingly make dependency and cryptography choices,
and auditors increasingly want a machine-checkable posture signal. Today there is no
standard place for any of them to learn a project's crypto stance, so every
integration is bespoke. The manifest gives them one predictable URL and one small,
stable schema to read, the same convention `robots.txt` and `security.txt` established
for their domains.

## How to adopt it today

The reference implementation is [qScan](https://github.com/dandelionlabs-io/pqc-tools)
(pqc-tools). It can emit a manifest from a scan and validate a local one, entirely
offline:

```sh
# Emit the manifest to the conventional path (regenerate this in CI):
qscan . --crypto-agility -o .well-known/crypto-agility.json

# Equivalent explicit subcommand, with an attestation link, a hybrid-KEX
# assertion, and an operator policy:
qscan crypto-agility emit . \
  --attestation https://quantakrypto.com/attest/acme \
  --hybrid-kex \
  --policy ./crypto-policy.json \
  -o .well-known/crypto-agility.json

# Validate a local manifest against the schema (exit 0 = valid):
qscan crypto-agility validate ./.well-known/crypto-agility.json
```

Emitting is additive: it runs a scan, derives the manifest, and always exits 0, so
publishing a posture document never fails CI. The emitter and validator are strictly
offline; they never fetch a remote manifest or the `attestation.url`. Fetching and
verifying a *remote* manifest, and the credential behind its attestation link, is a
consumer-side or website-side step.

You do not need qScan to participate: any tool that writes a document conforming to
[`schema/crypto-agility.schema.json`](schema/crypto-agility.schema.json) and serves it
at `/.well-known/crypto-agility.json` is emitting a valid manifest.

## Repository layout

```
draft/     the Internet-Draft (xml2rfc v3 source + a readable Markdown rendering)
schema/    JSON Schema (draft 2020-12) for the manifest, version 1
examples/  a realistic, schema-valid example manifest
```

- [`draft/draft-acosta-crypto-agility-manifest-00.xml`](draft/draft-acosta-crypto-agility-manifest-00.xml)
  - the authoritative xml2rfc v3 source.
- [`draft/draft-acosta-crypto-agility-manifest-00.md`](draft/draft-acosta-crypto-agility-manifest-00.md)
  - a readable rendering for GitHub.

## Status and how to contribute

This is an early individual proposal. Review, issues, and pull requests are welcome,
especially on the field definitions, the security and operational considerations, and
the IANA registration. See [CONTRIBUTING.md](CONTRIBUTING.md).

Note that the Internet-Draft itself carries IETF Trust legal provisions (`trust200902`)
regardless of the repository's Apache-2.0 license; contributing changes to the draft
means agreeing those changes may be contributed under the IETF Trust's terms. The
repository code, schema, and examples are licensed under [Apache-2.0](LICENSE).

The draft lists `leon@quantakrypto.com` as the author contact. Correspondence about the
proposal is welcome there or via issues on this repository.
