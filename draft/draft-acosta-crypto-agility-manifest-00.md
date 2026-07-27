# A Well-Known URI and JSON Format for Publishing Cryptographic Posture (the Crypto-Agility Manifest)

- **Internet-Draft:** draft-acosta-crypto-agility-manifest-00
- **Category:** Informational
- **IPR:** trust200902
- **Submission type:** IETF (individual submission)
- **Author:** Leon Acosta, Dandelion Labs (contact: `leon@quantakrypto.com`)
- **Date:** 2026

> This Markdown file is a readable rendering of the Internet-Draft so it can be
> read on GitHub without running xml2rfc. The authoritative source is
> `draft-acosta-crypto-agility-manifest-00.xml`. If the two ever disagree, the XML
> is normative.

> **This document is a proposal.** It is not an IETF product and is not a standard
> of any kind.

## Abstract

This document defines a discoverable, machine-readable JSON document, the
crypto-agility manifest, that a website or source repository publishes at the
well-known URI `/.well-known/crypto-agility.json` to declare its cryptographic
posture: a readiness summary, a compact Cryptography Bill of Materials (CBOM)
summary, an optional link to a posture attestation, and the migration policy it
measures itself against. The manifest lets an automated consumer, such as an AI
coding agent, a continuous-integration bot, or an auditor's tool, discover a
project's crypto posture the way it already discovers a security contact from
`security.txt`. The manifest is a public, self-reported claim; it is not a proof.
It is intended to complement, not replace, a full CBOM inventory, serving as the
CBOM's public-facing discovery counterpart.

## 1. Introduction

Crypto-agility, the capability to replace and adapt cryptographic algorithms while
preserving security and operations, is a mature and well-documented objective. It is
treated at the algorithm-agility level by [RFC7696], and at the organizational and
lifecycle level by [NIST-CSWP-39]. The migration timelines that give crypto-agility
its present urgency are set out in [NSM-10] and [NIST-IR-8547], and general
engineering guidance for the post-quantum transition itself is collected in
[RFC9958]. The inventory of what
cryptography a system actually uses now has a standard representation, the
Cryptography Bill of Materials (CBOM) defined in [CycloneDX-CBOM].

What is missing is not the concept and not the inventory format. It is a
conventional, discoverable place for a project to publish a short, public summary of
its posture that a machine can find and read without out-of-band configuration.
Automated agents increasingly make dependency and cryptography choices, and
continuous-integration systems increasingly gate on them, but there is no standard
location from which such a consumer can learn a project's crypto posture, policy, and
migration deadlines. Today every such integration is bespoke.

This document fills exactly that gap and no more. It borrows its structural model
directly from `security.txt` [RFC9116]: a small file at a registered well-known
location [RFC8615] that any party can fetch from an origin alone. Where `security.txt`
publishes how to report a vulnerability, the crypto-agility manifest publishes a
project's cryptographic posture. A full CBOM answers "what cryptography is in here";
the manifest is its public-facing discovery counterpart, answering "where do I find
this project's posture, and what does it summarize to".

The manifest is deliberately a summary and not a replacement for a full CBOM or a
detailed readiness report. It is small enough to fetch and parse on every CI run, and
it answers three questions at a glance: how ready is this project, what
quantum-vulnerable cryptography is it still using, and by when has it committed to
migrate. A consumer that needs component-level detail follows the CBOM pointer the
manifest carries.

### 1.1. Scope and Non-Goals

This document specifies the well-known URI, the media type, and the JSON field
definitions of the manifest. It does not define a new cryptographic mechanism, a new
attestation format, or a new CBOM format; it references the CBOM format of
[CycloneDX-CBOM] for the summary it carries. It does not specify how a producer
computes a readiness score, and it does not define the trust model of the credential
an `attestation` link points to. The manifest is a self-reported claim (see
Section 8); establishing whether that claim is true is out of scope and is the job of
the linked attestation and of the consumer.

## 2. Terminology and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD
NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to
be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they
appear in all capitals, as shown here.

The following terms are used in this document:

- **manifest:** the JSON document defined by this specification.
- **producer:** the party or tool that generates and publishes a manifest.
- **consumer:** any party that retrieves and interprets a manifest, for example an
  agent, a CI system, a scanner, or an auditor's tool.
- **origin:** as defined in [RFC9110], the scheme, host, and port from which the
  manifest is retrieved.
- **CBOM:** a Cryptography Bill of Materials as defined in [CycloneDX-CBOM].
- **classical public-key cryptography:** public-key algorithms, such as RSA and
  elliptic-curve Diffie-Hellman, whose security is broken by a cryptographically
  relevant quantum computer.

Field names, JSON literals, and example values are shown in a monospaced font. JSON
types are as defined by the JSON grammar: object, array, string, number, boolean, and
null. In this document, "integer" denotes a JSON number with no fractional part.

## 3. The Well-Known URI

A producer publishes its manifest at the path `/.well-known/crypto-agility.json` of an
origin, that is:

```
https://example.com/.well-known/crypto-agility.json
```

This location uses the well-known URI mechanism of [RFC8615], the same mechanism that
hosts `security.txt` [RFC9116]. The URI suffix `crypto-agility.json` is registered in
Section 9. A consumer that knows only an origin MUST be able to locate the manifest by
resolving this path against that origin, with no out-of-band configuration.

A manifest published for a website or service SHOULD be served from the origin's web
root at the path above. A manifest that describes a source repository MAY additionally
be committed into the repository at `/.well-known/crypto-agility.json` so that it
travels with the source and can be regenerated by continuous integration.

A manifest retrieved over HTTP or HTTPS SHOULD be retrieved over HTTPS (see
Section 7). A consumer MUST NOT follow a cross-origin redirect to locate a manifest
without treating the result as belonging to the redirect target rather than the
original origin.

## 4. File Format

The manifest is a single JSON [RFC8259] object encoded in UTF-8. When served over
HTTP, it SHOULD be served with a `Content-Type` header field [RFC9110] of
`application/json`. A consumer MUST reject a document that is not a single JSON object.

The top-level `version` field is the schema contract. A consumer MUST branch on
`version` and MUST reject a value it does not understand. This document defines
`version` 1. Additive, backward-compatible fields MAY be introduced under `version` 1;
any breaking change bumps `version`. A consumer MUST ignore object members it does not
recognize, so that additive fields do not break older consumers.

The manifest is public by design. It MUST NOT contain secrets, source snippets, file
contents, or any data not intended for public disclosure (see Section 7).

## 5. Field Definitions

The manifest object has the members defined in this section. Unless a member is
explicitly marked optional, it is REQUIRED and a conforming producer MUST emit it. A
machine-readable JSON Schema for `version` 1 accompanies this specification
(`schema/crypto-agility.schema.json`).

### 5.1. version

An integer. The manifest schema version. For this specification the value MUST be 1. A
consumer MUST reject a version it does not understand.

### 5.2. manifestType

A string. A discriminator that lets a consumer distinguish this document from other
JSON served at a well-known path. The value MUST be the string `crypto-agility`. A
consumer MUST reject a document whose `manifestType` is any other value.

### 5.3. generatedAt

A string. The instant the manifest was generated, formatted as an Internet timestamp
per [RFC3339] (a profile of ISO 8601). A producer MUST set this from its runtime clock
at generation time.

### 5.4. generator

An object describing what produced the manifest. It has two REQUIRED string members:

- **name:** the name of the producing tool.
- **version:** the version of the producing tool.

### 5.5. subject

An object identifying what the manifest describes. It has three REQUIRED members:

- **root:** a string. The scanned root the manifest describes.
- **repository:** a string or null. The source repository the manifest describes.
  MUST be null when unknown.
- **commit:** a string or null. The commit identifier the manifest was derived from.
  MUST be null when unknown.

### 5.6. posture

An object carrying the distilled cryptographic posture. It has four REQUIRED members:

- **readinessScore:** a number from 0 to 100 inclusive. A producer-defined readiness
  score. A value of 100 means no classical asymmetric cryptography was found. This
  document does not define how the score is computed; a consumer MUST NOT assume that
  scores from different producers are directly comparable.
- **hybridKexInUse:** a boolean or null. Whether the subject negotiates hybrid
  post-quantum key exchange. A producer that cannot determine this (for example a
  static source scan, which cannot observe a negotiated key-exchange group) MUST set
  null. A consumer MUST treat null as "unknown", distinct from false.
- **quantumVulnerable:** an object with a REQUIRED integer member `total` (the count
  of quantum-vulnerable findings) and a REQUIRED object member `bySeverity`.
  `bySeverity` MUST contain all five integer keys `critical`, `high`, `medium`, `low`,
  and `info`, each a count that MUST NOT be negative.
- **hndlExposedCount:** an integer. The number of findings exposed to
  harvest-now-decrypt-later, that is, data that can be recorded today and decrypted
  once a cryptographically relevant quantum computer exists.

### 5.7. cbomSummary

An object that summarizes, and points to, the full CBOM [CycloneDX-CBOM] from which it
was derived. The full CBOM is intentionally not inlined, so that the manifest stays
small. It has three REQUIRED members:

- **serialNumber:** a string. The CycloneDX `serialNumber` (a `urn:uuid:` value) of
  the full CBOM this summary was derived from. This links the manifest to a specific
  CBOM instance.
- **assetCount:** an integer. The number of distinct `cryptographic-asset` components
  in the full CBOM.
- **algorithmFamilies:** an array of objects, ordered most-referenced first. Each
  element has a REQUIRED string `family` (the algorithm family name, for example `RSA`
  or `ECDH`), a REQUIRED integer `count` (the number of references to that family),
  and a REQUIRED boolean `quantumVulnerable`.

### 5.8. attestation (optional)

An OPTIONAL object. When present, it has one REQUIRED string member:

- **url:** a URI locating a machine-verifiable posture credential. A producer MUST
  record the URI verbatim and MUST NOT be required to fetch it when generating the
  manifest. A producer MUST omit the `attestation` member entirely when no credential
  is declared, rather than emitting an empty or null value.

The presence of an `attestation` link does not by itself make the manifest verifiable;
it points a consumer to where verification can be performed. See Section 6.

### 5.9. policy

An object stating the migration policy the subject declares it is measured against. It
has five REQUIRED members:

- **source:** a string. A label for the policy source: a published standard's name, or
  the literal `operator-declared` when the deadlines are set by the operator rather
  than adopted from a standard.
- **deprecateClassicalAfter:** an integer year after which classical public-key
  cryptography is considered deprecated under the declared policy.
- **disallowClassicalAfter:** an integer year after which classical public-key
  cryptography is considered disallowed under the declared policy.
- **transitionDeadline:** a string or null. An operator-declared migration deadline
  (an [RFC3339] date or a year), or null when none is declared.
- **citation:** a string. A human-readable citation for the declared deadlines.

The values of `deprecateClassicalAfter` and `disallowClassicalAfter` are the policy
the subject holds itself to; they are a declaration, not a verification. A producer
that adopts a published timeline SHOULD name it in `source` and `citation`, for
example the 2030 and 2035 milestones of [NIST-IR-8547] and [NSM-10].
National-security profiles such as the milestones of [NSM-10] are a valid
`operator-declared` choice.

## 6. Examples

The following is a complete, conforming manifest for a repository that has migrated
most, but not all, of its key exchange to hybrid post-quantum key exchange, still uses
RSA and ECDH in two places, and adopts the [NIST-IR-8547] transition timeline.

```json
{
  "version": 1,
  "manifestType": "crypto-agility",
  "generatedAt": "2026-07-27T04:57:12.323Z",
  "generator": { "name": "qScan", "version": "0.5.0" },
  "subject": {
    "root": ".",
    "repository": "https://github.com/acme/widget-service",
    "commit": "9f2c1ab7d3e04c5b8a6f0e21d47c9b3e5a1f8c02"
  },
  "posture": {
    "readinessScore": 74,
    "hybridKexInUse": true,
    "quantumVulnerable": {
      "total": 2,
      "bySeverity": {
        "critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0
      }
    },
    "hndlExposedCount": 2
  },
  "cbomSummary": {
    "serialNumber": "urn:uuid:5834348b-e27b-4f71-8752-f0497d98166f",
    "assetCount": 2,
    "algorithmFamilies": [
      { "family": "ECDH", "count": 1, "quantumVulnerable": true },
      { "family": "RSA", "count": 1, "quantumVulnerable": true }
    ]
  },
  "attestation": { "url": "https://quantakrypto.com/attest/acme" },
  "policy": {
    "source": "NIST IR 8547 (transition to post-quantum cryptography standards)",
    "deprecateClassicalAfter": 2030,
    "disallowClassicalAfter": 2035,
    "transitionDeadline": null,
    "citation": "NIST IR 8547 (transition to post-quantum cryptography standards)"
  }
}
```

A producer that cannot observe live key exchange (a static source scan) sets
`hybridKexInUse` to null and omits `attestation` when none is declared. The rest of
the document is unchanged.

## 7. Operational Considerations

**The manifest is a self-reported claim.** Every value in it is asserted by the
producer about itself. On its own the manifest establishes what a project says about
its posture, not what is true of it. This is the same trust posture as `security.txt`:
publishing a file does not prove the statements in it.

The `attestation` link is the bridge from claim to evidence. It points a consumer to a
machine-verifiable posture credential that a third party can check independently of the
manifest. A consumer that needs assurance rather than a claim SHOULD follow
`attestation.url` and verify the credential there; the manifest itself SHOULD NOT be
treated as proof of the posture it reports. A manifest without an `attestation` member
is an unverified self-declaration and SHOULD be consumed as such.

The manifest and its CBOM summary SHOULD be derived from the same underlying scan and
CBOM, so that the summary can never contradict the full CBOM referenced by
`cbomSummary.serialNumber`. A consumer that needs component-level detail follows that
pointer to the full CBOM rather than relying on the summary.

Producers SHOULD regenerate the manifest as posture changes, for example on each CI
run, so that a stale manifest does not misrepresent a project that has since migrated
or regressed. `generatedAt` lets a consumer judge freshness and reject a manifest that
is older than a policy it enforces.

**Relationship to security.txt.** An origin that already publishes a `security.txt`
file [RFC9116] SHOULD co-locate this manifest beside it under `/.well-known/`, so that
an operator who maintains one maintains the other and the two describe a consistent
security posture. RFC 9116 does not define a field for pointing at an arbitrary
well-known resource, and its `Encryption` field is reserved for a key or a certificate
used to encrypt a report to the operator, not for a posture document; a producer MUST
NOT repurpose `Encryption` to reference this manifest. Where an operator wishes to make
the link explicit, they MAY add a comment line to `security.txt` naming the manifest's
well-known location. A consumer that has discovered a `security.txt` file SHOULD attempt
to resolve this manifest at its own well-known path independently, rather than relying
on any such reference.

## 8. Security Considerations

**A manifest is a claim, not a proof.** Nothing about serving a manifest establishes
that its contents are accurate. A consumer MUST NOT treat a manifest as an
authenticated statement of posture; a consumer that requires assurance MUST obtain it
from a verifiable credential (see Section 6), not from the manifest alone. A hostile or
careless producer can overstate readiness, understate vulnerable findings, or advertise
deadlines it does not meet. Gating decisions on an unverified manifest inherits that
risk.

**Do not leak internal detail.** The manifest is public. A producer MUST NOT place
secrets, key material, source snippets, file paths, internal hostnames, or any
non-public detail in it. The fields defined here are deliberately coarse summaries for
this reason. A precise public inventory of which quantum-vulnerable algorithms a system
still uses, and where it is exposed to harvest-now-decrypt-later, is also a roadmap for
an attacker; a producer SHOULD weigh the transparency benefit of a detailed posture
against the reconnaissance value it hands an adversary, and MAY publish only the coarse
summary this document defines.

**Retrieve over TLS.** A manifest retrieved over the network SHOULD be retrieved over
HTTPS, so that a network attacker cannot substitute or tamper with it in transit. A
consumer SHOULD reject, or clearly mark as untrusted, a manifest retrieved over an
unauthenticated channel. As with `security.txt` [RFC9116], a cross-origin redirect
encountered while retrieving a manifest MUST NOT be treated as authoritative for the
original origin.

**Freshness and denial of service.** A stale manifest can misrepresent current
posture; consumers SHOULD use `generatedAt` to bound acceptable age. Because the
manifest is fetched automatically and potentially often, producers SHOULD serve it as a
static resource, and consumers SHOULD bound the size they will read and cache results,
so that manifest retrieval is not turned into a denial-of-service vector against either
party.

## 9. IANA Considerations

IANA is requested to register the following well-known URI in the "Well-Known URIs"
registry defined by [RFC8615].

- **URI suffix:** crypto-agility.json
- **Change controller:** IETF
- **Specification document(s):** This document.
- **Status:** permanent
- **Related information:** The resource is a JSON [RFC8259] document with media type
  `application/json`. See Section 4.

This document registers no new media type; the manifest uses the existing
`application/json` media type.

## 10. Status of This Proposal

This document is an individual proposal published to solicit review. It is not the
product of any IETF working group, it does not represent IETF consensus, and it is not
a standard. The reference implementation, a schema, and examples are maintained in the
open at the repository from which this draft originates.

## 11. Normative References

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174, May 2017, <https://www.rfc-editor.org/info/rfc8174>.
- **[RFC8259]** Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange
  Format", STD 90, RFC 8259, December 2017,
  <https://www.rfc-editor.org/info/rfc8259>.
- **[RFC3339]** Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps",
  RFC 3339, July 2002, <https://www.rfc-editor.org/info/rfc3339>.
- **[RFC8615]** Nottingham, M., "Well-Known Uniform Resource Identifiers (URIs)",
  RFC 8615, May 2019, <https://www.rfc-editor.org/info/rfc8615>.
- **[RFC9110]** Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed., "HTTP
  Semantics", STD 97, RFC 9110, June 2022,
  <https://www.rfc-editor.org/info/rfc9110>.
- **[CycloneDX-CBOM]** OWASP CycloneDX / Ecma International TC54, "CycloneDX
  Cryptography Bill of Materials (CBOM)", 2025. Cryptographic assets in the CycloneDX
  Bill of Materials specification (integrated in CycloneDX 1.6, extended in 1.7;
  published as Ecma International standard ECMA-424),
  <https://cyclonedx.org/capabilities/cbom/>.

## 12. Informative References

- **[RFC9116]** Foudil, E. and Y. Shafranovich, "A File Format to Aid in Security
  Vulnerability Disclosure", RFC 9116, April 2022,
  <https://www.rfc-editor.org/info/rfc9116>.
- **[RFC9958]** Banerjee, A., Reddy.K, T., Schoinianakis, D., Hollebeek, T., and M.
  Ounsworth, "Post-Quantum Cryptography for Engineers", RFC 9958, June 2026,
  <https://www.rfc-editor.org/info/rfc9958>.
- **[RFC7696]** Housley, R., "Guidelines for Cryptographic Algorithm Agility and
  Selecting Mandatory-to-Implement Algorithms", BCP 201, RFC 7696, November 2015,
  <https://www.rfc-editor.org/info/rfc7696>.
- **[NIST-CSWP-39]** National Institute of Standards and Technology, "Considerations
  for Achieving Cryptographic Agility: Strategies and Practices", NIST CSWP 39,
  December 2025, <https://doi.org/10.6028/NIST.CSWP.39>.
- **[NIST-SP-800-56C]** Barker, E., Chen, L., and R. Davis, "Recommendation for
  Key-Derivation Methods in Key-Establishment Schemes", NIST SP 800-56C Rev. 2,
  August 2020, <https://doi.org/10.6028/NIST.SP.800-56Cr2>.
- **[NIST-IR-8547]** National Institute of Standards and Technology, "Transition to
  Post-Quantum Cryptography Standards", NIST IR 8547 (Initial Public Draft),
  November 2024, <https://csrc.nist.gov/pubs/ir/8547/ipd>.
- **[NSM-10]** The White House, "National Security Memorandum on Promoting United
  States Leadership in Quantum Computing While Mitigating Risks to Vulnerable
  Cryptographic Systems (NSM-10)", May 2022.
- **[ISO-IEC-23837]** ISO/IEC, "Information security - Security requirements, test and
  evaluation methods for quantum key distribution - Part 1: Requirements; Part 2:
  Evaluation and testing methods", ISO/IEC 23837-1:2023 and 23837-2:2023, 2023,
  <https://www.iso.org/standard/77097.html>.
