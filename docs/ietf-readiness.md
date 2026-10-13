# IETF -02 readiness

**Revision -02 has not been submitted.** It remains an individual proposal, not an IETF standard or an endorsed implementation. Formal submission preparation and this project's production/interoperability acceptance goals are separate below.

## Prepared materials

The authoritative RFCXML v3, generated Markdown, rendered text, embedded JSON Schema and examples describe one v2 contract. Version 1 remains available for existing qScan producers. The proposal requests a provisional well-known suffix; it introduces no media type, signature format, feed protocol or cryptographic algorithm. Contributor instructions require complete schema validation and regeneration checks.

## Submission process checked on 2026-10-13

The [Datatracker record](https://datatracker.ietf.org/doc/draft-acosta-crypto-agility-manifest/) still lists -01 as an individual Internet-Draft; -02 is the intended next revision. Its published status explicitly does not imply IETF endorsement.

The [official author guidance](https://authors.ietf.org/submitting-your-internet-draft) prefers RFCXML v3 and describes submission through the [Datatracker submission tool](https://datatracker.ietf.org/submit/). Posting requires the requested author confirmation unless the submitter is authenticated and listed as an author. The [IETF 127 dates](https://datatracker.ietf.org/meeting/127/important-dates/) list the Internet-Draft cutoff as November 2, 2026 at 23:59 UTC. Recheck these sources immediately before submitting; no submission transaction or author confirmation has been attempted for -02.

Before an upload, verify the revision, author metadata, references, standalone XML and generated renderings; review the exact candidate's idnits diagnostics and resolve blocking submission-tool errors. Hosted CI must pass on the final committed tree as this project's release policy. Passing offline idnits is preparation evidence, not a receipt from the submission service.

## Project acceptance and quality goals

The [dated implementation status](implementation-status.md) records the narrower evidence actually observed. October 11 established the stricter unsigned collector and durable legacy issuance. October 13 added fresh standard-JWS own-origin issuance, authenticated KMS status under the internal trust policy, exact manifest binding, persistent consumer restart/replay rejection and fresh-bundle recovery. A labeled test obtained provider-reported delivery. Independent verification also checked the public JWS, exact manifest/transcript bytes and ledger history. The consumer and alert timer are enabled; retained production alerts obtained durable provider-reported delivered receipts before exact acknowledgment. These receipts are bounded production evidence, not proof of every implementation or device.

Independent complete semantic consumers, representative device execution and independent IETF-area feedback remain project quality goals. Node/OpenSSL/Python wire tests establish a narrower interoperability boundary. The individual Internet-Draft submission guidance does not require production deployment, heterogeneous device measurements or prior independent implementation; those must not be presented as formal IETF upload requirements. Equally, filing an Internet-Draft would not establish those engineering properties or grant standards status.

The internal KMS status policy is not public root-signed nonrevocation. Compatibility stays unknown or declared where representative execution is absent. Prepare the submission materials while retaining these limitations; do not submit until the user's technical-readiness condition and current submission checks have been reviewed. No submission or IETF endorsement is claimed.
