# IETF -02 readiness

**Not submitted. The full requested acceptance criteria are not yet satisfied.**
The current branch prepares an individual proposal, not an IETF standard.

## Prepared materials

The authoritative RFCXML v3, generated Markdown, rendered text, embedded JSON
Schema and examples describe one v2 contract. Version 1 remains available for
existing qScan producers. The proposal requests a provisional well-known suffix;
it introduces no media type, signature format, feed protocol or cryptographic
algorithm. Contributor instructions require complete schema validation and
regeneration checks rather than a partial hand-written schema check.

## Verified submission process (2026-10-11)

- [Datatracker](https://datatracker.ietf.org/doc/draft-acosta-crypto-agility-manifest/)
  lists -01; -02 is the next revision. The author email is `leon@quantakrypto.com`.
- [IETF author guidance](https://github.com/ietf/authors.ietf.org/blob/main/submitting-your-internet-draft.md)
  prefers standalone RFCXML v3, validates with xml2rfc/idnits, and requires author
  confirmation unless submitted by an authenticated listed author.
- [IETF 127 dates](https://datatracker.ietf.org/meeting/127/important-dates/)
  list the draft cutoff as 2026-11-02 at 23:59 UTC. Recheck when submitting.
- Author confirmation and a submission transaction have not been attempted.

## Remaining gates

1. Hosted checks must pass on the exact commit retained in PR #2.
2. Complete the production issuer/exporter trust and deployment boundaries in
   [implementation-status.md](implementation-status.md). Reference fixture keys
   are not production trust anchors, and unsigned historical telemetry is not
   authenticated evidence.
3. Demonstrate the required heterogeneous runtime interoperability. Current
   profile tests assess declarations; Node/Python tests establish JWS and schema
   interoperability, not independent complete security consumers.
4. Review the final idnits diagnostics and obtain independent IETF-area feedback
   on the breaking v2 contract and registration. AI security review is not IETF
   endorsement. Recheck author metadata, references and the submission deadline.

No merge or submission is justified merely by a green reference test suite while
these acceptance gates remain open.

The official Datatracker document and submission instructions were checked again during the 2026-10-11 follow-up: -01 remains published and -02 remains the intended next revision. Standalone RFCXML v3 and an idnits review remain the preparation path; author confirmation and a submission transaction were not attempted. Production follow-up evidence and unresolved key-status, ledger and delivery gates are recorded in implementation-status.md. No independent complete semantic consumer implementation or IETF-area endorsement is inferred from the Node/Python wire tests.
