# Contributing

Thanks for taking the time to look at the crypto-agility manifest. This is an early
individual proposal, so the most valuable contributions right now are review and
argument, not just code.

## Where to start

- **The specification** lives in [`draft/`](draft/). The
  `draft-acosta-crypto-agility-manifest-01.xml` file is the authoritative source
  (xml2rfc v3, RFC 7991 vocabulary); the `.md` file is a readable rendering kept in
  sync with it. If you change one, change the other.
- **The contract** lives in [`schema/crypto-agility.schema.json`](schema/crypto-agility.schema.json)
  (JSON Schema, draft 2020-12). The schema, the draft's Field Definitions section, and
  the example in [`examples/`](examples/) must always agree.

## How to propose a change

1. Open an issue first for anything substantive (a new field, a changed requirement, a
   security consideration). It is cheaper to agree on a change in prose before editing
   three files.
2. For an accepted change, open a pull request that updates **all** of: the XML draft,
   the Markdown rendering, the JSON Schema, and the example (whichever apply), so they
   never drift apart.
3. Keep the tone level and non-hype. This document competes on being correct and
   honest about what it is (a claim, not a proof), not on marketing.

## House rules

- **No em dashes** anywhere: in prose, code, or XML. Use commas, colons, parentheses,
  or a spaced hyphen instead.
- **Verify, do not invent.** Every external standard cited must be checked against its
  primary source, with a correct title, number, and link. Do not add a citation you
  have not read.
- **Cite normatively vs informatively with care.** RFC 2119 / 8174 / 8259 / 3339 / 8615 /
  9110 and CycloneDX CBOM are normative (the draft depends on them to be implementable). The
  crypto-agility survey references (RFC 7696, NIST CSWP 39, NIST IR 8547, NSM-10,
  ISO/IEC 23837, NIST SP 800-56C) are informative.

## Validating your change locally

The example is checked against the schema with no third-party dependencies. Any small
JSON-Schema (draft 2020-12) validator works; if you have `ajv` available you can run it
directly, otherwise a short structural check over the schema's `required`, `type`,
`const`, and `additionalProperties` keywords is sufficient. Confirm that
`examples/crypto-agility.json` still validates after any schema change.

Check the draft XML is well-formed before opening a PR:

```sh
xmllint --noout draft/draft-acosta-crypto-agility-manifest-01.xml
```

## Licensing and IETF Trust provisions

The repository (schema, examples, tooling notes) is licensed under **Apache-2.0**; see
[LICENSE](LICENSE).

The Internet-Draft in [`draft/`](draft/) is a different matter. It carries the IETF
Trust legal provisions indicated by its `ipr="trust200902"` attribute, **regardless of
the repository's Apache-2.0 license**. By contributing changes to the draft you agree
that those contributions may be submitted to the IETF under the IETF Trust's terms
(see the IETF "Note Well" and BCP 78/79). If you are not comfortable with that,
contribute to the schema, examples, and tooling instead, and leave the draft prose to
be edited separately.

## Before an IETF submission

The draft is kept in submission-ready shape: the author contact
(`leon@quantakrypto.com`) and the IANA change-controller (`IETF`) are set. Validate the
XML with `xmllint --noout` and, ideally, render it through `xml2rfc` before submitting a
new revision, so the datatracker upload does not bounce on a format error.
