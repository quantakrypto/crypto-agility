# Contributing

This is an individual proposal, not an IETF standard. Preserve version 1 while
reviewing version 2. The authoritative candidate is
`draft/draft-acosta-crypto-agility-manifest-02.xml`; its embedded normative schema
must equal `schema/crypto-agility-v2.schema.json`. Update both in the same PR.
Generate the Markdown rendering with `python -m tools.render_draft`.

Keep the core to discovery and evidence references. Reuse existing cryptographic
protocols. Distinguish declarations, authenticated assertions and independently
verified runtime behavior. Cite primary sources and separate normative dependencies
from background. Do not use em dashes or claim validation without evidence.

## Validation

Install the pinned dependencies from `requirements.txt`, then run:

```sh
python -m unittest discover -s tests -v
python -m tools.render_draft --check
xml2rfc --text draft/draft-acosta-crypto-agility-manifest-02.xml --out /tmp/crypto-agility-02.txt
```

Run the independent consumer and live TLS checks required by CI. Required tests
must fail when their dependency or capability is absent, not silently skip.
Submission also requires review of current IETF author guidance, author contact,
revision availability, idnits output and any active submission deadline. Do not
submit or declare readiness while acceptance requirements remain unproven.

## Licensing

Code, schemas and examples use Apache-2.0. Draft contributions are subject to the
IETF Trust provisions indicated by `ipr="trust200902"` and BCP 78/79. Do not publish
secrets or private inventories as evidence.
