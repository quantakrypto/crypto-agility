# Contributing

This is an individual proposal, not an IETF standard. Preserve supported input compatibility and reject unsupported contract versions explicitly. The authoritative specification is `draft/draft-acosta-crypto-agility-manifest-02.xml`; its embedded normative schema must equal `schema/crypto-agility-v2.schema.json`. Update both in the same PR. Generate the Markdown rendering with `python -m tools.render_draft`.

Keep the core to discovery and evidence references. Reuse existing cryptographic protocols. Distinguish declarations, authenticated assertions and independently verified runtime behavior. Cite primary sources and separate normative dependencies from background. Do not use em dashes or claim validation without evidence.

## Validation

Install the pinned dependencies from `requirements.txt`, then run:

```sh
python -m unittest discover -s tests -v
python -m tools.render_draft --check
xml2rfc --text draft/draft-acosta-crypto-agility-manifest-02.xml --out /tmp/crypto-agility-02.txt
```

Run the independent consumer and live TLS checks required by CI. Required tests must fail when their dependency or capability is absent, not silently skip. Submission also requires review of current IETF author guidance, author contact, revision availability, idnits output and any active submission deadline. Submission status must reflect an observed Datatracker result. Authorize the submission explicitly, complete the current checks, and preserve the submission receipt; never infer publication from local rendering or upload preparation.

## Licensing

Code, schemas and examples use Apache-2.0. Draft contributions are subject to the IETF Trust provisions indicated by `ipr="trust200902"` and BCP 78/79. Do not publish secrets or private inventories as evidence.
