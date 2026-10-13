# Discovery and optional refresh hints

The discovery resource is the current manifest at `/.well-known/crypto-agility.json`. No custom feed format, hash chain, sequence protocol, or push service is required. Conditional HTTP retrieval provides bounded refresh without a second trust or sequencing protocol.

`tools.discovery.DiscoveryClient` uses an explicit origin allowlist, verified HTTPS, public-address checking followed by a pinned-IP connection with hostname/SNI validation, no proxies and no redirects. A worker deadline bounds DNS, TLS, response headers and body reads together. Responses are limited to 1 MiB, uncompressed JSON, 16 levels of nesting and schema limits. Duplicate members and non-JSON numbers fail.

The memory-only cache supports ETag/If-None-Match and Last-Modified/If-Modified-Since, Cache-Control max-age, no-cache, no-store and Age/Date. Local max-age defaults to 300 seconds and cannot exceed 3600 seconds. There is at most one cached manifest per configured origin, at most 256 origins. An expired or mismatched manifest is rejected, including after 304. HTTP freshness never refreshes evidence timestamps: the monitoring caller must reassess evidence and signatures on every evaluation. The cache returns original bytes for exact snapshot digest binding.

An operator can arrange a local authenticated notification to call `fetch(configured_origin, expected_subject, force=True)`. The notification is only a refresh hint. Its contents never supply a URL, security finding, or instruction. Ordinary periodic polling recovers from lost, duplicated, reordered, or forged notifications. A separate feed protocol should only be considered after an actual interoperability use case demonstrates that HTTP validators are insufficient.

Use `python -m unittest discover -s tests -p 'test_discovery.py' -v` for cache, expiry, SSRF, redirect, malformed response, exact hostname validation and total worker deadline tests. These tests do not claim production network availability.
