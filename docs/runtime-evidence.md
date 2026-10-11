# Runtime evidence

A declared profile says what a publisher claims. A transcript records an observation;
its bytes alone do not authenticate its source. The active OpenSSL collector checks
TLS 1.3 negotiation, the selected NamedGroup, PKIX certificate validation and hostname
validation. Classical fallback is observed separately. A hybrid exchange does not
make a classical certificate or peer signature post-quantum secure.

`tools.observatory_ingestion` accepts a bounded transcript only when its compact JWS
validates against an operator-provisioned issuer policy and binds the exact endpoint,
probe parameters, observation time and transcript digest. The monitor additionally
requires the signed manifest digest. See `signed-observations.md` for claims,
replay, expiry and trust configuration. An authenticated collector statement remains
`independentlyVerified: false`; a relying party needs its own fresh probe to establish
an independent observation.

No supported method proves every fleet member's behavior or inventory completeness.
