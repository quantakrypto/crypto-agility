# Observatory evidence integration

`tools.tls_probe.probe_openssl` collects a fresh TLS 1.3 handshake using the
operator's explicit endpoint and pinned IP address. OpenSSL performs certificate
chain and DNS/IP identity validation with `-verify_return_error`. The collector
bounds diagnostic output to 64 KiB, kills timed out subprocesses, sends no
application request and discards application stdout. A missing hybrid provider
fails rather than silently retrying with a classical configuration.

Default offered groups are `X25519MLKEM768:X25519:secp256r1`. The reported group
must actually be negotiated. Classical fallback is reported separately; offer
only `X25519MLKEM768` to test a policy that denies classical negotiation. The
certificate/handshake signature is reported separately and never promoted to
PQC authentication. Every result covers one address, time and configuration.

## Authenticated ingestion

The collector returns `evidence` and `transcript`. A separately trusted issuer
places the unmodified evidence object in the `observation` claim of the compact
JWS/JWT profile in [signed-observations.md](signed-observations.md). Evidence
contains:

- `profile: openssl-tls13-v1`, `observedAt` in UTC with whole-second precision;
- endpoint `host`, `port`, and the actual pinned IP `address`;
- probe `name`, OpenSSL `version`, offered `groups`,
  `certificateValidation: pkix-hostname`, and process `exitCode`;
- `transcriptSha256`, a SHA-256 digest of the exact diagnostic bytes.

The producer must collect new validated observations, sign under its deployed
issuer identity and transfer the token plus exact transcript through its chosen
transport. This repository does not distribute or discover private signing keys.
The consumer calls:

```python
result = ingest_measurement(
    token, transcript_bytes, trust_config, "https://example.org",
    expected_audience="monitor", replay_store=ReplayStore("replay.json"),
)
```

The consumer requires an explicitly trusted issuer, key and subject/audience/
purpose policy, valid signature, expiry, replay protection, fresh measurement,
exact endpoint/subject binding, transcript digest, successful validation and a
negotiated group from the offered list. A cryptographically valid token is
consumed even when its measurement is subsequently rejected; a correction needs
a new token identifier. `validUntil` is the earliest of token expiry, issuer
maximum age and measurement maximum age; cached reports must recheck it. A signed observation is an authenticated collector
statement, **not independent verification** of that collector's behavior.

## Existing Observatory boundary

The inspected Observatory baseline did not enforce a validated TLS 1.3 handshake
or retain all required evidence. Its historical database rows and public aggregates
cannot satisfy this authenticated profile. No unsigned legacy row is upgraded to
trusted evidence. qScan support hints also do not substitute for a validated
completed handshake.

Companion Observatory changes collect new bounded, certificate-validated evidence
and support export through the existing authority. The authority issues standard
RFC 9964 ML-DSA-65 JWS using the existing online key, with explicitly configured
issuer, audience, subject and optional exact snapshot bindings. Local cross-repository
tests exercise actual Observatory collection, authority issuance, ingestion and
monitor regression handling. Those tests use isolated test keys and local endpoints.

The running service's version, runtime identity, deployed issuer policy and fresh
production output must still be verified. A configured GitHub KMS identity does not
establish that the VM has that identity. Existing production keys are reused; no
private signing-service source or credentials are included in this repository.

## Reproduce validation

```sh
OPENSSL_BINARY=/path/to/openssl-3.5/bin/openssl REQUIRE_HYBRID_TLS=1 \
  python -m unittest discover -s tests -p 'test_tls_live.py' -v
python -m unittest discover -s tests -p 'test_observatory_ingestion.py' -v
```

The live test starts local TLS servers and exercises actual hybrid negotiation,
classical fallback, a hybrid-only refusal, hostname mismatch, untrusted
certificates and TLS 1.2 rejection. The required hybrid gate fails if the runtime
cannot negotiate the group. Synthetic transcript tests are not a substitute.
