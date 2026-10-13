# Persistent authenticated consumer

`python -m tools.consumer` wraps the existing monitor, authenticated ingestion, replay store and durable pending-alert outbox. It does not sign evidence, establish trust, send alerts or infer a delivery destination. Installation is prepared; production activation requires an operator-approved issuer/key status, subject/audience policy and alert destination with tested delivery and acknowledgment. A successfully running process or an output line is not proof that an observation was accepted or an alert delivered.

## Inputs and publication

Provision separate absolute paths for the configuration, bundle root and persistent state directory. Every input directory must be owned by the consumer account and mode 0700; input files must be owner-only regular files (0600), with exactly one link. No symlink path components, selectors, bundle directories or files are accepted. Use resolved physical paths on systems with conventional symlink ancestors. The consumer never creates input directories, alters their permissions, downloads keys or creates an issuer identity. The publisher and privileged operators are trusted to manage these private directories; another process running as that same account can modify them.

A bundle contains exactly `manifest.json`, `observation.jwt` and `transcript.txt`. The manifest must explicitly use version 2 with `subject.kind` equal to `origin` and `subject.id` equal to the configured canonical HTTPS origin. A qScan repository manifest must not be relabeled as origin evidence. Device compatibility remains unknown or declared unless representative measurements exist. The JWT must bind the SHA-256 digest of the exact manifest bytes. Reading a local committed bundle does not prove that a public HTTPS endpoint currently serves those bytes; independently compare the deployed response digest during publication acceptance.

Compute the bundle name as lowercase SHA-256 of UTF-8 compact JSON mapping each of the three filenames to its lowercase content SHA-256, sorted by filename, without trailing newline. For example, the hash input has the form `{"manifest.json":"<64hex>","observation.jwt":"<64hex>","transcript.txt":"<64hex>"}`. This is an immutable content commitment, not a new signature format or ledger chain identifier. The issuer transaction should retain the exact files and commitment for delivery recovery.

Write files to a new private staging directory, fsync every file, rename the complete directory to its 64-hex commitment under the bundle root, then fsync the root. Do not overwrite an existing committed directory. Write the commitment plus one optional newline to a private temporary selector, fsync it, atomically rename it to `current`, and fsync the root again. Retain the previously selected directory until no reader needs it. Never publish files individually into a selected directory. The consumer reads the selector once, opens that directory without following links, reads bounded file bytes and verifies their commitment before authentication; a selector change cannot mix transactions. Modified content fails closed.

## Operator configuration

`config.json` contains exactly these fields. Replace placeholders with independently approved values. The example intentionally cannot activate a consumer:

```json
{
  "version": 1,
  "issuer": "<approved issuer>",
  "subject": "https://example.org",
  "audience": "<approved consumer audience>",
  "keyId": "<approved key id>",
  "keyStatus": {
    "status": "unknown",
    "checkedAt": "<UTC RFC3339 timestamp ending Z>",
    "validUntil": "<UTC RFC3339 timestamp ending Z>",
    "source": "<operator decision or authoritative status reference>"
  },
  "trust": {
    "issuers": {
      "<approved issuer>": {
        "keys": {"<approved key id>": "<pinned public key in existing trust format>"},
        "subjects": ["https://example.org"],
        "audiences": ["<approved consumer audience>"],
        "purposes": ["pqc-observation"],
        "maxAgeSeconds": 3600,
        "maxLifetimeSeconds": 3600
      }
    }
  }
}
```

The status assertion must explicitly be `active`, have a nonempty source, and cover the current time with a validity window no longer than 24 hours. This is an operator assertion, **not cryptographic proof of current nonrevocation**. A missing revocation endpoint or an old root-signed certificate does not establish this assertion. Do not fill it automatically. The configuration permits exactly one issuer/key and the exact configured subject, audience and observation purpose; the existing verifier still validates algorithm, public-key encoding, signature, claim lifetime and policy. Configuration is reread every cycle, including when a previously authenticated measurement is cached. Replace the configuration atomically; absent, malformed, stale or inactive status queues a durable failure while preserving the last baseline.

## State, supervision and alert delivery

Before the first run, explicitly bootstrap a new empty private state directory with `python -m tools.consumer --initialize-state --state-directory /absolute/private/state`. This refuses existing state or lock files. Interrupted bootstrap requires reviewed recovery, not an automatic retry that erases files. The supervisor requires the initialization marker and all persistent documents on every check; missing files never recreate a replay store or baseline.

The state directory contains `initialized.json`, `replay.json`, `state.json`, `clock.json` and their stable locks, plus `consumer.lock` for the singleton CLI. Keep the entire directory across deployments and restarts. Never delete replay or clock state to make a rejected token pass. Restore only through an explicitly reviewed recovery procedure; restoring an old state backup can undo replay protection. The persistent clock high-water mark rejects rollback even after an input failure.

The long-running process retains the existing bounded in-memory authenticated-input cache and reevaluates expiration every cycle. After restart, a previously consumed token is rejected as replay; provision a new fresh observation and JTI. An unchanged token cannot silently become current assurance again. Historical trusted measurements and pending alerts survive, allowing later valid classical evidence to reveal a hybrid regression even after rejected inputs.

Reports go to stdout/journald; they are not alert-delivery receipts. The durable `state.json` outbox retains each occurrence's `deliveryId` until a separately configured delivery component confirms success. After confirmed delivery, acknowledge only that exact occurrence with `python -m tools.monitor --state /absolute/state/state.json --ack-alert <deliveryId>`. Never acknowledge merely because a report was printed or read. No delivery adapter or destination is selected here. Input failures continue producing reports and durable pending alerts; failures that prevent persistence explicitly include `deliveryPersistenceFailure`. State-directory startup failures or stdout errors stop the CLI so the supervisor can restart it. The CLI does not exit on an assessment finding, avoiding replay-producing restart loops.

`deploy/crypto-agility-consumer@.service` is an installation template, not discovered production coordinates. Review its paths and existing service account, install a pinned checkout and virtual environment at the chosen location, provision approved configuration/bundles, and retain private writable state. Install dependencies from `requirements.txt` with the supported Python version; ML-DSA verification additionally needs the compatible OpenSSL runtime described in the attestation documentation. The template grants no network access and exposes no signing credentials. Validate the unit on the actual Linux host with `systemd-analyze verify` before installing; no enable/start command is authorized by the mere presence of this template.

Before activation, run the zero-skip acceptance suite, authenticate a fresh exact-bound bundle, exercise a selector switch, restart/replay rejection, expiry, missing configuration, durable failure recovery and confirmed alert delivery at the operator's destination. Verify actual service ownership, filesystem permissions and persistence across a service restart. Hosted CI must cover the final committed tree; local fixture tests alone do not establish production success.
