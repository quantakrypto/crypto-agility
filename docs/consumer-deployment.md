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

Reports go to stdout/journald; they are not alert-delivery receipts. The durable `state.json` outbox retains each occurrence's `deliveryId` until a separately configured delivery component confirms success. After confirmed delivery, acknowledge only that exact occurrence with `python -m tools.monitor --state /absolute/state/state.json --ack-alert <deliveryId>`. Never acknowledge merely because a report was printed or read. The optional Resend adapter below handles the approved destination and provider receipt before acknowledgment. Input failures continue producing reports and durable pending alerts; failures that prevent persistence explicitly include `deliveryPersistenceFailure`. State-directory startup failures or stdout errors stop the CLI so the supervisor can restart it. The CLI does not exit on an assessment finding, avoiding replay-producing restart loops.

`deploy/crypto-agility-consumer@.service` is an installation template, not discovered production coordinates. Review its paths and existing service account, install a pinned checkout and virtual environment at the chosen location, provision approved configuration/bundles, and retain private writable state. Install dependencies from `requirements.txt` with the supported Python version; ML-DSA verification additionally needs the compatible OpenSSL runtime described in the attestation documentation. The template grants no network access and exposes no signing credentials. Validate the unit on the actual Linux host with `systemd-analyze verify` before installing; no enable/start command is authorized by the mere presence of this template.

Before activation, run the zero-skip acceptance suite, authenticate a fresh exact-bound bundle, exercise a selector switch, restart/replay rejection, expiry, missing configuration, durable failure recovery and confirmed alert delivery at the operator's destination. Verify actual service ownership, filesystem permissions and persistence across a service restart. Hosted CI must cover the final committed tree; local fixture tests alone do not establish production success.

## Automated internal KMS status

An operator can replace the manually asserted `keyStatus` object with the following internal policy. The existing `trust` entry must use the pinned ML-DSA-65 SPKI DER key; a matching key identifier alone is insufficient:

```json
{
  "mode": "aws-kms",
  "receipt": "/absolute/private/config/kms-status.json",
  "withdrawal": "/absolute/private/config/withdrawal.json",
  "keyArn": "arn:aws:kms:REGION:ACCOUNT:key/UUID",
  "spkiSha256": "<independently approved 64-hex SPKI digest>"
}
```

The independently provisioned withdrawal file contains `{"version":1,"withdrawn":false,"reason":"<operator decision>"}`. Changing `withdrawn` to `true` immediately fails the next consumer check; a missing/malformed file fails closed. The refresher never writes this override. Retain the local override independently of downloaded receipts, bundles and deployment releases.

Run `python -m tools.kms_status --policy /private/kms-policy.json --output /private/kms-status.json` in the existing authorized signing environment. The policy contains exactly `version: 1`, `keyArn`, `spkiSha256` and `ttlSeconds`. Use an explicit key ARN, never an alias. A 15-minute workflow interval with `ttlSeconds: 1800` leaves one refresh interval of margin; the maximum accepted receipt lifetime is one hour. Optional `--profile qk-attest` selects an already configured local profile. Actions should inherit its existing AWS authentication and omit the profile. No signing API is called and no credentials are read out, copied, exported to the consumer or installed on its host.

The bounded CLI invokes authenticated `DescribeKey` and `GetPublicKey` against the fixed regional HTTPS KMS endpoint. It requires the exact ARN, enabled state, `ML_DSA_65`, `SIGN_VERIFY`, `ML_DSA_SHAKE_256`, valid ML-DSA-65 SPKI framing and the approved SHA-256 digest. AWS documents the SPKI and algorithm fields in [GetPublicKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html). Requests that fail or disagree replace the receipt with `unknown` and return a nonzero exit code. Transfer that unknown receipt too; do not conceal a disabled key by publishing only successful refreshes. Invalid local policy or an unwritable output path stops publication; an old receipt expires naturally and cannot remain valid indefinitely.

Publish the receipt over the independently authenticated SSH connection into the private configuration directory, with atomic replacement, file/directory fsync and owner-only permissions. Its exact fields are `version`, `status`, `keyArn`, `spkiSha256`, `checkedAt`, `validUntil`, and `source` (`aws-kms:DescribeKey+GetPublicKey`). This JSON is not self-authenticating: trust depends on the authorized refresher, verified SSH host identity and protected local file. The consumer checks the receipt against both the configured ARN/pin and actual trusted public key, requires current bounded timestamps, and persists the highest valid KMS check time to reject rollback, including unknown-status receipts. After an unknown receipt, only an active check with a strictly later timestamp can restore acceptance. Receipt absence, expiry, unknown status or local withdrawal queues a durable monitor failure without replacing the last trusted baseline.

This internal policy establishes that the authorized refresh observed the expected KMS key enabled, subject to the receipt's freshness window and AWS eventual consistency. It does not establish public, root-signed nonrevocation, third-party measurement independence or PQC TLS authentication. Public revocation publication and independent interoperability remain distinct acceptance work.

## Durable email delivery

The approved QuantaKrypto alert destination is `leon@quantakrypto.com`. Provision owner-private `delivery.json` with `{"version":1,"recipient":"leon@quantakrypto.com","sender":"quantakrypto <no-reply@quantakrypto.com>"}` after confirming the existing sender configuration. Honor a configured production `EMAIL_FROM` when provisioning this sender instead of assuming the default. The adapter uses the existing `RESEND_API_KEY` from its runtime environment; it does not create, copy or print the key. Configure the service to read the existing host environment in place using a reviewed host-specific `EnvironmentFile` drop-in or an existing launcher that passes only the needed variable. Protect that existing source file with owner-only permissions before activation. The public contact form and its automatic confirmation are not a monitor transport.

Explicitly initialize delivery once with `python -m tools.alert_delivery --initialize-delivery --state-directory /absolute/private/state`, after initializing the consumer state. This adds `delivery.json` and its stable lock inside the persistent state directory. Initialization refuses previous or interrupted delivery state. Missing delivery state after initialization is an error; never delete it to retry a send. Run `python -m tools.alert_delivery --config /absolute/private/config/delivery.json --state-directory /absolute/private/state` from the existing mail runtime environment. The service/timer templates run independently from the offline consumer, so mail failures do not stop measurement assessment.

Each alert occurrence gets a durable sending intent and immutable payload before any network call. The Resend idempotency key is derived from its `deliveryId`; a returned provider message ID is persisted before polling. The message names the subject, occurrence, finding and repair action. Up to three least-recently-checked pending occurrences are processed per run, so bounced or ambiguous messages cannot starve later alerts. The provider transport uses fixed HTTPS endpoints, rejects redirects and bounds response bytes and total request time. Errors expose only fixed diagnostics, never API credentials or response bodies.

API acceptance (`sent` or `queued`) is not delivery. The adapter retains the pending alert until the provider's matching message record reports `delivered`, `opened` or `clicked`; it durably records that result before acknowledging the exact occurrence. This is provider-reported delivery to the receiving mail system, not proof that a human read or acted on the alert. The provider ID and delivery event remain in the private journal for acceptance evidence. Bounces, suppression, failure and complaints remain pending and report `delivery-failed` for operator action. Unknown or inaccessible provider status cannot acknowledge an alert; the existing key must permit message retrieval as well as sending.

Resend retains [idempotency keys for 24 hours](https://resend.com/changelog/idempotency-keys). An ambiguous submission can retry the same immutable request for at most 23 hours. After that it reports `reconciliation-required` and never blindly resends. Reconcile the occurrence tag/provider activity before any operator recovery; the tool deliberately cannot guess whether a message was sent when both acknowledgment and provider ID were lost. Delivered receipts can be retried locally after an outbox-write failure without sending another email. Retain receipt history across releases; reaching the bounded journal capacity requires reviewed archival, not silent deletion.

For production acceptance, send a clearly labeled monitor test occurrence to the approved recipient through this same durable path. Verify the provider-reported delivery event, persistent receipt and exact outbox acknowledgment, then exercise a send/status failure and recovery without losing its occurrence ID. Do not claim delivery from the CLI exit code alone. Hosted CI covers fixture provider behavior; the real host receipt establishes actual delivery.
