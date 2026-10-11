# Crypto-agility v2 production validation plan

**Goal:** Complete the existing PR implementation and verify production acceptance using the existing authority and collector.

**Architecture:** Retain the deployed Observatory timer and database, existing AWS signing identity and online key. Keep authenticated transport, issuer authorization, exact snapshot binding and durable state explicit. Never substitute fixture tests for observed production behavior.

**Constraints:** No private Authority source in public repositories, no credential copying, no new authority, one squashed change per affected repository, exact committed hosted CI, no IETF submission before readiness.

- [x] Read instructions, implementations, workflows, deployment docs and PR discussions; isolate worktrees and confirm remote heads.
- [x] Discover production service, worker path, runtime and existing signing context without exposing environment values.
- [x] Fix monitor baseline retention and durable alert outbox with regression tests and independent security review.
- [x] Disclose the proposed TLS 1.3/certificate validation methodology break without inventing a rollout date or device measurements.
- [x] Verify existing-key canary in website Actions with public-key continuity pin and no ledger mutation.
- [ ] Validate authenticated collection, exact binding, one serialized persistent ledger, consumer trust and persistent monitor/replay state before deployment acceptance.
- [ ] Establish alert destination with the operator and verify receipt; retain pending alerts until explicit acknowledgement.
- [ ] Run exact-tree hosted checks, review resulting evidence and merge only if every acceptance boundary is met.
- [ ] Recheck IETF requirements and preserve a handoff for any remaining operational or independent-review blocker.

Review focus: crash after state persistence; rejected evidence followed by a real TLS regression; legacy writers racing the issuer; unsigned transport records substituted for authenticated collection; unpublished or unverified method change misrepresented as observed rollout.
