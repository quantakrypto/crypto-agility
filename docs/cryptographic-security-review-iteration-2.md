# Security review

Threats considered: forged or replayed collector statements, wrong-subject evidence,
stale measurements in fresh wrappers, algorithm confusion, offered-group spoofing,
invalid certificates, malicious HTTP destinations, resource exhaustion, local state
symlinks and concurrent writers. The reference tests exercise these boundaries.

The implementation uses standard TLS certificate/hostname verification and compact
JWS/JWT. It does not create a signature canonicalization algorithm, hybrid combiner,
Merkle construction or new certificate-validation mechanism. Ed25519 statement
signatures are classical; hybrid TLS key establishment says nothing by itself about
post-quantum authentication.

Declared capabilities remain declarations. Authenticated observations mean an
explicitly trusted collector signed scoped evidence. Independently verified security
requires corroborating measurements and an explicit relying-party decision; a
publisher cannot select this status in a manifest.

State is protected from partial writes, concurrent writers, permissive file modes,
symlinks and observable rollback. It cannot defend against the account owner, root,
loss of the state directory or restored disk images. An operator must retain and
recover trusted checkpoints. No alert delivery is claimed without a delivery receipt.

Scope decisions and remaining deployment blockers are recorded in
[implementation-status.md](implementation-status.md). Source-level security review
and passing adversarial tests are not a cryptographic certification or an IETF review.
