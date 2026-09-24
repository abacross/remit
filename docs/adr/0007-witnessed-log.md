# 0007: The witnessed log

Date: 2026-09-24. Status: accepted.

## Context

SPEC section 6 defines completeness against `L`, "the set of warrants in the log", and the threat model relies on that log twice.
Against an operator (A4), the log must not be rewritable unnoticed, and must not show one history to an auditor and another to the broker.
Against a stolen issuer key (assumption 3), the log is what makes misuse visible: a warrant the thief issues and uses must leave a public trace.

Neither property comes from signing alone.
A signed log can still be forked: the operator signs two histories and shows each to a different party.
What prevents that is a second party that has seen the history, checks that each new state extends the last, and says so in a way anyone can verify.

This is a solved problem with an ecosystem.
Certificate Transparency, the Go checksum database and Sigstore all use the same pieces, now specified by C2SP:

- the RFC 9162 Merkle tree, with inclusion and consistency proofs;
- checkpoints, the log's signed statement of size and root (c2sp.org/tlog-checkpoint), in the signed note format (c2sp.org/signed-note);
- witnesses, which cosign a checkpoint only after verifying it is consistent with the largest one they have seen (c2sp.org/tlog-cosignature, c2sp.org/tlog-witness);
- tiles, a static layout that serves the whole log as immutable files from any web server or bucket (c2sp.org/tlog-tiles).

## Options

1. **A Remit-specific log format.** Complete control, and no witness anywhere could cosign it.
2. **The C2SP stack**, with Remit defining only what goes in and when it must be there.
3. **An existing public log such as Sigstore's Rekor.** Operated by others, well witnessed, but the product's central claim would rest on a third party's availability, retention and entry types.
4. **Timestamp anchoring alone** (RFC 3161, OpenTimestamps). Proves that a state existed by a time; says nothing about whether two parties were shown the same state.

## Decision

Option 2.

- **Formats are not invented.** The tree is RFC 9162 with SHA-256; checkpoints, notes, cosignatures and tiles are C2SP's. `remit-log` is tested against the RFC's own example, transparency-dev's corpus of valid and corrupted proofs, and vectors made by the reference Go implementations, which it reproduces byte for byte.
- **What is logged** (SPEC section 9.1): every signed warrant, one entry per link, and every reconciliation result, as a commitment to its bytes and signature. Credential issuance is not logged: the provider's own record is the authority on sessions, and SPEC section 6.2 already checks each session against its warrant. A second record of sessions, written by the broker, would be a record the operator writes, which is exactly what Remit declines to rely on.
- **Logged before used** (SPEC section 9.3): the broker issues no session for a chain unless every link is proven included in a checkpoint that its trust policy accepts. This is the rule that turns a stolen issuer key from invisible into visible.
- **Witnesses are chosen by the verifier.** Remit ships a witness (`remit witness`) so that a customer, their auditor or a design partner can run one, and a verifier's policy names the witnesses it trusts and how many must cosign. The operator of the log cannot choose them on the verifier's behalf.
- **Signatures.** The log signs with Ed25519 (type `0x01`), which tlog-tiles requires of any log that takes part in the public witness network. Witnesses cosign with timestamped Ed25519 (type `0x04`). tlog-cosignature recommends ML-DSA-44 for new deployments, because Ed25519 is not secure against quantum computers; Remit will add it before the log is offered to anyone else. **Unverified:** whether a Rust ML-DSA-44 implementation meets ADR 0002's bar today; the fact that settles it is the audit status of RustCrypto's `ml-dsa` crate.
- **Strictness beyond the formats.** Remit takes the signed note specification's "SHOULD reject" as "must", decodes base64 in one spelling only, and refuses checkpoint extension lines, which the checkpoint specification itself calls not auditable.

## Consequences

- A split view needs the log and a quorum of the verifier's witnesses to collude.
- The log is on the broker's path: if it cannot prove inclusion, no session is issued. This is failing closed, and it makes the log's availability part of Remit's.
- Serving the log is static files, so its running cost is storage and requests, not servers. Where it is hosted, and at what cost, is an owner decision (it spends money), taken when the log first leaves this machine.
- Joining the public witness network is outward-facing and is also an owner decision; until then, witnesses are ones Remit's users run.

## What would change it

A split-view defence that needs no witnesses, a C2SP revision that Remit's formats must follow, or evidence that a design partner's auditors will only accept a specific external timestamping authority, which would add RFC 3161 anchoring beside the witnesses rather than instead of them.
