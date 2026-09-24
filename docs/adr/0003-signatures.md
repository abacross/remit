# 0003: Signatures and delegation chains

Date: 2026-09-24. Status: accepted (2026-09-24).

## Context

A warrant must be attributable to the key that issued it, and a delegation chain must be checkable offline by anyone with the root issuer's public key (SPEC section 5).
Two established approaches exist.
Biscuit tokens support offline attenuation natively, carry Datalog policies, and have a mature Rust implementation (`biscuit-auth`, Apache-2.0).
A plain Ed25519 signature over Remit's canonical encoding, with the parent linked by identifier, is simpler and keeps Remit's semantics in one place.

## Options

1. **Ed25519 over the canonical encoding** (RFC 8032, via a widely audited crate). Semantics live only in SPEC; a chain is a list of signed warrants.
2. **Biscuit as the container**, with Remit's grants expressed as Datalog facts and checks. Offline attenuation without the delegator's cooperation, at the cost of a second semantics (Datalog) that must be proven equivalent to SPEC section 3.4.

## Leaning

Option 1 for the first milestone, because a single semantics is easier to prove sound, and nothing in Remit needs attenuation without the delegator's key: delegation is always an act of the delegating agent.
Revisit if interoperability with Biscuit-based systems becomes a requirement.

## Decision

Option 1: Ed25519 (RFC 8032) over the canonical encoding, with the parent linked by identifier.

- **One semantics.** Authorization lives only in SPEC sections 3 and 4; there is no second language to prove equivalent.
- **Self-certifying key identifiers.** A key's identifier is `ed25519:` followed by its 32-byte public key in lowercase unpadded base32 (52 characters, 60 in all). Verifying a warrant needs no key directory: the identifier is the key. Which keys a verifier trusts as roots is configuration, not a lookup.
- **Strict verification.** Signatures are checked with the library's strict verification, which rejects small-order public keys and non-canonical signature encodings, so a warrant has exactly one valid signature form for a given key and message.
- **A chain is a list** of signed warrants from a trusted root to the warrant being used, each link checked for its signature and for attenuation (SPEC section 4).
- **The library** is `ed25519-dalek` 3.0 (BSD-3-Clause, widely used and audited). Key generation stays outside `remit-core`, which takes keys as bytes and has no source of randomness.

## Consequences

Interoperability with Biscuit-based systems is not automatic; a bridge would translate SPEC semantics into Biscuit, not the reverse.
An agent that delegates must hold its own signing key, which is exactly the property SPEC section 4 rule 4 relies on.

## What would change it

A requirement to attenuate without the delegator's key, which only Biscuit-style offline attenuation provides, or a post-quantum requirement, which would add a second signature algorithm under a new SPEC version.
