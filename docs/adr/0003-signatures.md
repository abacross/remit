# 0003: Signatures and delegation chains

Date: 2026-09-24. Status: proposed.

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

Not yet taken. It must be taken before any code signs anything.
