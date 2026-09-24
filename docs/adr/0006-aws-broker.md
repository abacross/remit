# 0006: The AWS broker: a warrant becomes an STS session, and nothing else does

Date: 2026-09-24. Status: accepted.

## Context

SPEC section 6 assumes that managed principals obtain cloud credentials only through the broker, and that every session carries its warrant's identifier where the provider's own record will show it.
On AWS the mechanisms exist: `AssumeRole` with an inline session policy (the session is the intersection of the role and the policy), `SourceIdentity` (persisted across role chaining and recorded in CloudTrail), and a trust policy that can require it.

## Decision

1. **One role per trust domain, assumable only by the broker.** Its trust policy allows `sts:AssumeRole` only to the broker's principal and requires `sts:SourceIdentity`. The role's own policy is the ceiling; each warrant narrows it.
2. **The session policy is compiled from the warrant** (SPEC section 8.2), verbatim, with the window as a condition, refusing anything it cannot express exactly: policy variables, wildcards AWS forbids, or a policy over 2,048 characters.
3. **`SourceIdentity` is the warrant identifier.** It is what the reconciler joins CloudTrail events to warrants on (ADR 0004).
4. **The agent receives credentials in its process environment only.** `remit run -- <command>` verifies the chain, obtains the session, and starts the command with the credentials in its environment; nothing is written to disk.
5. **Crates.** The compiler is pure and lives in `remit-aws` beside a model of the evaluator used in tests. Network code (STS) lives in the broker and uses the official AWS SDK for Rust, a heavy dependency justified by correctness: request signing is not something to reimplement.

## Consequences

- Sessions last at least 900 seconds, so a warrant shorter than that cannot be used on AWS; the broker refuses it rather than issuing a longer session.
- Resource case is the one soundness assumption without a documented fact behind it; the reconciler reports any event it would let through (SPEC section 8.3).
- Creating the role is an AWS change and is approved by a human, once per account.

## What would change it

An AWS mechanism that binds a session to a caller-chosen identifier more directly than SourceIdentity, or evidence that the policy simulator and live enforcement disagree for the patterns Remit compiles.
