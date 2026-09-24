# 0004: Completeness by two-way reconciliation against the provider's record

Date: 2026-09-24. Status: accepted.

## Context

Hash-chained and anchored logs prove that what was recorded has not changed.
They cannot prove that everything was recorded, because the recorder is the party whose completeness is in question.
Remit's distinguishing claim (SPEC section 6) needs evidence written by someone other than the agent and other than Remit.

## Decision

Completeness is established by reconciling Remit's warrants against the cloud provider's own audit record, in both directions: every event maps to a warrant that permits it, and every closed warrant's events are known.
The link between them is an identifier the provider itself stamps on every event: on AWS, the warrant identifier as the session's SourceIdentity, which the broker sets and the role's trust policy requires.

## Consequences

- The claim inherits the provider record's coverage and integrity, and every result states both (SPEC section 6, assumptions).
- The reconciler must verify the configuration that makes the link hold (trust policies requiring SourceIdentity, the trail's validation) on every run.
- Each provider needs its own identifier stamp and its own record parser; AWS first.

## What would change it

A provider record that does not carry a caller-chosen identifier through to every event, which would require a different linking mechanism for that provider.
