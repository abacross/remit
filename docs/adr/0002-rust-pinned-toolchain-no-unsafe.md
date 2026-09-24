# 0002: Rust, a pinned toolchain, no unsafe code

Date: 2026-09-24. Status: accepted.

## Context

Remit parses untrusted input (warrants, cloud audit records), makes authorization decisions, and handles keys.
Memory-safety bugs in that code are security vulnerabilities, and nondeterministic builds make signed releases unverifiable.

## Decision

- Rust, for memory safety without a garbage collector and for a type system that can carry invariants (a `Pattern` that exists is a valid pattern).
- The toolchain is pinned to an exact version in `rust-toolchain.toml` (1.98.1 at the start), and moves only by a reviewed change that runs the full suite.
- `unsafe` is forbidden in every crate (`#![forbid(unsafe_code)]`). A future need for it is an ADR, not an edit.
- Clippy at pedantic level and rustfmt are part of CI, and warnings fail it.
- Dependencies are few, widely used, and audited before they are added; each one is justified in the commit that adds it.

## Consequences

Some conveniences are unavailable, and some code is longer than it would be with `unsafe` or with a large dependency.
In exchange, whole classes of vulnerability do not exist in the codebase, and a build today and a build next year from the same commit produce the same program.

## What would change it

A primitive that genuinely needs `unsafe` for correctness or performance, isolated in its own crate with its own review and fuzzing.
