#!/usr/bin/env bash
# ci.sh - everything that must hold before a commit leaves this machine.
#
#   bash scripts/ci.sh
#
# Formatting, lints at pedantic level with warnings as errors, the tests (including the
# property tests that carry SPEC's theorems), and the docs, which must build without a
# broken link. Uses the pinned toolchain from rust-toolchain.toml (ADR 0002).
set -euo pipefail
cd "$(dirname "$0")/.."
step() { printf '\n== %s\n' "$*"; }
step "format";  cargo fmt --all -- --check
step "lints";   cargo clippy --workspace --all-targets --locked -- -D warnings
step "tests";   cargo test --workspace --locked
step "docs";    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
step "prose";   ! grep -rnP '\x{2014}' --include='*.md' --include='*.rs' . --exclude-dir=target || { echo "em dash found"; exit 1; }
printf '\nall checks passed\n'
