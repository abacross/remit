# Test vectors

`transparency-dev-merkle.json` holds every inclusion and consistency proof case from the `testdata/inclusion` and `testdata/consistency` directories of [transparency-dev/merkle](https://github.com/transparency-dev/merkle) at commit `fbbcd741c3d1c69d8498487baa8edc9e5824847c`, gathered into one file with each case's original path in `path`.
They are Copyright 2019 Google LLC and others, licensed under the Apache License 2.0, and used here unchanged.
Of the 196 cases, 12 are valid proofs and 184 are the same proofs corrupted one way each: a flipped bit, a wrong size or index, a missing, extra or reordered hash.
A verifier written from RFC 9162 alone must agree with every one.

`c2sp-go.json` was produced by the program in `go/` with the reference Go implementations of the formats: `golang.org/x/mod/sumdb/note` for signed notes and `github.com/transparency-dev/formats/note` for cosignatures, at the versions pinned in `go/go.mod`.
It signs one checkpoint with a log key and cosigns it with a witness key, both from fixed seeds, and checks the result with the reference verifiers before writing it.
Regenerate with `go run .` in `go/`; the log signature is deterministic, and the cosignature changes only with its timestamp.
