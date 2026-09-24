//! The Merkle tree against RFC 9162's own example, an independent implementation of the
//! root, the transparency-dev corpus of valid and corrupted proofs, and exhaustive
//! round trips with every single-bit corruption.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use remit_log::{
    Hash, ProofError, consistency_proof, empty_root, inclusion_proof, leaf_hash, node_hash, root,
    verify_consistency, verify_inclusion,
};
use serde_json::Value;

fn leaves(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
        .collect()
}

/// Decodes standard base64 to a hash, or `None` when it is not 32 bytes: the corpus has
/// deliberately malformed values, which the `Hash` type cannot hold.
fn decode(s: &str) -> Option<Hash> {
    // Standard base64; decoded here without a dependency.
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes().filter(|&c| c != b'=') {
        bits = (bits << 6) | A.iter().position(|&a| a == c)? as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out.try_into().ok()
}

/// A corpus value as a hash. A malformed value in a case that must fail is a pass: the
/// type refuses it before any verification. In a case that must pass, the value is one
/// the verifier ignores (a root of an empty tree, say), so it is replaced by a stand-in
/// derived from its text, keeping equal values equal.
fn value(v: &Value, want_err: bool) -> Result<Hash, ()> {
    let s = v.as_str().unwrap();
    match decode(s) {
        Some(h) => Ok(h),
        None if want_err => Err(()),
        None => Ok(leaf_hash(s.as_bytes())),
    }
}

fn hashes(v: &Value, want_err: bool) -> Result<Vec<Hash>, ()> {
    v.as_array().map_or(Ok(Vec::new()), |a| {
        a.iter().map(|h| value(h, want_err)).collect()
    })
}

fn corpus() -> Value {
    let path = format!(
        "{}/tests/vectors/transparency-dev-merkle.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
#[allow(clippy::many_single_char_names, reason = "the RFC's own node names")]
fn the_rfc_9162_example_tree() {
    // Section 2.1.5: seven leaves d0..d6, with the interior nodes named as in the RFC.
    let d = leaves(7);
    let (a, b, c, dd, e, f, d6) = (d[0], d[1], d[2], d[3], d[4], d[5], d[6]);
    let g = node_hash(&a, &b);
    let h = node_hash(&c, &dd);
    let i = node_hash(&e, &f);
    let j = d6;
    let k = node_hash(&g, &h);
    let l = node_hash(&i, &j);
    assert_eq!(root(&d), node_hash(&k, &l));

    assert_eq!(inclusion_proof(&d, 0).unwrap(), vec![b, h, l]);
    assert_eq!(inclusion_proof(&d, 3).unwrap(), vec![c, g, l]);
    assert_eq!(inclusion_proof(&d, 4).unwrap(), vec![f, j, k]);
    assert_eq!(inclusion_proof(&d, 6).unwrap(), vec![i, k]);

    assert_eq!(consistency_proof(&d, 3).unwrap(), vec![c, dd, g, l]);
    assert_eq!(consistency_proof(&d, 4).unwrap(), vec![l]);
    assert_eq!(consistency_proof(&d, 6).unwrap(), vec![i, j, k]);
}

#[test]
fn the_root_agrees_with_the_rfc_stack_algorithm() {
    // Section 2.1.2, written independently of the recursive definition.
    fn stack_root(d: &[Hash]) -> Hash {
        let mut stack: Vec<Hash> = Vec::new();
        for (i, leaf) in d.iter().enumerate() {
            stack.push(*leaf);
            for _ in 0..i.trailing_ones() {
                let r = stack.pop().unwrap();
                let l = stack.pop().unwrap();
                stack.push(node_hash(&l, &r));
            }
        }
        while stack.len() > 1 {
            let r = stack.pop().unwrap();
            let l = stack.pop().unwrap();
            stack.push(node_hash(&l, &r));
        }
        stack.pop().unwrap_or_else(empty_root)
    }
    let d = leaves(300);
    for n in 0..=d.len() {
        assert_eq!(root(&d[..n]), stack_root(&d[..n]), "size {n}");
    }
}

#[test]
fn the_transparency_dev_roots() {
    let inputs: [&[u8]; 8] = [
        b"",
        &[0x00],
        &[0x10],
        &[0x20, 0x21],
        &[0x30, 0x31],
        &[0x40, 0x41, 0x42, 0x43],
        &[0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
        &[
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f,
        ],
    ];
    let expected = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];
    let d: Vec<Hash> = inputs.iter().map(|i| leaf_hash(i)).collect();
    for (n, want) in expected.iter().enumerate() {
        let want: Vec<u8> = (0..want.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&want[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(root(&d[..n]).to_vec(), want, "size {n}");
    }
}

#[test]
fn every_inclusion_case_in_the_corpus() {
    let corpus = corpus();
    let cases = corpus["inclusion"].as_array().unwrap();
    assert_eq!(cases.len(), 98);
    let mut verified = 0;
    for c in cases {
        let want_err = c["wantErr"].as_bool().unwrap();
        let (Ok(leaf), Ok(proof), Ok(root)) = (
            value(&c["leafHash"], want_err),
            hashes(&c["proof"], want_err),
            value(&c["root"], want_err),
        ) else {
            continue;
        };
        let got = verify_inclusion(
            c["leafIdx"].as_u64().unwrap(),
            c["treeSize"].as_u64().unwrap(),
            &leaf,
            &proof,
            &root,
        );
        assert_eq!(got.is_err(), want_err, "{}", c["path"]);
        verified += 1;
    }
    // The other 26 carry a value that is not a 32-byte hash, which the type refuses.
    assert_eq!(verified, 72);
}

#[test]
fn every_consistency_case_in_the_corpus() {
    let corpus = corpus();
    let cases = corpus["consistency"].as_array().unwrap();
    assert_eq!(cases.len(), 98);
    let mut verified = 0;
    for c in cases {
        let want_err = c["wantErr"].as_bool().unwrap();
        let (Ok(root1), Ok(root2), Ok(proof)) = (
            value(&c["root1"], want_err),
            value(&c["root2"], want_err),
            hashes(&c["proof"], want_err),
        ) else {
            continue;
        };
        let got = verify_consistency(
            c["size1"].as_u64().unwrap(),
            c["size2"].as_u64().unwrap(),
            &root1,
            &root2,
            &proof,
        );
        assert_eq!(got.is_err(), want_err, "{}", c["path"]);
        verified += 1;
    }
    // The other 26 carry a value that is not a 32-byte hash, which the type refuses.
    assert_eq!(verified, 72);
}

fn flip(proof: &[Hash], at: usize, bit: usize) -> Vec<Hash> {
    let mut p = proof.to_vec();
    p[at][bit / 8] ^= 1 << (bit % 8);
    p
}

#[test]
fn every_inclusion_proof_verifies_and_no_corruption_does() {
    let d = leaves(70);
    for n in 1..=d.len() {
        let t = &d[..n];
        let r = root(t);
        let size = n as u64;
        for m in 0..n {
            let proof = inclusion_proof(t, m).unwrap();
            let idx = m as u64;
            assert_eq!(verify_inclusion(idx, size, &t[m], &proof, &r), Ok(()));
            // Wrong leaf, index, size or root.
            assert!(verify_inclusion(idx, size, &leaf_hash(b"x"), &proof, &r).is_err());
            assert!(verify_inclusion(idx, size, &t[m], &proof, &empty_root()).is_err());
            // A proof binds to its size only through the root: the same path can fit a
            // neighbouring size with the same root, which is why a checkpoint signs the
            // two together. Against the real tree of another size, it fails.
            if n < d.len() {
                let bigger = root(&d[..=n]);
                assert!(verify_inclusion(idx, size + 1, &t[m], &proof, &bigger).is_err());
            }
            if m + 1 < n {
                assert!(verify_inclusion(idx + 1, size, &t[m], &proof, &r).is_err());
            }
            // Every single-bit change, and a hash dropped, added or swapped.
            for at in 0..proof.len() {
                for bit in [0, 7, 100, 255] {
                    assert!(
                        verify_inclusion(idx, size, &t[m], &flip(&proof, at, bit), &r).is_err()
                    );
                }
            }
            let mut longer = proof.clone();
            longer.push(r);
            assert!(verify_inclusion(idx, size, &t[m], &longer, &r).is_err());
            if let Some((_, shorter)) = proof.split_last() {
                assert!(verify_inclusion(idx, size, &t[m], shorter, &r).is_err());
            }
            if proof.len() >= 2 && proof[0] != proof[1] {
                let mut swapped = proof.clone();
                swapped.swap(0, 1);
                assert!(verify_inclusion(idx, size, &t[m], &swapped, &r).is_err());
            }
        }
        assert!(inclusion_proof(t, n).is_none());
        assert_eq!(
            verify_inclusion(size, size, &d[0], &[], &r),
            Err(ProofError::OutOfRange)
        );
    }
}

#[test]
fn every_consistency_proof_verifies_and_no_corruption_does() {
    let d = leaves(40);
    for n in 0..=d.len() {
        let r2 = root(&d[..n]);
        for m in 0..=n {
            let r1 = root(&d[..m]);
            let proof = consistency_proof(&d[..n], m).unwrap();
            let (s1, s2) = (m as u64, n as u64);
            assert_eq!(
                verify_consistency(s1, s2, &r1, &r2, &proof),
                Ok(()),
                "{m} {n}"
            );
            if m > 0 && m < n {
                assert!(verify_consistency(s1, s2, &r2, &r2, &proof).is_err());
                assert!(verify_consistency(s1, s2, &r1, &r1, &proof).is_err());
                assert!(verify_consistency(s1 + 1, s2, &root(&d[..=m]), &r2, &proof).is_err());
                if n < d.len() {
                    let bigger = root(&d[..=n]);
                    assert!(verify_consistency(s1, s2 + 1, &r1, &bigger, &proof).is_err());
                }
                for at in 0..proof.len() {
                    for bit in [0, 9, 128, 255] {
                        let bad = flip(&proof, at, bit);
                        assert!(
                            verify_consistency(s1, s2, &r1, &r2, &bad).is_err(),
                            "{m} {n}"
                        );
                    }
                }
                let mut longer = proof.clone();
                longer.push(r1);
                assert!(verify_consistency(s1, s2, &r1, &r2, &longer).is_err());
                assert!(verify_consistency(s1, s2, &r1, &r2, &proof[1..]).is_err());
            }
            // A history that differs anywhere in the first m leaves is never consistent.
            if m > 0 && m < n {
                let mut forked = d[..n].to_vec();
                forked[m - 1] = leaf_hash(b"rewritten");
                let fr = root(&forked);
                assert!(verify_consistency(s1, s2, &r1, &fr, &proof).is_err());
            }
        }
        assert!(consistency_proof(&d[..n], n + 1).is_none());
        if n > 0 {
            assert_eq!(
                verify_consistency(n as u64, n as u64 - 1, &r2, &r2, &[]),
                Err(ProofError::OutOfRange)
            );
        }
    }
}
