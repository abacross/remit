//! The Merkle tree of RFC 9162 section 2.1 (the same tree as RFC 6962), with SHA-256.
//!
//! Generation here works over the full list of leaf hashes and follows the RFC's recursive
//! definitions literally, so that it can serve as the reference the tile-backed log is
//! tested against. Verification follows the RFC's iterative algorithms, and is checked
//! against an independent corpus of valid and corrupted proofs (tests/vectors).

use sha2::{Digest, Sha256};

/// A SHA-256 hash: a leaf hash, an interior node, or a root.
pub type Hash = [u8; 32];

/// Why a proof was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The index is not inside the tree, or the second tree is smaller than the first.
    OutOfRange,
    /// The proof has the wrong number of hashes for the sizes given.
    WrongLength,
    /// The proof is well formed but does not lead to the roots given.
    Mismatch,
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::OutOfRange => "index or size out of range",
            Self::WrongLength => "proof has the wrong number of hashes",
            Self::Mismatch => "proof does not lead to the root",
        })
    }
}

impl std::error::Error for ProofError {}

/// The root of the empty tree: `SHA-256()`.
#[must_use]
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// The hash of a leaf: `SHA-256(0x00 || entry)`.
#[must_use]
pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(entry);
    h.finalize().into()
}

/// The hash of an interior node: `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two smaller than `n`, for `n >= 2` (RFC 9162 `k`).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let below = n.saturating_sub(1);
    1_usize
        << (usize::BITS
            .saturating_sub(1)
            .saturating_sub(below.leading_zeros()))
}

/// The Merkle Tree Hash of a list of leaf hashes (RFC 9162 section 2.1.1).
#[must_use]
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => empty_root(),
        [only] => *only,
        _ => {
            let (left, right) = leaves.split_at(split(leaves.len()));
            node_hash(&root(left), &root(right))
        }
    }
}

/// The inclusion proof for leaf `index` (RFC 9162 section 2.1.3.1), or `None` when the
/// index is not in the tree.
#[must_use]
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    path(leaves, index, &mut proof);
    Some(proof)
}

fn path(leaves: &[Hash], index: usize, proof: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split(leaves.len());
    let (left, right) = leaves.split_at(k);
    if index < k {
        path(left, index, proof);
        proof.push(root(right));
    } else {
        path(right, index.saturating_sub(k), proof);
        proof.push(root(left));
    }
}

/// The consistency proof from the first `old_size` leaves to all of them (RFC 9162
/// section 2.1.4.1), or `None` when `old_size` is larger than the tree. Empty when
/// `old_size` is zero or the whole tree, which need no proof.
#[must_use]
pub fn consistency_proof(leaves: &[Hash], old_size: usize) -> Option<Vec<Hash>> {
    if old_size > leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    if old_size > 0 && old_size < leaves.len() {
        subproof(leaves, old_size, true, &mut proof);
    }
    Some(proof)
}

fn subproof(leaves: &[Hash], m: usize, known: bool, proof: &mut Vec<Hash>) {
    if m == leaves.len() {
        if !known {
            proof.push(root(leaves));
        }
        return;
    }
    let k = split(leaves.len());
    let (left, right) = leaves.split_at(k);
    if m <= k {
        subproof(left, m, known, proof);
        proof.push(root(right));
    } else {
        subproof(right, m.saturating_sub(k), false, proof);
        proof.push(root(left));
    }
}

/// Verifies that `leaf` is at `index` in the tree of `size` leaves whose root is `root`
/// (RFC 9162 section 2.1.3.2).
///
/// # Errors
///
/// [`ProofError::OutOfRange`] when `index >= size`, [`ProofError::WrongLength`] when the
/// proof is longer or shorter than the path, [`ProofError::Mismatch`] otherwise.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf: &Hash,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), ProofError> {
    if index >= size {
        return Err(ProofError::OutOfRange);
    }
    let mut f = index;
    let mut s = size.saturating_sub(1);
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return Err(ProofError::WrongLength);
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(ProofError::WrongLength);
    }
    if r == *root {
        Ok(())
    } else {
        Err(ProofError::Mismatch)
    }
}

/// Verifies that the tree of `size2` leaves with root `root2` extends the tree of `size1`
/// leaves with root `root1` (RFC 9162 section 2.1.4.2).
///
/// Sizes the RFC leaves undefined are settled as follows: equal sizes need an empty proof
/// and equal roots; a first size of zero needs an empty proof, because every tree extends
/// the empty one.
///
/// # Errors
///
/// [`ProofError::OutOfRange`] when `size2 < size1`, [`ProofError::WrongLength`] when the
/// proof has the wrong number of hashes, [`ProofError::Mismatch`] otherwise.
pub fn verify_consistency(
    size1: u64,
    size2: u64,
    root1: &Hash,
    root2: &Hash,
    proof: &[Hash],
) -> Result<(), ProofError> {
    if size2 < size1 {
        return Err(ProofError::OutOfRange);
    }
    if size1 == size2 || size1 == 0 {
        if !proof.is_empty() {
            return Err(ProofError::WrongLength);
        }
        return if size1 == 0 || root1 == root2 {
            Ok(())
        } else {
            Err(ProofError::Mismatch)
        };
    }
    if proof.is_empty() {
        return Err(ProofError::WrongLength);
    }
    let (first, rest) = if size1.is_power_of_two() {
        (root1, proof)
    } else {
        proof.split_first().ok_or(ProofError::WrongLength)?
    };
    let mut f = size1.saturating_sub(1);
    let mut s = size2.saturating_sub(1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let mut fr = *first;
    let mut sr = *first;
    for c in rest {
        if s == 0 {
            return Err(ProofError::WrongLength);
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(ProofError::WrongLength);
    }
    if fr == *root1 && sr == *root2 {
        Ok(())
    } else {
        Err(ProofError::Mismatch)
    }
}
