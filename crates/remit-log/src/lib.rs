//! The Remit witnessed log (SPEC section 9).
//!
//! An append-only log of warrants and reconciliation reports that anyone can check offline:
//! the RFC 9162 Merkle tree with inclusion and consistency proofs ([`merkle`]), and, built
//! on it, checkpoints signed by the log and cosigned by witnesses in the C2SP formats, so
//! that the operator cannot show different histories to different people unnoticed.

#![forbid(unsafe_code)]

pub mod merkle;

pub use merkle::{
    Hash, ProofError, consistency_proof, empty_root, inclusion_proof, leaf_hash, node_hash, root,
    verify_consistency, verify_inclusion,
};
