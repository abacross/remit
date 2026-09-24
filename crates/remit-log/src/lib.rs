//! The Remit witnessed log (SPEC section 9).
//!
//! An append-only log of warrants and reconciliation reports that anyone can check offline:
//! the RFC 9162 Merkle tree with inclusion and consistency proofs ([`merkle`]), checkpoints
//! signed by the log and cosigned by witnesses in the C2SP formats ([`note`],
//! [`checkpoint`]), so that the operator cannot show different histories to different
//! people unnoticed.

#![forbid(unsafe_code)]

pub mod base64;
pub mod checkpoint;
pub mod merkle;
pub mod note;

pub use checkpoint::{Checkpoint, CheckpointError, TrustPolicy, TrustedCheckpoint, open};
pub use merkle::{
    Hash, ProofError, consistency_proof, empty_root, inclusion_proof, leaf_hash, node_hash, root,
    verify_consistency, verify_inclusion,
};
pub use note::{KeyKind, Note, NoteError, NoteSigner, SignatureLine, Verified, VerifierKey};
