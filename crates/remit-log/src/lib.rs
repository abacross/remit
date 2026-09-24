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
pub mod entry;
pub mod merkle;
pub mod note;
pub mod proof;
pub mod tiles;
pub mod witness;

pub use checkpoint::{Checkpoint, CheckpointError, TrustPolicy, TrustedCheckpoint, open};
pub use entry::{ENTRY_MAGIC, Entry, EntryError, MAX_ENTRY_BYTES};
pub use merkle::{
    Hash, ProofError, consistency_proof, empty_root, inclusion_proof, leaf_hash, node_hash, root,
    verify_consistency, verify_inclusion,
};
pub use note::{KeyKind, Note, NoteError, NoteSigner, SignatureLine, Verified, VerifierKey};
pub use proof::{LoggedProof, ProofFileError};
pub use tiles::{TILE_WIDTH, TileError, TileSource, TileWrite, Tiles};
pub use witness::{MAX_PROOF_LINES, Witness, WitnessError};
