//! Warrants for AI agents: what one agent may do, where, and when; the authorization
//! decision; delegation that can only narrow; and a canonical, content-derived identity.
//!
//! This crate is the normative core of Remit and has no I/O. It implements SPEC sections
//! 3 and 4 (`docs/SPEC.md` in the repository); where the two disagree, this crate is wrong.
//!
//! ```
//! use remit_core::{Request, Warrant, WarrantSpec};
//!
//! let grants: &[(&[&str], &[&str])] = &[(&["s3:GetObject"], &["arn:aws:s3:::reports/*"])];
//! let warrant = Warrant::new(&WarrantSpec {
//!     issuer: "key:alice",
//!     subject: "agent:runner",
//!     purpose: "read the September reports",
//!     not_before: 1_790_000_000,
//!     not_after: 1_790_003_600,
//!     grants,
//!     parent: None,
//!     max_depth: 0,
//! })?;
//! let read = Request::new("agent:runner", "s3:getobject", "arn:aws:s3:::reports/sep.csv", 1_790_000_100)?;
//! let write = Request::new("agent:runner", "s3:PutObject", "arn:aws:s3:::reports/sep.csv", 1_790_000_100)?;
//! assert!(warrant.permits(&read));
//! assert!(!warrant.permits(&write));
//! assert_eq!(warrant.id().as_str().len(), 36); // fits AWS SourceIdentity
//! # Ok::<(), remit_core::WarrantError>(())
//! ```

#![forbid(unsafe_code)]

pub mod attenuation;
pub mod decode;
pub mod encoding;
pub mod pattern;
pub mod signed;
pub mod warrant;

pub use attenuation::{AttenuationError, check as check_attenuation};
pub use decode::DecodeError;
pub use pattern::{ActionPattern, PatternError, ResourcePattern};
pub use signed::{ChainError, IssuerKey, KeyId, SignatureError, SignedWarrant, verify_chain};
pub use warrant::{Grant, Identifier, Request, Warrant, WarrantError, WarrantId, WarrantSpec};
