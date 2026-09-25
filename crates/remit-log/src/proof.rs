//! Proof that a chain is logged (SPEC section 9.3), and the trust policy file a verifier
//! keeps (section 9.2).
//!
//! A proof is text:
//!
//! ```text
//! remit-logged/v1
//! <index> <hash> <hash> ...      one line per link, in chain order
//!
//! <the checkpoint, as a signed note with its cosignatures>
//! ```
//!
//! Each line gives the link's entry index and its inclusion proof in that checkpoint's
//! tree, hashes in base64. A policy is text, one directive per line: `log <vkey>`, then
//! `witness <vkey>` for each trusted witness, then `quorum <k>`.

use core::fmt;

use remit_core::SignedWarrant;

use crate::base64;
use crate::checkpoint::{CheckpointError, TrustPolicy, TrustedCheckpoint, open};
use crate::entry::Entry;
use crate::merkle::{Hash, verify_inclusion};
use crate::note::{KeyKind, VerifierKey};

const HEADER: &str = "remit-logged/v1";

/// The most links a proof covers: the longest chain (SPEC section 5.5).
const MAX_LINKS: usize = 16;

/// The longest inclusion proof in a tree of up to 2^64 entries.
const MAX_PROOF: usize = 64;

/// Why a proof or policy was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofFileError {
    /// Not in the format; the reason says where.
    Malformed(&'static str),
    /// The checkpoint does not satisfy the policy.
    Checkpoint(CheckpointError),
    /// A link is not proven: its position in the chain.
    NotLogged(usize),
    /// The proof covers a different number of links than the chain has.
    WrongLinks,
}

impl fmt::Display for ProofFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed: {why}"),
            Self::Checkpoint(e) => write!(f, "checkpoint not trusted: {e}"),
            Self::NotLogged(i) => write!(f, "link {i} of the chain is not proven logged"),
            Self::WrongLinks => f.write_str("the proof is for a chain of another length"),
        }
    }
}

impl std::error::Error for ProofFileError {}

/// A proof that each link of a chain is in a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedProof {
    /// Per link, in chain order: its entry index and inclusion proof.
    pub links: Vec<(u64, Vec<Hash>)>,
    /// The checkpoint the proofs are against, as a signed note.
    pub checkpoint: String,
}

impl LoggedProof {
    /// The text form.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = format!("{HEADER}\n");
        for (index, proof) in &self.links {
            out.push_str(&index.to_string());
            for h in proof {
                out.push(' ');
                out.push_str(&base64::encode(h));
            }
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&self.checkpoint);
        out
    }

    /// Parses the text form.
    ///
    /// # Errors
    ///
    /// Anything [`LoggedProof::encode`] does not produce.
    pub fn parse(text: &str) -> Result<Self, ProofFileError> {
        let rest = text
            .strip_prefix(HEADER)
            .and_then(|r| r.strip_prefix('\n'))
            .ok_or(ProofFileError::Malformed("header"))?;
        let (link_lines, checkpoint) = rest
            .split_once("\n\n")
            .ok_or(ProofFileError::Malformed("no blank line"))?;
        let mut links = Vec::new();
        for line in link_lines.split('\n') {
            if links.len() == MAX_LINKS {
                return Err(ProofFileError::Malformed("too many links"));
            }
            let mut parts = line.split(' ');
            let index = parts
                .next()
                .filter(|n| {
                    *n == "0" || (!n.starts_with('0') && n.bytes().all(|c| c.is_ascii_digit()))
                })
                .and_then(|n| n.parse::<u64>().ok())
                .ok_or(ProofFileError::Malformed("index"))?;
            let proof: Vec<Hash> = parts
                .map(|h| base64::decode(h).and_then(|b| b.try_into().ok()))
                .collect::<Option<_>>()
                .ok_or(ProofFileError::Malformed("hash"))?;
            if proof.len() > MAX_PROOF {
                return Err(ProofFileError::Malformed("proof too long"));
            }
            links.push((index, proof));
        }
        Ok(Self {
            links,
            checkpoint: checkpoint.to_owned(),
        })
    }

    /// Verifies that every link of `chain` is included in a checkpoint `policy` trusts.
    ///
    /// # Errors
    ///
    /// An untrusted checkpoint, a proof for a chain of another length, or a link whose
    /// entry is not at its index.
    pub fn verify(
        &self,
        chain: &[SignedWarrant],
        policy: &TrustPolicy,
    ) -> Result<TrustedCheckpoint, ProofFileError> {
        let trusted = open(&self.checkpoint, policy).map_err(ProofFileError::Checkpoint)?;
        if chain.len() != self.links.len() {
            return Err(ProofFileError::WrongLinks);
        }
        let (size, root) = (trusted.checkpoint.size(), *trusted.checkpoint.root());
        for (i, (link, (index, proof))) in chain.iter().zip(&self.links).enumerate() {
            let leaf = Entry::warrant(link.clone())
                .map_err(|_| ProofFileError::NotLogged(i))?
                .leaf_hash();
            verify_inclusion(*index, size, &leaf, proof, &root)
                .map_err(|_| ProofFileError::NotLogged(i))?;
        }
        Ok(trusted)
    }
}

impl TrustPolicy {
    /// Parses a policy file: `log <vkey>`, any number of `witness <vkey>`, `quorum <k>`.
    /// Blank lines and lines starting with `#` are ignored.
    ///
    /// # Errors
    ///
    /// A missing or repeated `log` or `quorum`, a bad key, a key of the wrong kind, or a
    /// quorum larger than the number of distinct witnesses, which no checkpoint could meet.
    pub fn parse(text: &str) -> Result<Self, ProofFileError> {
        let mut log = None;
        let mut witnesses: Vec<VerifierKey> = Vec::new();
        let mut quorum = None;
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (directive, value) = line
                .split_once(' ')
                .ok_or(ProofFileError::Malformed("policy line"))?;
            match directive {
                "log" if log.is_none() => {
                    let key = VerifierKey::parse(value)
                        .map_err(|_| ProofFileError::Malformed("log key"))?;
                    if key.kind() != KeyKind::Log {
                        return Err(ProofFileError::Malformed("log key is not a log key"));
                    }
                    log = Some(key);
                }
                "witness" => {
                    let key = VerifierKey::parse(value)
                        .map_err(|_| ProofFileError::Malformed("witness key"))?;
                    if key.kind() != KeyKind::Witness {
                        return Err(ProofFileError::Malformed(
                            "witness key is not a witness key",
                        ));
                    }
                    witnesses.push(key);
                }
                "quorum" if quorum.is_none() => {
                    quorum = Some(
                        value
                            .parse::<usize>()
                            .map_err(|_| ProofFileError::Malformed("quorum"))?,
                    );
                }
                _ => return Err(ProofFileError::Malformed("unknown or repeated directive")),
            }
        }
        let log = log.ok_or(ProofFileError::Malformed("no log key"))?;
        let quorum = quorum.ok_or(ProofFileError::Malformed("no quorum"))?;
        let mut distinct: Vec<Vec<u8>> = witnesses.iter().map(VerifierKey::public_key).collect();
        distinct.sort_unstable();
        distinct.dedup();
        if quorum > distinct.len() {
            return Err(ProofFileError::Malformed(
                "quorum above the number of witnesses",
            ));
        }
        Ok(Self {
            log,
            witnesses,
            quorum,
        })
    }
}
