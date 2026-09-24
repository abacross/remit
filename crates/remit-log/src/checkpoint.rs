//! Checkpoints (c2sp.org/tlog-checkpoint): the log's signed statement of its size and root,
//! and the rule a client applies before trusting one (SPEC section 9).

use core::fmt;

use crate::base64;
use crate::merkle::Hash;
use crate::note::{KeyKind, Note, NoteError, Verified, VerifierKey};

/// Why a checkpoint was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// The note around it was refused.
    Note(NoteError),
    /// The body is not a checkpoint; the reason says where.
    Malformed(&'static str),
    /// The origin is not the one expected.
    WrongOrigin,
    /// The log's own signature is missing or does not verify.
    NotSignedByLog,
    /// Fewer distinct witnesses cosigned than the policy requires.
    Quorum {
        /// Witnesses required.
        need: usize,
        /// Witnesses whose cosignatures verified.
        got: usize,
    },
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Note(e) => e.fmt(f),
            Self::Malformed(why) => write!(f, "malformed checkpoint: {why}"),
            Self::WrongOrigin => f.write_str("checkpoint is for another log"),
            Self::NotSignedByLog => f.write_str("checkpoint is not signed by the log"),
            Self::Quorum { need, got } => {
                write!(f, "{got} witness cosignatures verified, {need} required")
            }
        }
    }
}

impl std::error::Error for CheckpointError {}

impl From<NoteError> for CheckpointError {
    fn from(e: NoteError) -> Self {
        Self::Note(e)
    }
}

/// A log's size and root, under its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    origin: String,
    size: u64,
    root: Hash,
}

impl Checkpoint {
    /// A checkpoint. The origin must be non-empty and contain no space, plus sign or
    /// control character (the specification's recommendation, required here).
    ///
    /// # Errors
    ///
    /// A bad origin.
    pub fn new(origin: &str, size: u64, root: Hash) -> Result<Self, CheckpointError> {
        if origin.is_empty()
            || origin
                .chars()
                .any(|c| c.is_whitespace() || c == '+' || c.is_control())
        {
            return Err(CheckpointError::Malformed("bad origin"));
        }
        Ok(Self {
            origin: origin.to_owned(),
            size,
            root,
        })
    }

    /// Parses a checkpoint body. Remit's log writes no extension lines, and a body with
    /// any is refused: nothing a client cannot audit is accepted.
    ///
    /// # Errors
    ///
    /// Anything but exactly the three lines.
    pub fn parse(body: &str) -> Result<Self, CheckpointError> {
        let lines = body
            .strip_suffix('\n')
            .ok_or(CheckpointError::Malformed("no final newline"))?;
        let mut lines = lines.split('\n');
        let (Some(origin), Some(size), Some(root), None) =
            (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            return Err(CheckpointError::Malformed(
                "not exactly origin, size and root",
            ));
        };
        let canonical = !size.is_empty()
            && size.bytes().all(|c| c.is_ascii_digit())
            && (size == "0" || !size.starts_with('0'));
        let size =
            size.parse::<u64>()
                .ok()
                .filter(|_| canonical)
                .ok_or(CheckpointError::Malformed(
                    "size is not a canonical decimal",
                ))?;
        let root: Hash = base64::decode(root).and_then(|r| r.try_into().ok()).ok_or(
            CheckpointError::Malformed("root is not a base64 SHA-256 hash"),
        )?;
        Self::new(origin, size, root)
    }

    /// The body, as signed.
    #[must_use]
    pub fn body(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            base64::encode(&self.root)
        )
    }

    /// The log's identity.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The number of entries.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The Merkle root.
    #[must_use]
    pub fn root(&self) -> &Hash {
        &self.root
    }
}

/// Who a client trusts for one log: the log's key, whose name is the log's origin, the
/// witnesses, and how many distinct witnesses must cosign.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    /// The log's key.
    pub log: VerifierKey,
    /// The witnesses' keys.
    pub witnesses: Vec<VerifierKey>,
    /// Distinct witness cosignatures required.
    pub quorum: usize,
}

/// A checkpoint that satisfied a [`TrustPolicy`], with the cosignatures that counted.
#[derive(Debug, Clone)]
pub struct TrustedCheckpoint {
    /// The checkpoint.
    pub checkpoint: Checkpoint,
    /// The witnesses that cosigned, with the time each signed at.
    pub cosignatures: Vec<Verified>,
}

/// Opens a signed checkpoint under a policy: the note verifies, the log signed it, its
/// origin is the log's name, and at least `quorum` distinct witnesses cosigned it.
///
/// # Errors
///
/// The first rule that fails.
pub fn open(note: &str, policy: &TrustPolicy) -> Result<TrustedCheckpoint, CheckpointError> {
    if policy.log.kind() != KeyKind::Log
        || policy
            .witnesses
            .iter()
            .any(|w| w.kind() != KeyKind::Witness)
    {
        return Err(CheckpointError::Malformed(
            "policy mixes up log and witness keys",
        ));
    }
    let note = Note::parse(note)?;
    let mut keys = vec![policy.log.clone()];
    keys.extend(policy.witnesses.iter().cloned());
    let verified = note.verify(&keys)?;
    if !verified.iter().any(|v| v.key == policy.log) {
        return Err(CheckpointError::NotSignedByLog);
    }
    let checkpoint = Checkpoint::parse(note.text())?;
    if checkpoint.origin() != policy.log.name() {
        return Err(CheckpointError::WrongOrigin);
    }
    // One witness is one public key: the specification requires distinct keys for
    // distinct cosigners, so two names on one key count once.
    let mut cosignatures: Vec<Verified> = Vec::new();
    for v in verified {
        if v.key.kind() == KeyKind::Witness
            && !cosignatures
                .iter()
                .any(|c| c.key.public_key() == v.key.public_key())
        {
            cosignatures.push(v);
        }
    }
    if cosignatures.len() < policy.quorum {
        return Err(CheckpointError::Quorum {
            need: policy.quorum,
            got: cosignatures.len(),
        });
    }
    Ok(TrustedCheckpoint {
        checkpoint,
        cosignatures,
    })
}
