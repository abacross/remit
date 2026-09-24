//! A witness (c2sp.org/tlog-witness): cosigns a log's checkpoint only when it is
//! consistent with the last checkpoint the witness cosigned for that log.
//!
//! This is the protocol's logic without the HTTP: [`Witness::add_checkpoint`] takes the
//! request body and returns the response body or the error, and each error names the
//! status code the specification assigns it. The state it keeps, the last cosigned size
//! and root per log, is what makes a cosignature mean anything: a witness that forgets it
//! can be led to cosign a fork. The caller must make it durable before releasing a
//! cosignature ([`Witness::state_text`]).

use core::fmt;
use std::collections::BTreeMap;

use crate::base64;
use crate::checkpoint::Checkpoint;
use crate::merkle::{Hash, empty_root, verify_consistency};
use crate::note::{KeyKind, Note, NoteSigner, VerifierKey};

/// The most consistency proof lines a request may carry (tlog-witness).
pub const MAX_PROOF_LINES: usize = 63;

/// Why a checkpoint was not cosigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// The witness does not follow this log (404).
    UnknownOrigin,
    /// Not signed by the log's key, or a signature by it fails (403).
    Forbidden,
    /// The request is malformed, or the old size is above the checkpoint's (400).
    BadRequest(&'static str),
    /// The old size is not the size the witness last cosigned, which it returns (409).
    Conflict(u64),
    /// The checkpoint is not consistent with what the witness cosigned before (422).
    Unprocessable(&'static str),
}

impl WitnessError {
    /// The HTTP status tlog-witness assigns.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::UnknownOrigin => 404,
            Self::Forbidden => 403,
            Self::BadRequest(_) => 400,
            Self::Conflict(_) => 409,
            Self::Unprocessable(_) => 422,
        }
    }
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOrigin => f.write_str("unknown log"),
            Self::Forbidden => f.write_str("not signed by the log"),
            Self::BadRequest(why) => write!(f, "bad request: {why}"),
            Self::Conflict(size) => write!(f, "last cosigned size is {size}"),
            Self::Unprocessable(why) => write!(f, "not consistent: {why}"),
        }
    }
}

impl std::error::Error for WitnessError {}

/// A witness: its key, the logs it follows, and the last checkpoint it cosigned for each.
#[derive(Debug)]
pub struct Witness {
    signer: NoteSigner,
    logs: Vec<VerifierKey>,
    latest: BTreeMap<String, (u64, Hash)>,
}

impl Witness {
    /// A witness that follows `logs` (each key's name is its log's origin), starting from
    /// the state `state_text` wrote, or from nothing.
    ///
    /// # Errors
    ///
    /// A signer that is not a witness key, a log key that is not a log key, or a state
    /// that does not parse.
    pub fn new(
        signer: NoteSigner,
        logs: Vec<VerifierKey>,
        state: &str,
    ) -> Result<Self, WitnessError> {
        if signer.verifier_key().kind() != KeyKind::Witness
            || logs.iter().any(|k| k.kind() != KeyKind::Log)
        {
            return Err(WitnessError::BadRequest("wrong key kinds"));
        }
        let mut latest = BTreeMap::new();
        for line in state.lines() {
            let mut parts = line.split(' ');
            let (Some(origin), Some(size), Some(root), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(WitnessError::BadRequest("state line"));
            };
            let checkpoint = Checkpoint::parse(&format!("{origin}\n{size}\n{root}\n"))
                .map_err(|_| WitnessError::BadRequest("state line"))?;
            latest.insert(origin.to_owned(), (checkpoint.size(), *checkpoint.root()));
        }
        Ok(Self {
            signer,
            logs,
            latest,
        })
    }

    /// The state to make durable: one line per log, `<origin> <size> <root>`.
    #[must_use]
    pub fn state_text(&self) -> String {
        let mut out = String::new();
        for (origin, (size, root)) in &self.latest {
            for part in [
                origin.as_str(),
                " ",
                &size.to_string(),
                " ",
                &base64::encode(root),
                "\n",
            ] {
                out.push_str(part);
            }
        }
        out
    }

    /// The last checkpoint cosigned for `origin`: its size and root.
    #[must_use]
    pub fn latest(&self, origin: &str) -> Option<(u64, Hash)> {
        self.latest.get(origin).copied()
    }

    /// Handles an `add-checkpoint` request body at time `now` (POSIX seconds, not zero),
    /// and returns the response body: the cosignature line. On success the state has moved
    /// to the new checkpoint; persist it before returning the response.
    ///
    /// # Errors
    ///
    /// The checks of tlog-witness, in its order.
    pub fn add_checkpoint(&mut self, request: &str, now: u64) -> Result<String, WitnessError> {
        let (header, note) = request
            .split_once("\n\n")
            .ok_or(WitnessError::BadRequest("no blank line"))?;
        let mut lines = header.split('\n');
        let old = lines
            .next()
            .and_then(|l| l.strip_prefix("old "))
            .filter(|n| *n == "0" || (!n.starts_with('0') && n.bytes().all(|c| c.is_ascii_digit())))
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or(WitnessError::BadRequest("old size line"))?;
        let proof: Vec<Hash> = lines
            .map(|l| base64::decode(l).and_then(|h| h.try_into().ok()))
            .collect::<Option<_>>()
            .ok_or(WitnessError::BadRequest("proof line"))?;
        if proof.len() > MAX_PROOF_LINES {
            return Err(WitnessError::BadRequest("too many proof lines"));
        }

        let note = Note::parse(note).map_err(|_| WitnessError::BadRequest("not a note"))?;
        let origin = note.text().split('\n').next().unwrap_or_default();
        let keys: Vec<VerifierKey> = self
            .logs
            .iter()
            .filter(|k| k.name() == origin)
            .cloned()
            .collect();
        if keys.is_empty() {
            return Err(WitnessError::UnknownOrigin);
        }
        note.verify(&keys).map_err(|_| WitnessError::Forbidden)?;
        let checkpoint = Checkpoint::parse(note.text())
            .map_err(|_| WitnessError::BadRequest("not a checkpoint"))?;

        if old > checkpoint.size() {
            return Err(WitnessError::BadRequest("old size above the checkpoint's"));
        }
        let (latest_size, latest_root) = self
            .latest
            .get(origin)
            .copied()
            .unwrap_or((0, empty_root()));
        if old != latest_size {
            return Err(WitnessError::Conflict(latest_size));
        }
        if checkpoint.size() == 0 && *checkpoint.root() != empty_root() {
            return Err(WitnessError::Unprocessable("size 0 without the empty root"));
        }
        if old == 0 && !proof.is_empty() {
            return Err(WitnessError::Unprocessable("proof from the empty tree"));
        }
        if old == checkpoint.size() && *checkpoint.root() != latest_root {
            return Err(WitnessError::Unprocessable("same size, different root"));
        }
        verify_consistency(
            old,
            checkpoint.size(),
            &latest_root,
            checkpoint.root(),
            &proof,
        )
        .map_err(|_| WitnessError::Unprocessable("consistency proof does not verify"))?;
        if now == 0 {
            return Err(WitnessError::BadRequest("a cosignature needs a time"));
        }

        let line = self
            .signer
            .sign(note.text(), now)
            .map_err(|_| WitnessError::BadRequest("cannot cosign"))?;
        self.latest
            .insert(origin.to_owned(), (checkpoint.size(), *checkpoint.root()));
        Ok(line)
    }
}
