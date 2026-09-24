//! The Remit log on a filesystem (SPEC section 9), in exactly the layout it is served in
//! (c2sp.org/tlog-tiles): `checkpoint`, `tile/...`, `tile/entries/...` and `result/<hex>`.
//!
//! Crash safety rests on three rules. Every file is written whole or not at all (a
//! temporary file, flushed, renamed, and the directory flushed). Tiles and bundles are
//! written before the checkpoint that makes them part of the log, so a crash leaves at
//! worst files beyond the committed size, which the next append overwrites. And the
//! checkpoint commits the new size, signed by the log alone, before any witness is asked to
//! cosign it, so no witness ever holds a checkpoint the log did not publish; cosignatures
//! are added to the same checkpoint afterwards. One writer at a time holds `.lock`.

#![forbid(unsafe_code)]

use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use remit_log::tiles::{
    append as tile_append, bundle_path, decode_bundle, encode_bundle, tile_path,
};
use remit_log::{
    Checkpoint, Entry, Hash, Note, NoteSigner, TILE_WIDTH, TileError, TileSource, Tiles,
    VerifierKey, Witness, WitnessError, base64, empty_root,
};
use sha2::{Digest, Sha256};

/// What went wrong.
#[derive(Debug)]
pub enum StoreError {
    /// A file could not be read or written.
    Io(PathBuf, std::io::Error),
    /// Another writer holds the lock.
    Locked,
    /// The stored log is not what it should be; the reason says how.
    Corrupt(String),
    /// A request the log refuses; the reason says why.
    Refused(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "{}: {e}", path.display()),
            Self::Locked => f.write_str("another process is appending to this log"),
            Self::Corrupt(why) => write!(f, "log is corrupt: {why}"),
            Self::Refused(why) => write!(f, "refused: {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<TileError> for StoreError {
    fn from(e: TileError) -> Self {
        Self::Corrupt(e.to_string())
    }
}

type Result<T> = core::result::Result<T, StoreError>;

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> StoreError + '_ {
    move |e| StoreError::Io(path.to_owned(), e)
}

/// Writes `bytes` to `path` whole or not at all, creating directories as needed.
///
/// # Errors
///
/// Any I/O failure.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = directory_of(path);
    fs::create_dir_all(dir).map_err(io(dir))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| StoreError::Refused(format!("{} has no file name", path.display())))?;
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut f = File::create(&tmp).map_err(io(&tmp))?;
    f.write_all(bytes).map_err(io(&tmp))?;
    f.sync_all().map_err(io(&tmp))?;
    drop(f);
    fs::rename(&tmp, path).map_err(io(path))?;
    File::open(dir).and_then(|d| d.sync_all()).map_err(io(dir))
}

/// The directory a file is in: `.` for a bare file name, whose parent is the empty path
/// (which cannot be opened to flush it).
fn directory_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// A log directory, read as a [`TileSource`].
#[derive(Debug, Clone)]
pub struct LogDir {
    root: PathBuf,
}

impl LogDir {
    /// The directory at `root`.
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// The raw `checkpoint` file.
    ///
    /// # Errors
    ///
    /// It cannot be read.
    pub fn checkpoint_text(&self) -> Result<String> {
        let path = self.path("checkpoint");
        fs::read_to_string(&path).map_err(io(&path))
    }

    /// The current checkpoint, after checking that `log` signed it for its own origin.
    /// Witness cosignatures are not checked here; [`remit_log::open`] applies a policy.
    ///
    /// # Errors
    ///
    /// A checkpoint that does not parse or is not signed by `log`.
    pub fn checkpoint(&self, log: &VerifierKey) -> Result<Checkpoint> {
        let text = self.checkpoint_text()?;
        let note = Note::parse(&text).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        note.verify(core::slice::from_ref(log))
            .map_err(|e| StoreError::Corrupt(format!("checkpoint: {e}")))?;
        let checkpoint =
            Checkpoint::parse(note.text()).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        if checkpoint.origin() != log.name() {
            return Err(StoreError::Corrupt(
                "checkpoint is for another origin".into(),
            ));
        }
        Ok(checkpoint)
    }

    /// The inclusion proof for entry `index` in the tree of `size` entries.
    ///
    /// # Errors
    ///
    /// An index outside the tree, or corrupt tiles.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<Vec<Hash>> {
        Ok(Tiles::new(self, size).inclusion_proof(index)?)
    }

    /// The index of `entry` in the tree of `size` entries, if it is there, by reading the
    /// entry bundles in order. Linear in the log's size.
    ///
    /// # Errors
    ///
    /// A missing or corrupt bundle.
    pub fn find(&self, entry: &Entry, size: u64) -> Result<Option<u64>> {
        let wanted = entry.encode();
        let mut bundle: u64 = 0;
        while bundle.saturating_mul(TILE_WIDTH) < size {
            let width = size
                .saturating_sub(bundle.saturating_mul(TILE_WIDTH))
                .min(TILE_WIDTH);
            for (i, e) in self.bundle(bundle, width)?.iter().enumerate() {
                if *e == wanted {
                    let i = u64::try_from(i).unwrap_or(u64::MAX);
                    return Ok(Some(bundle.saturating_mul(TILE_WIDTH).saturating_add(i)));
                }
            }
            bundle = bundle.saturating_add(1);
        }
        Ok(None)
    }

    /// The entry at `index` in a tree of `size` entries.
    ///
    /// # Errors
    ///
    /// An index outside the tree, or a missing or corrupt bundle.
    pub fn entry(&self, index: u64, size: u64) -> Result<Entry> {
        if index >= size {
            return Err(StoreError::Refused("index outside the log".into()));
        }
        let bundle = index / TILE_WIDTH;
        let width = size
            .saturating_sub(bundle.saturating_mul(TILE_WIDTH))
            .min(TILE_WIDTH);
        let entries = self.bundle(bundle, width)?;
        let at = usize::try_from(index % TILE_WIDTH).unwrap_or(usize::MAX);
        let bytes = entries
            .get(at)
            .ok_or_else(|| StoreError::Corrupt(bundle_path(bundle, width)))?;
        Entry::decode(bytes).map_err(|e| StoreError::Corrupt(format!("entry {index}: {e}")))
    }

    fn bundle(&self, index: u64, width: u64) -> Result<Vec<Vec<u8>>> {
        let rel = bundle_path(index, width);
        let path = self.path(&rel);
        let bytes = fs::read(&path).map_err(io(&path))?;
        let entries = decode_bundle(&bytes)?;
        if u64::try_from(entries.len()).ok() != Some(width) {
            return Err(StoreError::Corrupt(rel));
        }
        Ok(entries)
    }

    /// A published result's bytes, by the digest a result entry commits to.
    ///
    /// # Errors
    ///
    /// Missing, or not the bytes the digest names.
    pub fn result(&self, digest: &Hash) -> Result<Vec<u8>> {
        let rel = result_path(digest);
        let path = self.path(&rel);
        let bytes = fs::read(&path).map_err(io(&path))?;
        let actual: Hash = Sha256::digest(&bytes).into();
        if actual != *digest {
            return Err(StoreError::Corrupt(rel));
        }
        Ok(bytes)
    }
}

impl TileSource for LogDir {
    fn read_tile(
        &self,
        level: u8,
        index: u64,
        width: u64,
    ) -> core::result::Result<Vec<Hash>, TileError> {
        let rel = tile_path(level, index, width);
        let bytes = fs::read(self.path(&rel)).map_err(|_| TileError::Missing(rel.clone()))?;
        let (hashes, rest) = bytes.as_chunks::<32>();
        if !rest.is_empty() || u64::try_from(hashes.len()).ok() != Some(width) {
            return Err(TileError::Corrupt(rel));
        }
        Ok(hashes.to_vec())
    }
}

/// Where a result is published: `result/` and the lowercase hex of its SHA-256.
#[must_use]
pub fn result_path(digest: &Hash) -> String {
    let hex: String = digest
        .iter()
        .flat_map(|b| {
            let [hi, lo] = [b >> 4, b & 0x0f];
            [hi, lo].map(|n| char::from_digit(u32::from(n), 16).unwrap_or('0'))
        })
        .collect();
    format!("result/{hex}")
}

/// Something that cosigns: a local witness, or a client of a remote one. It takes a
/// tlog-witness `add-checkpoint` request body and returns the cosignature lines.
pub trait Cosigner {
    /// A name for reports.
    fn name(&self) -> String;

    /// Submits a request.
    ///
    /// # Errors
    ///
    /// The witness's refusal.
    fn add_checkpoint(&mut self, request: &str) -> core::result::Result<String, WitnessError>;
}

/// A witness running in this process, whose state is a file made durable before any
/// cosignature leaves it.
#[derive(Debug)]
pub struct LocalWitness {
    name: String,
    witness: Witness,
    state: PathBuf,
    clock: fn() -> u64,
}

impl LocalWitness {
    /// A witness whose state lives at `state` (created empty if absent).
    ///
    /// # Errors
    ///
    /// A state file that cannot be read or does not parse.
    pub fn open(
        signer: NoteSigner,
        logs: Vec<VerifierKey>,
        state: &Path,
        clock: fn() -> u64,
    ) -> Result<Self> {
        let text = match fs::read_to_string(state) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(StoreError::Io(state.to_owned(), e)),
        };
        let name = signer.verifier_key().name().to_owned();
        let witness = Witness::new(signer, logs, &text)
            .map_err(|e| StoreError::Corrupt(format!("witness state: {e}")))?;
        Ok(Self {
            name,
            witness,
            state: state.to_owned(),
            clock,
        })
    }
}

impl Cosigner for LocalWitness {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn add_checkpoint(&mut self, request: &str) -> core::result::Result<String, WitnessError> {
        let line = self.witness.add_checkpoint(request, (self.clock)())?;
        // Durable before released: a witness that forgets can be led to cosign a fork.
        write_atomic(&self.state, self.witness.state_text().as_bytes())
            .map_err(|_| WitnessError::BadRequest("witness state could not be saved"))?;
        Ok(line)
    }
}

/// An open log, holding the writer's lock.
#[derive(Debug)]
pub struct Log {
    dir: LogDir,
    signer: NoteSigner,
    _lock: File,
}

/// A cosigner that refused: its name, and why.
pub type Refusal = (String, String);

/// What an append did.
#[derive(Debug, Clone)]
pub struct Appended {
    /// The index of the first appended entry.
    pub first: u64,
    /// The new checkpoint, with its cosignatures.
    pub checkpoint: String,
    /// The cosigners that refused, with why.
    pub refusals: Vec<Refusal>,
}

impl Log {
    /// Creates a log in an empty or absent directory, with a checkpoint of the empty tree.
    ///
    /// # Errors
    ///
    /// A directory that already holds a log, or any I/O failure.
    pub fn create(root: &Path, signer: NoteSigner) -> Result<Self> {
        if root.join("checkpoint").exists() {
            return Err(StoreError::Refused(format!(
                "{} already holds a log",
                root.display()
            )));
        }
        fs::create_dir_all(root).map_err(io(root))?;
        let log = Self::lock(root, signer)?;
        let body = log.body(0, empty_root())?;
        log.publish(&body, &[])?;
        Ok(log)
    }

    /// Opens an existing log for appending.
    ///
    /// # Errors
    ///
    /// No log there, a checkpoint the key did not sign, or the lock is held.
    pub fn open(root: &Path, signer: NoteSigner) -> Result<Self> {
        let log = Self::lock(root, signer)?;
        log.current()?;
        Ok(log)
    }

    fn lock(root: &Path, signer: NoteSigner) -> Result<Self> {
        let path = root.join(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(io(&path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(StoreError::Locked),
            Err(std::fs::TryLockError::Error(e)) => return Err(StoreError::Io(path, e)),
        }
        Ok(Self {
            dir: LogDir::new(root),
            signer,
            _lock: lock,
        })
    }

    /// The log's verifier key.
    #[must_use]
    pub fn verifier_key(&self) -> &VerifierKey {
        self.signer.verifier_key()
    }

    /// The directory, for reading.
    #[must_use]
    pub fn dir(&self) -> &LogDir {
        &self.dir
    }

    /// The current checkpoint, after checking the log's own signature on it.
    ///
    /// # Errors
    ///
    /// A checkpoint that does not parse or is not signed by this log's key.
    pub fn current(&self) -> Result<Checkpoint> {
        self.dir.checkpoint(self.signer.verifier_key())
    }

    fn body(&self, size: u64, root: Hash) -> Result<String> {
        Ok(
            Checkpoint::new(self.signer.verifier_key().name(), size, root)
                .map_err(|e| StoreError::Refused(e.to_string()))?
                .body(),
        )
    }

    fn publish(&self, body: &str, cosignatures: &[String]) -> Result<()> {
        let line = self
            .signer
            .sign(body, 0)
            .map_err(|e| StoreError::Refused(e.to_string()))?;
        let text = format!("{body}\n{line}{}", cosignatures.concat());
        write_atomic(&self.dir.path("checkpoint"), text.as_bytes())
    }

    /// Publishes a result's bytes at `result/<hex>` so that a result entry can be appended
    /// for it. Idempotent.
    ///
    /// # Errors
    ///
    /// Any I/O failure.
    pub fn publish_result(&self, bytes: &[u8]) -> Result<Hash> {
        let digest: Hash = Sha256::digest(bytes).into();
        let path = self.dir.path(&result_path(&digest));
        if !path.exists() {
            write_atomic(&path, bytes)?;
        }
        Ok(digest)
    }

    /// Appends entries, commits the new checkpoint, then asks each cosigner to cosign it and
    /// republishes the checkpoint with the cosignatures it got. A result entry needs its
    /// result published first ([`Log::publish_result`]).
    ///
    /// # Errors
    ///
    /// A result entry without its result, or any I/O failure. A cosigner's refusal is not
    /// an error: it is reported in [`Appended::refusals`], and the checkpoint stands
    /// without that cosignature.
    pub fn append(
        &mut self,
        entries: &[Entry],
        cosigners: &mut [&mut dyn Cosigner],
    ) -> Result<Appended> {
        let old = self.current()?;
        for e in entries {
            if let Entry::Result { digest, .. } = e {
                let bytes = self.dir.result(digest)?;
                e.check_result(&bytes)
                    .map_err(|err| StoreError::Refused(err.to_string()))?;
            }
        }
        let size = old.size();
        let added =
            u64::try_from(entries.len()).map_err(|_| StoreError::Refused("too many".into()))?;
        let new_size = size
            .checked_add(added)
            .ok_or_else(|| StoreError::Refused("log full".into()))?;

        // 1. Entry bundles and tiles, all beyond the committed size.
        self.write_bundles(size, entries)?;
        let leaves: Vec<Hash> = entries.iter().map(Entry::leaf_hash).collect();
        for w in tile_append(&self.dir, size, &leaves)? {
            write_atomic(&self.dir.path(&w.path()), &w.bytes())?;
        }
        // Reading the root back through the files just written checks them.
        let root = Tiles::new(&self.dir, new_size).root()?;

        // 2. Commit: the log's own checkpoint.
        let body = self.body(new_size, root)?;
        self.publish(&body, &[])?;

        // 3. Cosign the committed checkpoint.
        let (cosignatures, refusals) = self.cosign(&body, size, cosigners)?;
        self.publish(&body, &cosignatures)?;
        Ok(Appended {
            first: size,
            checkpoint: self.dir.checkpoint_text()?,
            refusals,
        })
    }

    /// Asks cosigners to cosign the current checkpoint again, for example after a crash
    /// between commit and cosigning, or to add a new witness. Keeps nothing old: the
    /// checkpoint is republished with the cosignatures gathered now.
    ///
    /// # Errors
    ///
    /// Any I/O failure.
    pub fn cosign_current(&mut self, cosigners: &mut [&mut dyn Cosigner]) -> Result<Appended> {
        let current = self.current()?;
        let body = current.body();
        let (cosignatures, refusals) = self.cosign(&body, current.size(), cosigners)?;
        self.publish(&body, &cosignatures)?;
        Ok(Appended {
            first: current.size(),
            checkpoint: self.dir.checkpoint_text()?,
            refusals,
        })
    }

    fn cosign(
        &self,
        body: &str,
        hint: u64,
        cosigners: &mut [&mut dyn Cosigner],
    ) -> Result<(Vec<String>, Vec<Refusal>)> {
        let checkpoint = Checkpoint::parse(body).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let line = self
            .signer
            .sign(body, 0)
            .map_err(|e| StoreError::Refused(e.to_string()))?;
        let signed = format!("{body}\n{line}");
        let tiles = Tiles::new(&self.dir, checkpoint.size());
        let mut cosignatures = Vec::new();
        let mut refusals = Vec::new();
        for c in cosigners.iter_mut() {
            // Start from the size this log last committed; a witness that last cosigned
            // another size says which, and the request is made again from there.
            let mut old = hint;
            let mut outcome = Err(WitnessError::BadRequest("not attempted"));
            for _ in 0..2 {
                if old > checkpoint.size() {
                    outcome = Err(WitnessError::Conflict(old));
                    break;
                }
                let proof: String = tiles
                    .consistency_proof(old)?
                    .iter()
                    .map(|h| base64::encode(h) + "\n")
                    .collect();
                let request = format!("old {old}\n{proof}\n{signed}");
                outcome = c.add_checkpoint(&request);
                match outcome {
                    Err(WitnessError::Conflict(theirs)) if theirs != old => old = theirs,
                    _ => break,
                }
            }
            match outcome {
                Ok(lines) => cosignatures.push(lines),
                Err(e) => refusals.push((c.name(), e.to_string())),
            }
        }
        Ok((cosignatures, refusals))
    }

    fn write_bundles(&self, size: u64, entries: &[Entry]) -> Result<()> {
        let first = size / TILE_WIDTH;
        let kept = size % TILE_WIDTH;
        let mut all = if kept > 0 {
            self.dir.bundle(first, kept)?
        } else {
            Vec::new()
        };
        all.extend(entries.iter().map(Entry::encode));
        for (i, chunk) in all.chunks(256).enumerate() {
            let index = first.saturating_add(u64::try_from(i).unwrap_or(u64::MAX));
            let width = u64::try_from(chunk.len()).unwrap_or(0);
            let bytes = encode_bundle(chunk)?;
            write_atomic(&self.dir.path(&bundle_path(index, width)), &bytes)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::directory_of;

    #[test]
    fn a_bare_file_name_is_in_the_current_directory() {
        // Found end to end: `--witness-state witness.state` saved the state, then failed to
        // flush the empty-path directory, and every cosignature was withheld.
        assert_eq!(directory_of(Path::new("witness.state")), Path::new("."));
        assert_eq!(directory_of(Path::new("a/b")), Path::new("a"));
        assert_eq!(directory_of(Path::new("/b")), Path::new("/"));
    }
}
