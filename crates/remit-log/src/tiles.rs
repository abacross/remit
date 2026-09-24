//! The tiled layout of c2sp.org/tlog-tiles: paths, entry bundles, appending, and proofs
//! computed from tiles.
//!
//! A tile at tile level `T` and index `N` holds up to 256 hashes of complete subtrees of
//! height `8T`, left to right: at level 0 the leaf hashes, above that the roots of full
//! tiles below. Everything here reads tiles through a [`TileSource`] and never assumes it
//! holds the whole tree, so a proof costs a few tile reads however large the log grows.
//! The proofs are the RFC 9162 definitions computed over ranges instead of lists, and are
//! tested equal to [`crate::merkle`]'s, which follows the RFC literally.

use core::fmt;

use crate::merkle::{Hash, empty_root, node_hash, root};

/// Hashes in a full tile.
pub const TILE_WIDTH: u64 = 256;

/// The tree height a tile level spans.
const TILE_HEIGHT: u32 = 8;

/// Why tiles could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TileError {
    /// A tile or bundle the size says must exist is missing.
    Missing(String),
    /// A tile or bundle does not have the contents its path requires.
    Corrupt(String),
    /// A request outside the tree.
    OutOfRange,
}

impl fmt::Display for TileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(path) => write!(f, "missing {path}"),
            Self::Corrupt(path) => write!(f, "corrupt {path}"),
            Self::OutOfRange => f.write_str("outside the tree"),
        }
    }
}

impl std::error::Error for TileError {}

/// The `<N>` path element: 3-digit groups, all but the last prefixed with `x`.
fn index_path(index: u64) -> String {
    let digits = index.to_string();
    let pad = 3_usize.saturating_sub(digits.len() % 3) % 3;
    let padded = format!("{}{digits}", "0".repeat(pad));
    let groups: Vec<&str> = padded
        .as_bytes()
        .chunks(3)
        .map(|g| core::str::from_utf8(g).unwrap_or("000"))
        .collect();
    let last = groups.len().saturating_sub(1);
    groups
        .iter()
        .enumerate()
        .map(|(i, g)| {
            if i == last {
                (*g).to_owned()
            } else {
                format!("x{g}")
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn with_width(path: String, width: u64) -> String {
    if width == TILE_WIDTH {
        path
    } else {
        format!("{path}.p/{width}")
    }
}

/// The path of the hash tile at tile level `level`, index `index`, holding `width` hashes
/// (256 for a full tile).
#[must_use]
pub fn tile_path(level: u8, index: u64, width: u64) -> String {
    with_width(format!("tile/{level}/{}", index_path(index)), width)
}

/// The path of the entry bundle `index` holding `width` entries.
#[must_use]
pub fn bundle_path(index: u64, width: u64) -> String {
    with_width(format!("tile/entries/{}", index_path(index)), width)
}

/// Encodes entries as a bundle: each prefixed by its length as a big-endian `u16`.
///
/// # Errors
///
/// An entry longer than 65,535 bytes.
pub fn encode_bundle(entries: &[Vec<u8>]) -> Result<Vec<u8>, TileError> {
    let mut out = Vec::new();
    for e in entries {
        let len = u16::try_from(e.len()).map_err(|_| TileError::OutOfRange)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(e);
    }
    Ok(out)
}

/// Decodes a bundle into its entries.
///
/// # Errors
///
/// A length that runs past the end.
pub fn decode_bundle(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, TileError> {
    let corrupt = || TileError::Corrupt("entry bundle".into());
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (len, rest) = bytes.split_first_chunk::<2>().ok_or_else(corrupt)?;
        let len = usize::from(u16::from_be_bytes(*len));
        let (entry, rest) = rest.split_at_checked(len).ok_or_else(corrupt)?;
        out.push(entry.to_vec());
        bytes = rest;
    }
    Ok(out)
}

/// Where tiles come from: a directory, a bucket, memory.
pub trait TileSource {
    /// The hash tile at `level`, `index`, with exactly `width` hashes.
    ///
    /// # Errors
    ///
    /// [`TileError::Missing`] or [`TileError::Corrupt`].
    fn read_tile(&self, level: u8, index: u64, width: u64) -> Result<Vec<Hash>, TileError>;
}

/// How many hashes exist at tile level `level` in a tree of `size` leaves.
fn hashes_at(level: u8, size: u64) -> u64 {
    size.checked_shr(TILE_HEIGHT.saturating_mul(u32::from(level)))
        .unwrap_or(0)
}

/// The width of tile `index` at `level` in a tree of `size` leaves.
fn width_of(level: u8, index: u64, size: u64) -> u64 {
    hashes_at(level, size)
        .saturating_sub(index.saturating_mul(TILE_WIDTH))
        .min(TILE_WIDTH)
}

/// A tree of `size` leaves, read through its tiles.
#[derive(Debug)]
pub struct Tiles<'a, S: TileSource> {
    source: &'a S,
    size: u64,
}

impl<'a, S: TileSource> Tiles<'a, S> {
    /// The tree of `size` leaves in `source`.
    pub fn new(source: &'a S, size: u64) -> Self {
        Self { source, size }
    }

    /// The hash of the complete subtree of `height` whose leftmost leaf is
    /// `index << height`.
    ///
    /// # Errors
    ///
    /// A subtree not complete in this tree, or a tile that cannot be read.
    pub fn subtree(&self, height: u32, index: u64) -> Result<Hash, TileError> {
        let end = index
            .checked_add(1)
            .and_then(|i| i.checked_shl(height))
            .ok_or(TileError::OutOfRange)?;
        if end > self.size || height >= 64 {
            return Err(TileError::OutOfRange);
        }
        let level = u8::try_from(height / TILE_HEIGHT).map_err(|_| TileError::OutOfRange)?;
        let within = height % TILE_HEIGHT;
        // The subtree covers 2^within consecutive hashes at this tile level, in one tile.
        let first = index << within;
        let tile = first / TILE_WIDTH;
        let offset = usize::try_from(first % TILE_WIDTH).map_err(|_| TileError::OutOfRange)?;
        let count = 1usize << within;
        let width = width_of(level, tile, self.size);
        let hashes = self.source.read_tile(level, tile, width)?;
        let covered = hashes
            .get(offset..offset.saturating_add(count))
            .ok_or_else(|| TileError::Corrupt(tile_path(level, tile, width)))?;
        Ok(root(covered))
    }

    /// The Merkle Tree Hash of leaves `start..end` (RFC 9162 `MTH(D[start:end])`) for the
    /// ranges its recursion produces, whose power-of-two parts are always aligned.
    ///
    /// # Errors
    ///
    /// A range outside the tree, or a tile that cannot be read.
    pub fn range_root(&self, start: u64, end: u64) -> Result<Hash, TileError> {
        if start > end || end > self.size {
            return Err(TileError::OutOfRange);
        }
        let n = end.saturating_sub(start);
        if n == 0 {
            return Ok(empty_root());
        }
        if n.is_power_of_two() && start.is_multiple_of(n) {
            let height = n.trailing_zeros();
            return self.subtree(height, start >> height);
        }
        let k = split(n);
        let mid = start.saturating_add(k);
        Ok(node_hash(
            &self.range_root(start, mid)?,
            &self.range_root(mid, end)?,
        ))
    }

    /// The root of the whole tree.
    ///
    /// # Errors
    ///
    /// A tile that cannot be read.
    pub fn root(&self) -> Result<Hash, TileError> {
        self.range_root(0, self.size)
    }

    /// The inclusion proof for leaf `index` (RFC 9162 section 2.1.3.1).
    ///
    /// # Errors
    ///
    /// An index outside the tree, or a tile that cannot be read.
    pub fn inclusion_proof(&self, index: u64) -> Result<Vec<Hash>, TileError> {
        if index >= self.size {
            return Err(TileError::OutOfRange);
        }
        let mut proof = Vec::new();
        let (mut start, mut end) = (0, self.size);
        // Walk down, then reverse: the RFC lists the deepest sibling first.
        while end.saturating_sub(start) > 1 {
            let mid = start.saturating_add(split(end.saturating_sub(start)));
            if index < mid {
                proof.push(self.range_root(mid, end)?);
                end = mid;
            } else {
                proof.push(self.range_root(start, mid)?);
                start = mid;
            }
        }
        proof.reverse();
        Ok(proof)
    }

    /// The consistency proof from the first `old` leaves to the whole tree (RFC 9162
    /// section 2.1.4.1); empty when `old` is zero or the whole tree.
    ///
    /// # Errors
    ///
    /// `old` larger than the tree, or a tile that cannot be read.
    pub fn consistency_proof(&self, old: u64) -> Result<Vec<Hash>, TileError> {
        if old > self.size {
            return Err(TileError::OutOfRange);
        }
        let mut proof = Vec::new();
        if old == 0 || old == self.size {
            return Ok(proof);
        }
        let (mut start, mut end, mut m, mut known) = (0, self.size, old, true);
        loop {
            let n = end.saturating_sub(start);
            if m == n {
                if !known {
                    proof.push(self.range_root(start, end)?);
                }
                break;
            }
            let k = split(n);
            let mid = start.saturating_add(k);
            if m <= k {
                proof.push(self.range_root(mid, end)?);
                end = mid;
            } else {
                proof.push(self.range_root(start, mid)?);
                start = mid;
                m = m.saturating_sub(k);
                known = false;
            }
        }
        proof.reverse();
        Ok(proof)
    }
}

/// The largest power of two smaller than `n`, for `n >= 2`.
fn split(n: u64) -> u64 {
    1_u64 << (63_u32.saturating_sub(n.saturating_sub(1).leading_zeros()))
}

/// A tile to write: complete when it holds 256 hashes, partial otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TileWrite {
    /// Tile level.
    pub level: u8,
    /// Index within the level.
    pub index: u64,
    /// Its hashes.
    pub hashes: Vec<Hash>,
}

impl TileWrite {
    /// Its path.
    #[must_use]
    pub fn path(&self) -> String {
        tile_path(
            self.level,
            self.index,
            u64::try_from(self.hashes.len()).unwrap_or(0),
        )
    }

    /// Its bytes: the hashes, concatenated.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.hashes.concat()
    }
}

/// The tiles to write to grow a tree of `size` leaves by `leaves`: at every level that
/// gains hashes, the rightmost tile rewritten with them (as a new partial or a full tile)
/// and any tiles after it. Existing full tiles are never rewritten.
///
/// # Errors
///
/// A tile that cannot be read.
pub fn append<S: TileSource>(
    source: &S,
    size: u64,
    leaves: &[Hash],
) -> Result<Vec<TileWrite>, TileError> {
    let mut writes = Vec::new();
    let mut level: u8 = 0;
    let mut incoming = leaves.to_vec();
    while !incoming.is_empty() {
        let existing = hashes_at(level, size);
        let first_tile = existing / TILE_WIDTH;
        let kept = existing % TILE_WIDTH;
        let mut hashes = if kept > 0 {
            source.read_tile(level, first_tile, kept)?
        } else {
            Vec::new()
        };
        hashes.append(&mut incoming);
        let mut above = Vec::new();
        for (i, chunk) in hashes.chunks(256).enumerate() {
            let index = first_tile.saturating_add(u64::try_from(i).unwrap_or(u64::MAX));
            if chunk.len() == 256 {
                above.push(root(chunk));
            }
            writes.push(TileWrite {
                level,
                index,
                hashes: chunk.to_vec(),
            });
        }
        incoming = above;
        level = level.checked_add(1).ok_or(TileError::OutOfRange)?;
    }
    Ok(writes)
}
