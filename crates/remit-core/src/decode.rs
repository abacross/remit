//! The strict decoder (SPEC section 5.4): exactly the byte strings section 3.6 produces for
//! some valid warrant, and nothing else.
//!
//! Every length is checked against what remains before anything is allocated, every count
//! against the limits before any loop, and the result is re-encoded and compared with the
//! input, so a decoder that accepted two spellings of one warrant would fail here rather
//! than let two different byte strings carry one signature's meaning.

use core::fmt;

use crate::encoding::MAGIC;
use crate::warrant::{
    MAX_GRANTS, MAX_IDENTIFIER, MAX_PATTERNS, MAX_PURPOSE, VERSION, Warrant, WarrantError,
    WarrantId, WarrantSpec,
};

/// Why bytes were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The first eight bytes are not `REMITWv1`.
    Magic,
    /// A version this crate does not implement.
    Version(u16),
    /// The input ended inside a field; the name says which.
    Truncated(&'static str),
    /// A length or count over its limit, before anything was read.
    TooLong(&'static str, u64),
    /// A string that is not UTF-8.
    Utf8(&'static str),
    /// A `parent` flag other than 0 or 1.
    ParentFlag(u8),
    /// Bytes left over after a complete warrant.
    Trailing(usize),
    /// A warrant the encoding describes but section 3 forbids.
    Invalid(WarrantError),
    /// Decoded, but re-encoding gives different bytes: never expected, checked anyway.
    NotCanonical,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Magic => f.write_str("not a version 1 warrant encoding"),
            Self::Version(v) => write!(f, "unsupported version {v}"),
            Self::Truncated(what) => write!(f, "input ends inside {what}"),
            Self::TooLong(what, n) => write!(f, "{what} of {n} is over the limit"),
            Self::Utf8(what) => write!(f, "{what} is not UTF-8"),
            Self::ParentFlag(b) => write!(f, "parent flag {b} is neither 0 nor 1"),
            Self::Trailing(n) => write!(f, "{n} bytes after the end of the warrant"),
            Self::Invalid(e) => write!(f, "invalid warrant: {e}"),
            Self::NotCanonical => f.write_str("does not re-encode to the same bytes"),
        }
    }
}

impl std::error::Error for DecodeError {}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < n {
            return Err(DecodeError::Truncated(what));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], DecodeError> {
        let bytes = self.take(N, what)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array(what)?))
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array(what)?))
    }

    /// A 4-byte length or count, refused if over `limit` before it is used.
    fn len(&mut self, what: &'static str, limit: usize) -> Result<usize, DecodeError> {
        let n = u32::from_be_bytes(self.array(what)?);
        let n = usize::try_from(n).map_err(|_| DecodeError::TooLong(what, u64::from(n)))?;
        if n > limit {
            return Err(DecodeError::TooLong(what, n as u64));
        }
        Ok(n)
    }

    fn string(&mut self, what: &'static str, limit: usize) -> Result<&'a str, DecodeError> {
        let n = self.len(what, limit)?;
        let bytes = self.take(n, what)?;
        core::str::from_utf8(bytes).map_err(|_| DecodeError::Utf8(what))
    }
}

impl Warrant {
    /// Decodes a canonical encoding (SPEC sections 3.6 and 5.4), accepting nothing else.
    ///
    /// # Errors
    ///
    /// Any deviation from section 3.6, any content section 3 forbids, or trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader { rest: bytes };
        if r.take(MAGIC.len(), "magic")? != MAGIC {
            return Err(DecodeError::Magic);
        }
        let version = r.u16("version")?;
        if version != VERSION {
            return Err(DecodeError::Version(version));
        }
        let issuer = r.string("issuer", MAX_IDENTIFIER)?;
        let subject = r.string("subject", MAX_IDENTIFIER)?;
        let purpose = r.string("purpose", MAX_PURPOSE)?;
        let not_before = r.u64("not_before")?;
        let not_after = r.u64("not_after")?;
        let grant_count = r.len("grant count", MAX_GRANTS)?;
        let mut grants: Vec<(Vec<&str>, Vec<&str>)> = Vec::with_capacity(grant_count);
        for _ in 0..grant_count {
            let actions = read_patterns(&mut r, "action")?;
            let resources = read_patterns(&mut r, "resource")?;
            grants.push((actions, resources));
        }
        let parent = match r.take(1, "parent flag")? {
            [0] => None,
            [1] => {
                let text = r.string("parent", 64)?;
                Some(WarrantId::parse(text).map_err(DecodeError::Invalid)?)
            }
            [other] => return Err(DecodeError::ParentFlag(*other)),
            [] | [_, _, ..] => return Err(DecodeError::Truncated("parent flag")),
        };
        let max_depth = r.u64("max_depth")?;
        if !r.rest.is_empty() {
            return Err(DecodeError::Trailing(r.rest.len()));
        }
        let refs: Vec<(&[&str], &[&str])> = grants
            .iter()
            .map(|(a, rs)| (a.as_slice(), rs.as_slice()))
            .collect();
        let warrant = Warrant::new(&WarrantSpec {
            issuer,
            subject,
            purpose,
            not_before,
            not_after,
            grants: &refs,
            parent,
            max_depth,
        })
        .map_err(DecodeError::Invalid)?;
        if warrant.canonical_bytes() != bytes {
            return Err(DecodeError::NotCanonical);
        }
        Ok(warrant)
    }
}

fn read_patterns<'a>(r: &mut Reader<'a>, what: &'static str) -> Result<Vec<&'a str>, DecodeError> {
    let n = r.len(what, MAX_PATTERNS)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.string(what, crate::pattern::MAX_LEN)?);
    }
    Ok(out)
}
