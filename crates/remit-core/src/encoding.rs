//! Canonical encoding and content-derived identity (SPEC sections 3.5 and 3.6).
//!
//! The encoding is what a signature will cover, so it has exactly one form per warrant:
//! fixed field order, fixed-width big-endian integers, length-prefixed strings, and no
//! sorting or deduplication on the author's behalf.

use sha2::{Digest, Sha256};

use crate::warrant::{VERSION, Warrant, WarrantId};

/// The first bytes of every version 1 encoding.
pub const MAGIC: &[u8; 8] = b"REMITWv1";

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_len(out: &mut Vec<u8>, n: usize) {
    // Every length is bounded far below u32::MAX by the limits in `warrant`, so the
    // conversion cannot fail for a valid warrant; saturating keeps it total regardless.
    let n = u32::try_from(n).unwrap_or(u32::MAX);
    out.extend_from_slice(&n.to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_len(out, s.len());
    out.extend_from_slice(s.as_bytes());
}

impl Warrant {
    /// The canonical encoding (SPEC section 3.6).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(MAGIC);
        put_u16(&mut out, VERSION);
        put_str(&mut out, self.issuer.as_str());
        put_str(&mut out, self.subject.as_str());
        put_str(&mut out, &self.purpose);
        put_u64(&mut out, self.not_before);
        put_u64(&mut out, self.not_after);
        put_len(&mut out, self.grants.len());
        for grant in &self.grants {
            put_len(&mut out, grant.actions().len());
            for p in grant.actions() {
                put_str(&mut out, p.as_str());
            }
            put_len(&mut out, grant.resources().len());
            for p in grant.resources() {
                put_str(&mut out, p.as_str());
            }
        }
        match &self.parent {
            None => out.push(0),
            Some(id) => {
                out.push(1);
                put_str(&mut out, id.as_str());
            }
        }
        put_u64(&mut out, self.max_depth);
        out
    }

    /// The warrant's identifier (SPEC section 3.5): `rw1-` and the first 20 bytes of the
    /// SHA-256 of the canonical encoding, in lowercase unpadded base32.
    #[must_use]
    pub fn id(&self) -> WarrantId {
        let digest = Sha256::digest(self.canonical_bytes());
        let head = digest.get(..20).unwrap_or(&digest[..]);
        WarrantId::from_trusted(format!("rw1-{}", base32_lower(head)))
    }
}

/// RFC 4648 base32, lowercase, without padding.
#[must_use]
pub fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(data.len().saturating_mul(8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            let index = (buffer >> bits) & 0x1f;
            out.push(char::from(
                ALPHABET.get(index as usize).copied().unwrap_or(b'a'),
            ));
        }
        buffer &= (1u32 << bits).saturating_sub(1);
    }
    if bits > 0 {
        let index = (buffer << 5u32.saturating_sub(bits)) & 0x1f;
        out.push(char::from(
            ALPHABET.get(index as usize).copied().unwrap_or(b'a'),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_test_vectors() {
        // RFC 4648 section 10, lowercased and with padding removed.
        let vectors = [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ];
        for (input, expected) in vectors {
            assert_eq!(base32_lower(input.as_bytes()), expected, "{input:?}");
        }
    }
}
