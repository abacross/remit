//! Standard base64 (RFC 4648 section 4), with padding, decoded strictly.
//!
//! Signed notes and checkpoints carry signatures and hashes in this encoding. Decoding
//! accepts exactly one spelling for each byte string: padding is required, and the bits
//! the final character leaves unused must be zero. Otherwise one signature could be
//! written several ways, and a note could change without its signature changing.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c.checked_sub(b'A')?,
        b'a'..=b'z' => c.checked_sub(b'a')?.checked_add(26)?,
        b'0'..=b'9' => c.checked_sub(b'0')?.checked_add(52)?,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

fn symbol(bits: u32) -> char {
    ALPHABET
        .get(usize::try_from(bits & 0x3f).unwrap_or(0))
        .map_or('A', |&c| char::from(c))
}

/// Encodes bytes.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(symbol(n >> 18));
        out.push(symbol(n >> 12));
        out.push(if chunk.len() > 1 { symbol(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { symbol(n) } else { '=' });
    }
    out
}

/// Decodes the one canonical encoding of a byte string, or returns `None`.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(3) / 4);
    let groups = bytes.len() / 4;
    for (g, quad) in bytes.chunks(4).enumerate() {
        let last = g.checked_add(1) == Some(groups);
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            let v = if i >= 4usize.saturating_sub(pad) {
                0
            } else {
                value(c)?
            };
            n = (n << 6) | v;
        }
        let [_, b0, b1, b2] = n.to_be_bytes();
        match pad {
            0 => out.extend_from_slice(&[b0, b1, b2]),
            // The unused low bits of the last character must be zero: one spelling only.
            1 if b2 == 0 => out.extend_from_slice(&[b0, b1]),
            2 if b1 == 0 && b2 == 0 => out.push(b0),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn rfc_4648_test_vectors() {
        // RFC 4648 section 10.
        for (plain, coded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded).as_deref(), Some(plain.as_bytes()));
        }
    }

    #[test]
    fn only_the_canonical_spelling_decodes() {
        for bad in [
            "Zg",
            "Zg=",
            "Zh==",
            "Zm9=",
            "Zg==Zg==",
            "Z===",
            "====",
            "Zm9v\n",
            " Zm9v",
            "Zm-v",
            "Zm_v",
            "Zm9vYg==\0",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn every_byte_string_round_trips() {
        for len in 0..=40usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i.wrapping_mul(97) % 256).unwrap_or(0))
                .collect();
            assert_eq!(decode(&encode(&bytes)), Some(bytes));
        }
    }
}
