//! Patterns over action and resource names (SPEC section 3.3).
//!
//! A pattern is printable ASCII in which `*` matches any sequence and `?` matches one
//! character. Two operations matter: matching a concrete name, which must be exact, and
//! deciding whether one pattern contains another, which delegation relies on and which
//! must be *sound*: it may say "not contained" for patterns that are, but it must never
//! say "contained" for patterns that are not (SPEC section 4). The property tests in
//! `tests/pattern_soundness.rs` check both against brute force.

use core::fmt;

/// The longest pattern or name accepted, in bytes. AWS ARNs are at most 2,048 characters.
pub const MAX_LEN: usize = 2048;

const STAR: u8 = b'*';
const ONE: u8 = b'?';

/// Why a pattern or a name was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// Empty text.
    Empty,
    /// Longer than [`MAX_LEN`].
    TooLong(usize),
    /// A byte outside printable ASCII (0x21 to 0x7E), at the given offset.
    InvalidByte {
        /// Offset of the byte.
        at: usize,
        /// The byte.
        byte: u8,
    },
    /// A wildcard in a concrete name, where it is not allowed (SPEC section 3.3).
    WildcardInName(usize),
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty"),
            Self::TooLong(n) => write!(f, "{n} bytes, over the limit of {MAX_LEN}"),
            Self::InvalidByte { at, byte } => {
                write!(f, "byte 0x{byte:02x} at offset {at} is not printable ASCII")
            }
            Self::WildcardInName(at) => write!(f, "wildcard at offset {at} in a concrete name"),
        }
    }
}

impl std::error::Error for PatternError {}

fn validate(text: &str, wildcards_allowed: bool) -> Result<(), PatternError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(PatternError::Empty);
    }
    if bytes.len() > MAX_LEN {
        return Err(PatternError::TooLong(bytes.len()));
    }
    for (at, &byte) in bytes.iter().enumerate() {
        if !(0x21..=0x7e).contains(&byte) {
            return Err(PatternError::InvalidByte { at, byte });
        }
        if !wildcards_allowed && (byte == STAR || byte == ONE) {
            return Err(PatternError::WildcardInName(at));
        }
    }
    Ok(())
}

/// Case rule for a kind of name: AWS action names ignore case, resource names do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    Insensitive,
    Sensitive,
}

impl Case {
    fn fold(self, b: u8) -> u8 {
        match self {
            Self::Insensitive => b.to_ascii_lowercase(),
            Self::Sensitive => b,
        }
    }
}

/// Does `pattern` match the whole of `name`? Iterative, linear in the common case,
/// quadratic at worst, never recursive.
fn glob_matches(pattern: &[u8], name: &[u8], case: Case) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    // The position just after the last star seen in the pattern, and the name position
    // it was tried against, for backtracking.
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        match (pattern.get(p).copied(), name.get(n).copied()) {
            (Some(STAR), _) => {
                p = p.saturating_add(1);
                star = Some((p, n));
            }
            (Some(ONE), Some(_)) => {
                p = p.saturating_add(1);
                n = n.saturating_add(1);
            }
            (Some(pc), Some(nc)) if case.fold(pc) == case.fold(nc) => {
                p = p.saturating_add(1);
                n = n.saturating_add(1);
            }
            _ => match star {
                // Let the last star swallow one more character and retry from there.
                Some((sp, sn)) => {
                    let next = sn.saturating_add(1);
                    star = Some((sp, next));
                    p = sp;
                    n = next;
                }
                None => return false,
            },
        }
    }
    // The name is used up; only stars may remain in the pattern.
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|&b| b == STAR))
}

/// Is every name matched by `inner` also matched by `outer`? Sound, conservative.
///
/// `cover[i][j]` answers: does `outer[i..]` cover `inner[j..]`? Each rule only lets an
/// outer token account for inner tokens whose every expansion it matches:
///
/// * an outer `*` absorbs nothing, or one inner token of any kind (a literal, a `?`, or
///   an inner `*`, whose arbitrary expansion the outer star also matches);
/// * an outer `?` accounts for exactly one character: an inner literal or `?`, never an
///   inner `*`, which could expand to zero or several characters;
/// * an outer literal accounts only for the same inner literal.
///
/// Every step is sound, so the answer is; it is incomplete for some equivalent forms
/// (for example `?*` against `*?`), which only ever refuses a delegation.
fn glob_contains(outer: &[u8], inner: &[u8], case: Case) -> bool {
    let (o_len, i_len) = (outer.len(), inner.len());
    let width = i_len.saturating_add(1);
    // Rows are outer positions, filled from the end; index = i * width + j.
    let mut cover = vec![false; o_len.saturating_add(1).saturating_mul(width)];
    let at = |i: usize, j: usize| i.saturating_mul(width).saturating_add(j);
    if let Some(cell) = cover.get_mut(at(o_len, i_len)) {
        *cell = true;
    }
    for i in (0..o_len).rev() {
        for j in (0..=i_len).rev() {
            let o = outer.get(i).copied();
            let n = inner.get(j).copied();
            let next_i = i.saturating_add(1);
            let next_j = j.saturating_add(1);
            let get = |ii: usize, jj: usize| cover.get(at(ii, jj)).copied().unwrap_or(false);
            let value = match (o, n) {
                (Some(STAR), _) => get(next_i, j) || (n.is_some() && get(i, next_j)),
                // Outer needs a character the inner has run out of, or outer is exhausted
                // before inner (a row past the end is never read, but the match is total).
                (Some(_), None) | (None, _) => false,
                (Some(ONE), Some(nb)) => nb != STAR && get(next_i, next_j),
                (Some(ob), Some(nb)) => {
                    nb != STAR && nb != ONE && case.fold(ob) == case.fold(nb) && get(next_i, next_j)
                }
            };
            if let Some(cell) = cover.get_mut(at(i, j)) {
                *cell = value;
            }
        }
    }
    cover.get(at(0, 0)).copied().unwrap_or(false)
}

macro_rules! pattern_type {
    ($(#[$doc:meta])* $name:ident, $case:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parses a pattern, refusing anything outside SPEC section 3.3 rather than
            /// normalizing it.
            ///
            /// # Errors
            ///
            /// Empty, too long, or containing a byte outside printable ASCII.
            pub fn new(text: &str) -> Result<Self, PatternError> {
                validate(text, true)?;
                Ok(Self(text.to_owned()))
            }

            /// The pattern as written.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Does this pattern match the concrete name?
            #[must_use]
            pub fn matches(&self, name: &str) -> bool {
                glob_matches(self.0.as_bytes(), name.as_bytes(), $case)
            }

            /// Is every name `inner` matches also matched by `self`? Sound: a `true` is
            /// always right; a `false` may be conservative (SPEC section 4).
            #[must_use]
            pub fn contains(&self, inner: &Self) -> bool {
                glob_contains(self.0.as_bytes(), inner.0.as_bytes(), $case)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

pattern_type!(
    /// A pattern over action names, matched without regard to case, as AWS matches them.
    ActionPattern,
    Case::Insensitive
);
pattern_type!(
    /// A pattern over resource names, matched with regard to case.
    ResourcePattern,
    Case::Sensitive
);

/// Checks that a concrete action or resource name is acceptable in a request: printable
/// ASCII, no wildcards (SPEC section 3.3).
///
/// # Errors
///
/// Empty, too long, a byte outside printable ASCII, or a wildcard.
pub fn validate_name(name: &str) -> Result<(), PatternError> {
    validate(name, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> ActionPattern {
        ActionPattern::new(s).unwrap_or_else(|e| unreachable!("{s}: {e}"))
    }
    fn r(s: &str) -> ResourcePattern {
        ResourcePattern::new(s).unwrap_or_else(|e| unreachable!("{s}: {e}"))
    }

    #[test]
    fn actions_ignore_case_resources_do_not() {
        assert!(a("s3:GetObject").matches("S3:getobject"));
        assert!(!r("arn:aws:s3:::Reports/*").matches("arn:aws:s3:::reports/x"));
    }

    #[test]
    fn star_crosses_colons_and_slashes() {
        // Deliberately broader than AWS (SPEC section 3.3).
        assert!(r("arn:*").matches("arn:aws:s3:::b/k/v"));
        assert!(r("arn:aws:s3:::b/*/test/*").matches("arn:aws:s3:::b/1/2/test/3/o.jpg"));
        assert!(!r("arn:aws:s3:::b/*/test/*").matches("arn:aws:s3:::b/test/o.jpg"));
    }

    #[test]
    fn containment_basics() {
        assert!(r("*").contains(&r("arn:aws:s3:::b/*")));
        assert!(r("arn:aws:s3:::b/*").contains(&r("arn:aws:s3:::b/k?/*")));
        assert!(!r("arn:aws:s3:::b/k?/*").contains(&r("arn:aws:s3:::b/*")));
        assert!(!r("a?").contains(&r("a*")));
        assert!(a("s3:*").contains(&a("S3:Get*")));
    }

    #[test]
    fn refuses_rather_than_normalizes() {
        assert_eq!(ActionPattern::new(""), Err(PatternError::Empty));
        assert!(matches!(
            ActionPattern::new("s3: Get"),
            Err(PatternError::InvalidByte { byte: b' ', .. })
        ));
        assert_eq!(validate_name("arn:*"), Err(PatternError::WildcardInName(4)));
        assert!(ResourcePattern::new(&"x".repeat(MAX_LEN + 1)).is_err());
    }
}
