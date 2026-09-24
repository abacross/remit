//! Remit on AWS (SPEC section 8, ADR 0006).
//!
//! [`compile_session_policy`] turns a warrant into the inline session policy the broker
//! passes to `AssumeRole`. It copies every pattern verbatim, adds only a condition that
//! narrows the policy to the warrant's window, and refuses anything it cannot express
//! exactly, so the compiled policy never allows a request the warrant does not permit
//! (SPEC section 8.3). The property tests in `tests/compile_soundness.rs` check it.

#![forbid(unsafe_code)]

use core::fmt;

use remit_core::{ActionPattern, ResourcePattern, Warrant};

/// The most plaintext characters AWS accepts for session policies (STS `AssumeRole`).
pub const MAX_POLICY_CHARS: usize = 2048;

/// Why a warrant cannot be compiled. Each is a refusal, never an approximation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// A pattern containing `${`, which AWS would substitute as a policy variable.
    PolicyVariable(String),
    /// An action pattern that is not `*` or `service:name` with a plain service prefix.
    ActionShape(String),
    /// A resource pattern that is not `*` or an ARN of at least six segments with no
    /// wildcard in its service segment.
    ResourceShape(String),
    /// The compiled policy is longer than AWS accepts.
    TooLong(usize),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyVariable(p) => write!(f, "{p:?} contains ${{, which AWS substitutes"),
            Self::ActionShape(p) => write!(f, "{p:?} is not `*` or `service:name`"),
            Self::ResourceShape(p) => {
                write!(f, "{p:?} is not `*` or an ARN with a plain service segment")
            }
            Self::TooLong(n) => write!(f, "{n} characters, over AWS's limit of {MAX_POLICY_CHARS}"),
        }
    }
}

impl std::error::Error for CompileError {}

fn has_wildcard(s: &str) -> bool {
    s.contains(['*', '?'])
}

fn check_action(p: &str) -> Result<(), CompileError> {
    if p.contains("${") {
        return Err(CompileError::PolicyVariable(p.to_owned()));
    }
    if p == "*" {
        return Ok(());
    }
    match p.split_once(':') {
        Some((service, name))
            if !service.is_empty()
                && !name.is_empty()
                && !has_wildcard(service)
                && service
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-') =>
        {
            Ok(())
        }
        _ => Err(CompileError::ActionShape(p.to_owned())),
    }
}

fn check_resource(p: &str) -> Result<(), CompileError> {
    if p.contains("${") {
        return Err(CompileError::PolicyVariable(p.to_owned()));
    }
    if p == "*" {
        return Ok(());
    }
    // arn:partition:service:region:account:resource
    let segments: Vec<&str> = p.splitn(6, ':').collect();
    let ok = segments.len() == 6
        && segments.first() == Some(&"arn")
        && segments
            .get(2)
            .is_some_and(|s| !s.is_empty() && !has_wildcard(s));
    if ok {
        Ok(())
    } else {
        Err(CompileError::ResourceShape(p.to_owned()))
    }
}

/// A JSON string literal. Patterns are printable ASCII (SPEC section 3.3), so only the
/// quote and the backslash need escaping.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
}

fn json_list<'a>(out: &mut String, items: impl Iterator<Item = &'a str>) {
    out.push('[');
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_str(out, item);
    }
    out.push(']');
}

/// Compiles a warrant to its session policy (SPEC section 8.2).
///
/// # Errors
///
/// A pattern AWS would read differently from Remit, or a result over 2,048 characters.
pub fn compile_session_policy(warrant: &Warrant) -> Result<String, CompileError> {
    for grant in warrant.grants() {
        grant
            .actions()
            .iter()
            .try_for_each(|p| check_action(p.as_str()))?;
        grant
            .resources()
            .iter()
            .try_for_each(|p| check_resource(p.as_str()))?;
    }
    let window = format!(
        "\"Condition\":{{\"DateGreaterThanEquals\":{{\"aws:CurrentTime\":\"{}\"}},\"DateLessThanEquals\":{{\"aws:CurrentTime\":\"{}\"}}}}",
        iso8601(warrant.not_before()),
        iso8601(warrant.not_after()),
    );
    let mut out = String::from("{\"Version\":\"2012-10-17\",\"Statement\":[");
    for (i, grant) in warrant.grants().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"Effect\":\"Allow\",\"Action\":");
        json_list(&mut out, grant.actions().iter().map(ActionPattern::as_str));
        out.push_str(",\"Resource\":");
        json_list(
            &mut out,
            grant.resources().iter().map(ResourcePattern::as_str),
        );
        out.push(',');
        out.push_str(&window);
        out.push('}');
    }
    out.push_str("]}");
    if out.len() > MAX_POLICY_CHARS {
        return Err(CompileError::TooLong(out.len()));
    }
    Ok(out)
}

/// UTC seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`, by Howard Hinnant's
/// days-to-civil algorithm. Exact for every `u64` second up to year 9999; later values are
/// clamped to 9999-12-31T23:59:59Z, which a warrant's window never reaches in practice and
/// which only ever shortens the window it expresses.
///
/// Arithmetic is allowed here, and only here, on a bound: `seconds` is clamped to year
/// 9999, so `days` is below 2,932,897 and every intermediate below is under 2^32, far from
/// overflow in `i64`. Checked against day-by-day counting up to 2200 and against Python at
/// 1970, 2000-02-29 and 9999 (`tests/compile_soundness.rs`).
#[must_use]
#[allow(clippy::arithmetic_side_effects)]
pub fn iso8601(seconds: u64) -> String {
    const MAX: u64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    let s = seconds.min(MAX);
    let days = i64::try_from(s / 86_400).unwrap_or(0);
    let rem = s % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ` (the form [`iso8601`] writes and `CloudTrail` records) to
/// UTC seconds since the Unix epoch, by Howard Hinnant's days-from-civil algorithm.
/// Anything else, including fractional seconds or an offset other than `Z`, is `None`.
///
/// Arithmetic is allowed on the same bound as [`iso8601`]: years 1970 to 9999, so every
/// intermediate is far below `i64` overflow; round-trip tested against it.
#[must_use]
#[allow(clippy::arithmetic_side_effects)]
pub fn parse_iso8601(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    let shape_ok = b.len() == 20
        && b.get(4) == Some(&b'-')
        && b.get(7) == Some(&b'-')
        && b.get(10) == Some(&b'T')
        && b.get(13) == Some(&b':')
        && b.get(16) == Some(&b':')
        && b.get(19) == Some(&b'Z');
    if !shape_ok {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let s = text.get(from..to)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if year < 1970
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hh > 23
        || mm > 59
        || ss > 59
    {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss;
    let secs = u64::try_from(secs).ok()?;
    // Reject dates that do not exist (2026-02-30 would otherwise roll into March).
    (iso8601(secs) == text).then_some(secs)
}
