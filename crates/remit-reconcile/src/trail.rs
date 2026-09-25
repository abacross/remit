//! Validated trail log files (SPEC section 6.7): the evidence that lets a run say
//! `complete` rather than `complete, unvalidated`.
//!
//! With log file integrity validation on, CloudTrail delivers a digest file every hour in
//! every region, even an hour with no activity, listing the SHA-256 of each log file
//! delivered in that hour and chained to the previous digest by its path, hash and RSA
//! signature (AWS, CloudTrail user guide, "Custom implementations of CloudTrail log file
//! integrity validation" and "CloudTrail digest file structure"). A chain that verifies,
//! with no gap between consecutive digests, across the whole window, is positive evidence
//! that the record is complete and unaltered; anything less is a named problem.
//!
//! Pure: the caller fetches the files (and decompresses them) and the public keys.

use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;

use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use remit_aws::parse_iso8601;

/// A CloudTrail public key, as `ListPublicKeys` returns it.
#[derive(Debug, Clone)]
pub struct TrailKey {
    /// Its fingerprint, which digest files name.
    pub fingerprint: String,
    /// The DER encoding AWS returns: an `RSAPublicKey` (PKCS #1), or the same wrapped in a
    /// `SubjectPublicKeyInfo`.
    pub der: Vec<u8>,
}

/// One digest file, decompressed, with where it was read from.
#[derive(Debug, Clone)]
pub struct DigestFile {
    /// The bucket it was read from.
    pub bucket: String,
    /// The key it was read from.
    pub object: String,
    /// Its uncompressed bytes.
    pub bytes: Vec<u8>,
    /// Its signature from the object's `x-amz-meta-signature`, in hex. Needed for the
    /// newest digest of a chain; an older one's signature is in its successor.
    pub signature_hex: Option<String>,
}

/// What a region's chain established.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Coverage {
    /// The region the digests were delivered from.
    pub region: String,
    /// The earliest verified digest's start, UTC seconds.
    pub start: u64,
    /// The latest verified digest's end.
    pub end: u64,
    /// Digests verified.
    pub digests: usize,
    /// Log files verified.
    pub log_files: usize,
}

/// The outcome: the records of every verified log file, what was covered, and every
/// problem found. Any problem means the record cannot be relied on for this window.
#[derive(Debug, Clone, Default)]
pub struct ValidatedTrail {
    /// The records (CloudTrail events) of the verified log files.
    pub records: Vec<Value>,
    /// Per region, what the verified chain covers.
    pub coverage: Vec<Coverage>,
    /// Everything that failed, in words.
    pub problems: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0f].map(|n| char::from_digit(u32::from(n), 16).unwrap_or('0')))
        .collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| {
            let hi = char::from(*p.first()?).to_digit(16)?;
            let lo = char::from(*p.get(1)?).to_digit(16)?;
            u8::try_from(hi.checked_mul(16)?.checked_add(lo)?).ok()
        })
        .collect()
}

/// The `RSAPublicKey` inside a `SubjectPublicKeyInfo` for rsaEncryption, or the input when
/// it is already one. Only the one shape AWS documents is unwrapped; anything else is left
/// for the verifier to reject.
fn pkcs1(der: &[u8]) -> &[u8] {
    // SEQUENCE { SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }, BIT STRING { 0x00, key } }
    const ALG: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let Some(rest) = strip_header(der, 0x30) else {
        return der;
    };
    let Some(rest) = rest.strip_prefix(&ALG[..]) else {
        return der;
    };
    match strip_header(rest, 0x03).and_then(|b| b.strip_prefix(&[0x00][..])) {
        Some(key) => key,
        None => der,
    }
}

/// The contents of a DER element with this tag that spans the whole input.
fn strip_header(der: &[u8], tag: u8) -> Option<&[u8]> {
    let (&t, rest) = der.split_first()?;
    if t != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (len_bytes, rest) = rest.split_at_checked(n)?;
        let len = len_bytes.iter().try_fold(0usize, |acc, &b| {
            acc.checked_mul(256)?.checked_add(usize::from(b))
        })?;
        (len, rest)
    };
    (rest.len() == len).then_some(rest)
}

/// The region a digest was delivered from: the segment after `CloudTrail-Digest/`.
fn region_of(object: &str) -> Option<&str> {
    object
        .split("/CloudTrail-Digest/")
        .nth(1)?
        .split('/')
        .next()
}

/// One parsed digest.
struct Parsed {
    file: DigestFile,
    json: Value,
    start: u64,
    end: u64,
    sha256: String,
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// The string CloudTrail signs: end time, `bucket/key`, the hex SHA-256 of the digest's
/// uncompressed bytes, and the previous digest's signature (`null` for a starting digest).
fn data_to_sign(p: &Parsed) -> String {
    format!(
        "{}\n{}/{}\n{}\n{}",
        text(&p.json, "digestEndTime").unwrap_or_default(),
        text(&p.json, "digestS3Bucket").unwrap_or_default(),
        text(&p.json, "digestS3Object").unwrap_or_default(),
        p.sha256,
        text(&p.json, "previousDigestSignature").unwrap_or("null")
    )
}

fn verify_signature(p: &Parsed, signature_hex: &str, keys: &[TrailKey]) -> Result<(), String> {
    let fingerprint = text(&p.json, "digestPublicKeyFingerprint").ok_or("no key fingerprint")?;
    if text(&p.json, "digestSignatureAlgorithm") != Some("SHA256withRSA") {
        return Err("not signed with SHA256withRSA".into());
    }
    let key = keys
        .iter()
        .find(|k| k.fingerprint == fingerprint)
        .ok_or_else(|| format!("no public key with fingerprint {fingerprint}"))?;
    let signature = unhex(signature_hex).ok_or("signature is not hex")?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pkcs1(&key.der))
        .verify(data_to_sign(p).as_bytes(), &signature)
        .map_err(|_| "signature does not verify".to_owned())
}

/// Parses digests and groups them by delivering region; malformed or moved ones are named.
fn parse_digests(
    digests: &[DigestFile],
    problems: &mut Vec<String>,
) -> BTreeMap<String, Vec<Parsed>> {
    let mut by_region: BTreeMap<String, Vec<Parsed>> = BTreeMap::new();
    for f in digests {
        let name = format!("{}/{}", f.bucket, f.object);
        let Ok(json) = serde_json::from_slice::<Value>(&f.bytes) else {
            problems.push(format!("{name}: not JSON"));
            continue;
        };
        if text(&json, "digestS3Bucket") != Some(f.bucket.as_str())
            || text(&json, "digestS3Object") != Some(f.object.as_str())
        {
            problems.push(format!("{name}: not at the location it records"));
            continue;
        }
        let times = (
            text(&json, "digestStartTime").and_then(parse_iso8601),
            text(&json, "digestEndTime").and_then(parse_iso8601),
        );
        let (Some(start), Some(end), Some(region)) = (times.0, times.1, region_of(&f.object))
        else {
            problems.push(format!("{name}: no time range or region"));
            continue;
        };
        by_region
            .entry(region.to_owned())
            .or_default()
            .push(Parsed {
                file: f.clone(),
                json,
                start,
                end,
                sha256: hex(&Sha256::digest(&f.bytes)),
            });
    }
    by_region
}

/// Checks one digest's signature and its link to the next; returns nothing, naming problems.
fn check_link(
    p: &Parsed,
    next: Option<&Parsed>,
    first: bool,
    region: &str,
    keys: &[TrailKey],
    problems: &mut Vec<String>,
) {
    let name = &p.file.object;
    let from_next = next.and_then(|n| text(&n.json, "previousDigestSignature"));
    let signature = match (p.file.signature_hex.as_deref(), from_next) {
        (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b) => {
            problems.push(format!(
                "{name}: its signature differs from the one its successor records"
            ));
            None
        }
        (Some(a), _) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => {
            problems.push(format!(
                "{name}: no signature (the newest digest's comes from S3 metadata)"
            ));
            None
        }
    };
    if let Some(signature) = signature
        && let Err(e) = verify_signature(p, signature, keys)
    {
        problems.push(format!("{name}: {e}"));
    }
    if let Some(n) = next {
        if text(&n.json, "previousDigestS3Object") != Some(p.file.object.as_str())
            || text(&n.json, "previousDigestS3Bucket") != Some(p.file.bucket.as_str())
            || text(&n.json, "previousDigestHashValue") != Some(p.sha256.as_str())
        {
            problems.push(format!("{}: does not chain to {name}", n.file.object));
        }
        if n.start != p.end {
            problems.push(format!(
                "{region}: no digest covers {} to {}; the record has a gap",
                remit_aws::iso8601(p.end),
                remit_aws::iso8601(n.start)
            ));
        }
    }
    if !first && text(&p.json, "previousDigestSignature").is_none() {
        problems.push(format!(
            "{name}: validation was restarted here; the chain before it is not linked"
        ));
    }
}

/// Checks the log files one digest lists and collects their records; returns how many
/// verified.
fn check_logs<S: BuildHasher>(
    p: &Parsed,
    logs: &HashMap<(String, String), Vec<u8>, S>,
    records: &mut Vec<Value>,
    problems: &mut Vec<String>,
) -> usize {
    let mut verified = 0usize;
    for lf in p
        .json
        .get("logFiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(b), Some(o), Some(h)) = (
            text(lf, "s3Bucket"),
            text(lf, "s3Object"),
            text(lf, "hashValue"),
        ) else {
            problems.push(format!("{}: a log file entry is incomplete", p.file.object));
            continue;
        };
        if text(lf, "hashAlgorithm") != Some("SHA-256") {
            problems.push(format!("{b}/{o}: not hashed with SHA-256"));
            continue;
        }
        let Some(bytes) = logs.get(&(b.to_owned(), o.to_owned())) else {
            problems.push(format!("{b}/{o}: listed in a digest but not provided"));
            continue;
        };
        if hex(&Sha256::digest(bytes)) != h {
            problems.push(format!(
                "{b}/{o}: its hash is not the one its digest records"
            ));
            continue;
        }
        match serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|v| v.get("Records").cloned())
        {
            Some(Value::Array(rs)) => {
                records.extend(rs);
                verified = verified.saturating_add(1);
            }
            _ => problems.push(format!("{b}/{o}: not a CloudTrail log file")),
        }
    }
    verified
}

/// Validates every region's digest chain and the log files it lists, and requires a chain
/// for each of `regions` that covers `[need_from, need_to]` (delivery time) without a gap.
#[must_use]
pub fn validate<S: BuildHasher>(
    digests: &[DigestFile],
    logs: &HashMap<(String, String), Vec<u8>, S>,
    keys: &[TrailKey],
    regions: &[String],
    need_from: u64,
    need_to: u64,
) -> ValidatedTrail {
    let mut out = ValidatedTrail::default();
    let by_region = parse_digests(digests, &mut out.problems);
    for region in regions {
        if !by_region.contains_key(region) {
            out.problems.push(format!(
                "{region}: no digest files; nothing shows what was recorded there"
            ));
        }
    }
    for (region, mut chain) in by_region {
        chain.sort_by_key(|p| p.end);
        let before = out.problems.len();
        let mut log_files = 0usize;
        for (i, p) in chain.iter().enumerate() {
            check_link(
                p,
                chain.get(i.saturating_add(1)),
                i == 0,
                &region,
                keys,
                &mut out.problems,
            );
            // The log files of every digest that overlaps the window.
            if p.end >= need_from && p.start <= need_to {
                log_files = log_files.saturating_add(check_logs(
                    p,
                    logs,
                    &mut out.records,
                    &mut out.problems,
                ));
            }
        }
        let (Some(first), Some(last)) = (chain.first(), chain.last()) else {
            continue;
        };
        if first.start > need_from || last.end < need_to {
            out.problems.push(format!(
                "{region}: digests cover {} to {}, not the whole of {} to {}",
                remit_aws::iso8601(first.start),
                remit_aws::iso8601(last.end),
                remit_aws::iso8601(need_from),
                remit_aws::iso8601(need_to)
            ));
        }
        if out.problems.len() == before {
            out.coverage.push(Coverage {
                region,
                start: first.start,
                end: last.end,
                digests: chain.len(),
                log_files,
            });
        }
    }
    out
}
