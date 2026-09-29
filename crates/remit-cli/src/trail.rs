//! A local copy of a CloudTrail bucket, read for `remit reconcile --trail-dir`.
//!
//! The copy is taken separately (reading S3 bills per request; see
//! `scripts/fetch-trail.sh`), so validation itself makes no AWS call and can be repeated.
//! Paths under the directory are the objects' S3 keys.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::Path;

use remit_reconcile::trail::{DigestFile, TrailKey};

use crate::Result;

/// Everything the validator needs, read from disk.
pub(crate) struct Local {
    pub(crate) digests: Vec<DigestFile>,
    pub(crate) logs: HashMap<(String, String), Vec<u8>>,
    pub(crate) keys: Vec<TrailKey>,
}

fn gunzip(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    // At most 256 MiB uncompressed per file: far above any CloudTrail file.
    flate2::read::GzDecoder::new(file)
        .take(256 << 20)
        .read_to_end(&mut out)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(out)
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) -> Result<()> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            walk(&path, root, out)?;
        } else if path.to_string_lossy().ends_with(".json.gz") {
            let key = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            out.push((key, path));
        }
    }
    Ok(())
}

/// CloudTrail's public keys from the JSON `aws cloudtrail list-public-keys` prints.
pub(crate) fn keys_from_file(keys: &Path) -> Result<Vec<TrailKey>> {
    let key_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(keys).map_err(|e| format!("{}: {e}", keys.display()))?,
    )
    .map_err(|e| format!("{}: {e}", keys.display()))?;
    let mut trail_keys = Vec::new();
    for k in key_json
        .get("PublicKeyList")
        .and_then(serde_json::Value::as_array)
        .ok_or("no PublicKeyList in the keys file")?
    {
        let (Some(fp), Some(value)) = (
            k.get("Fingerprint").and_then(serde_json::Value::as_str),
            k.get("Value").and_then(serde_json::Value::as_str),
        ) else {
            return Err("a public key without Fingerprint or Value".into());
        };
        let der = remit_log::base64::decode(value).ok_or("a public key that is not base64")?;
        trail_keys.push(TrailKey {
            fingerprint: fp.to_owned(),
            der,
        });
    }
    Ok(trail_keys)
}

/// CloudTrail's public keys for `[from, to]`, asked of CloudTrail itself in each region
/// with the run's own credentials: what vouches for the record comes from AWS, not from
/// whoever started the run (THREAT-MODEL, crossing X12).
pub(crate) async fn fetch_keys(
    config: &aws_config::SdkConfig,
    regions: &[String],
    from: u64,
    to: u64,
) -> Result<Vec<TrailKey>> {
    let mut keys: Vec<TrailKey> = Vec::new();
    for region in regions {
        let regional = config
            .to_builder()
            .region(aws_config::Region::new(region.clone()))
            .build();
        let client = aws_sdk_cloudtrail::Client::new(&regional);
        let at = |t: u64| {
            aws_sdk_cloudtrail::primitives::DateTime::from_secs(i64::try_from(t).unwrap_or(0))
        };
        let mut token: Option<String> = None;
        loop {
            let page = client
                .list_public_keys()
                .start_time(at(from))
                .end_time(at(to))
                .set_next_token(token.clone())
                .send()
                .await
                .map_err(|e| {
                    format!(
                        "{region}: list-public-keys: {}",
                        aws_sdk_cloudtrail::error::DisplayErrorContext(&e)
                    )
                })?;
            for k in page.public_key_list() {
                let (Some(fp), Some(value)) = (k.fingerprint(), k.value()) else {
                    return Err(format!(
                        "{region}: a public key without fingerprint or value"
                    ));
                };
                if !keys.iter().any(|have| have.fingerprint == fp) {
                    keys.push(TrailKey {
                        fingerprint: fp.to_owned(),
                        der: value.as_ref().to_vec(),
                    });
                }
            }
            token = page.next_token().map(str::to_owned);
            if token.is_none() {
                break;
            }
        }
    }
    if keys.is_empty() {
        return Err("CloudTrail returned no public keys for the window".into());
    }
    Ok(keys)
}

/// Reads digests, log files and the newest digests' signatures; the public keys are given.
pub(crate) fn load(
    dir: &Path,
    bucket: &str,
    keys: Vec<TrailKey>,
    signatures: &Path,
) -> Result<Local> {
    let sigs: HashMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(signatures)
            .map_err(|e| format!("{}: {e}", signatures.display()))?,
    )
    .map_err(|e| format!("{}: {e}", signatures.display()))?;
    let mut files = Vec::new();
    walk(dir, dir, &mut files)?;
    let mut digests = Vec::new();
    let mut logs = HashMap::new();
    for (key, path) in files {
        let bytes = gunzip(&path)?;
        if key.contains("/CloudTrail-Digest/") {
            digests.push(DigestFile {
                bucket: bucket.to_owned(),
                signature_hex: sigs.get(&key).cloned(),
                object: key,
                bytes,
            });
        } else if key.contains("/CloudTrail/") {
            logs.insert((bucket.to_owned(), key), bytes);
        }
    }
    Ok(Local {
        digests,
        logs,
        keys,
    })
}
