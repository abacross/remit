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

/// Reads digests, log files, public keys and the newest digests' signatures.
pub(crate) fn load(dir: &Path, bucket: &str, keys: &Path, signatures: &Path) -> Result<Local> {
    let sigs: HashMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(signatures)
            .map_err(|e| format!("{}: {e}", signatures.display()))?,
    )
    .map_err(|e| format!("{}: {e}", signatures.display()))?;
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
        keys: trail_keys,
    })
}
