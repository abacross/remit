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

/// Which management events these selectors record, and which data events: CloudTrail
/// has two selector forms, and a trail uses one or the other.
fn scope_of(
    basic: &[aws_sdk_cloudtrail::types::EventSelector],
    advanced: &[aws_sdk_cloudtrail::types::AdvancedEventSelector],
) -> (remit_reconcile::trail::Management, Vec<String>) {
    use aws_sdk_cloudtrail::types::ReadWriteType;
    use remit_reconcile::trail::Management;
    let mut found: Vec<Management> = Vec::new();
    let mut data = Vec::new();
    for s in basic {
        data.extend(
            s.data_resources()
                .iter()
                .filter_map(|r| r.r#type().map(str::to_owned)),
        );
        if s.include_management_events() == Some(false) {
            continue;
        }
        let excluded = s.exclude_management_event_sources();
        found.push(match s.read_write_type() {
            Some(ReadWriteType::ReadOnly) => Management::Partly("write events".into()),
            Some(ReadWriteType::WriteOnly) => Management::Partly("read events".into()),
            _ if !excluded.is_empty() => {
                Management::Partly(format!("events from {}", excluded.join(", ")))
            }
            _ => Management::All,
        });
    }
    for s in advanced {
        let fields = s.field_selectors();
        let category = fields
            .iter()
            .find(|f| f.field() == "eventCategory")
            .map(|f| f.equals().join(","));
        match category.as_deref() {
            Some("Management") => {
                let limits: Vec<String> = fields
                    .iter()
                    .filter(|f| f.field() != "eventCategory")
                    .map(|f| match (f.field(), f.equals()) {
                        ("readOnly", [v]) if v == "true" => "write events".to_owned(),
                        ("readOnly", [v]) if v == "false" => "read events".to_owned(),
                        ("eventSource", _) if !f.not_equals().is_empty() => {
                            format!("events from {}", f.not_equals().join(", "))
                        }
                        (other, _) => format!("events other than those its {other} selects"),
                    })
                    .collect();
                found.push(if limits.is_empty() {
                    Management::All
                } else {
                    Management::Partly(limits.join(" and "))
                });
            }
            Some("Data") => data.extend(
                fields
                    .iter()
                    .filter(|f| f.field() == "resources.type")
                    .flat_map(|f| f.equals().iter().cloned()),
            ),
            _ => {}
        }
    }
    data.sort();
    data.dedup();
    let management = if found.contains(&Management::All) {
        Management::All
    } else {
        found.into_iter().next().unwrap_or(Management::Nothing)
    };
    (management, data)
}

/// The configuration of the trail that delivers to `bucket`, read from CloudTrail
/// (SPEC 6.7): a validated record says its files are whole, and this says what they cover.
pub(crate) async fn trail_config(
    config: &aws_config::SdkConfig,
    bucket: &str,
) -> Result<remit_reconcile::trail::TrailConfig> {
    let error = |what: &str, e: &dyn std::fmt::Display| format!("{what}: {e}");
    let trails = aws_sdk_cloudtrail::Client::new(config)
        .describe_trails()
        .include_shadow_trails(true)
        .send()
        .await
        .map_err(|e| {
            error(
                "describe-trails",
                &aws_sdk_cloudtrail::error::DisplayErrorContext(&e),
            )
        })?;
    let trail = trails
        .trail_list()
        .iter()
        .filter(|t| t.s3_bucket_name() == Some(bucket))
        .max_by_key(|t| t.is_multi_region_trail() == Some(true))
        .ok_or_else(|| format!("no trail delivers to {bucket}"))?;
    let arn = trail
        .trail_arn()
        .ok_or("a trail without an ARN")?
        .to_owned();
    let home = trail.home_region().unwrap_or("us-east-1").to_owned();
    let client = aws_sdk_cloudtrail::Client::new(
        &config
            .to_builder()
            .region(aws_config::Region::new(home.clone()))
            .build(),
    );
    let status = client
        .get_trail_status()
        .name(&arn)
        .send()
        .await
        .map_err(|e| {
            error(
                "get-trail-status",
                &aws_sdk_cloudtrail::error::DisplayErrorContext(&e),
            )
        })?;
    let selectors = client
        .get_event_selectors()
        .trail_name(&arn)
        .send()
        .await
        .map_err(|e| {
            error(
                "get-event-selectors",
                &aws_sdk_cloudtrail::error::DisplayErrorContext(&e),
            )
        })?;
    let (management, data_events) = scope_of(
        selectors.event_selectors(),
        selectors.advanced_event_selectors(),
    );
    Ok(remit_reconcile::trail::TrailConfig {
        arn,
        bucket: bucket.to_owned(),
        multi_region: trail.is_multi_region_trail() == Some(true),
        home_region: home,
        global_service_events: trail.include_global_service_events() == Some(true),
        logging: status.is_logging() == Some(true),
        file_validation: trail.log_file_validation_enabled() == Some(true),
        management,
        data_events,
    })
}

#[cfg(test)]
mod tests {
    use super::scope_of;
    use aws_sdk_cloudtrail::types::{
        AdvancedEventSelector, AdvancedFieldSelector, DataResource, EventSelector, ReadWriteType,
    };
    use remit_reconcile::trail::Management;

    fn field(name: &str, equals: &[&str], not_equals: &[&str]) -> AdvancedFieldSelector {
        let mut b = AdvancedFieldSelector::builder().field(name);
        for v in equals {
            b = b.equals(*v);
        }
        for v in not_equals {
            b = b.not_equals(*v);
        }
        b.build().unwrap()
    }

    fn advanced(fields: Vec<AdvancedFieldSelector>) -> AdvancedEventSelector {
        AdvancedEventSelector::builder()
            .set_field_selectors(Some(fields))
            .build()
            .unwrap()
    }

    #[test]
    fn basic_selectors_read_as_the_console_writes_them() {
        let all = EventSelector::builder()
            .read_write_type(ReadWriteType::All)
            .include_management_events(true)
            .data_resources(DataResource::builder().r#type("AWS::S3::Object").build())
            .build();
        assert_eq!(
            scope_of(&[all], &[]),
            (Management::All, vec!["AWS::S3::Object".to_owned()])
        );
        let reads = EventSelector::builder()
            .read_write_type(ReadWriteType::ReadOnly)
            .build();
        assert_eq!(
            scope_of(&[reads], &[]).0,
            Management::Partly("write events".into())
        );
        let no_kms = EventSelector::builder()
            .read_write_type(ReadWriteType::All)
            .exclude_management_event_sources("kms.amazonaws.com")
            .build();
        assert_eq!(
            scope_of(&[no_kms], &[]).0,
            Management::Partly("events from kms.amazonaws.com".into())
        );
        let none = EventSelector::builder()
            .include_management_events(false)
            .build();
        assert_eq!(scope_of(&[none], &[]).0, Management::Nothing);
    }

    #[test]
    fn advanced_selectors_are_read_field_by_field() {
        let all = advanced(vec![field("eventCategory", &["Management"], &[])]);
        let data = advanced(vec![
            field("eventCategory", &["Data"], &[]),
            field(
                "resources.type",
                &["AWS::S3::Object", "AWS::Lambda::Function"],
                &[],
            ),
        ]);
        let (m, d) = scope_of(&[], &[all, data]);
        assert_eq!(m, Management::All);
        assert_eq!(d, vec!["AWS::Lambda::Function", "AWS::S3::Object"]);
        let writes_only = advanced(vec![
            field("eventCategory", &["Management"], &[]),
            field("readOnly", &["false"], &[]),
        ]);
        assert_eq!(
            scope_of(&[], &[writes_only]).0,
            Management::Partly("read events".into())
        );
        let no_kms = advanced(vec![
            field("eventCategory", &["Management"], &[]),
            field("eventSource", &[], &["kms.amazonaws.com"]),
        ]);
        assert_eq!(
            scope_of(&[], &[no_kms]).0,
            Management::Partly("events from kms.amazonaws.com".into())
        );
        assert_eq!(scope_of(&[], &[]).0, Management::Nothing);
    }
}
