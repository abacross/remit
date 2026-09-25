//! `remit`: keys, warrants, delegation, and `remit run`.
//!
//! `remit run` verifies a warrant chain against trusted roots and that every link is
//! proven logged (SPEC section 9.3), obtains an STS session stamped with the leaf
//! warrant's identifier (SPEC section 8.1), and runs a command with those credentials and
//! no other: every other place an AWS SDK looks for credentials is closed in the child's
//! environment, so it cannot fall back to the broker's own.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

mod approve;
mod log;

use clap::{Args, Parser, Subcommand};
use remit_core::{
    IssuerKey, KeyId, SignedWarrant, Warrant, WarrantSpec, check_attenuation, decode_chain,
    encode_chain, verify_chain,
};

#[derive(Parser)]
#[command(
    name = "remit",
    version,
    about = "Authorized, bounded, provably complete cloud activity for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Top,
}

#[derive(Subcommand)]
enum Top {
    /// Signing keys.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Issue, delegate and inspect warrants.
    #[command(subcommand)]
    Warrant(WarrantCmd),
    /// Run a command with AWS credentials scoped by a verified warrant chain.
    Run(RunArgs),
    /// Reconcile `CloudTrail` against warrants (SPEC 6); read-only AWS calls only.
    Reconcile(ReconcileArgs),
    /// Ask an approver for one action, inside a bound a human signed (SPEC 10).
    Approve(approve::ApproveArgs),
    /// AWS's service reference, from which approvers take an action's risk band.
    #[command(subcommand)]
    Reference(ReferenceCmd),
    /// The witnessed log: create, append, cosign, prove and verify (SPEC 9).
    #[command(subcommand)]
    Log(log::LogCmd),
    /// Verify a signed reconciliation report offline.
    VerifyReport {
        /// The report.
        #[arg(long)]
        report: PathBuf,
        /// Its signature file.
        #[arg(long)]
        signature: PathBuf,
        /// The reconciler key the report must be signed by.
        #[arg(long)]
        key_id: String,
    },
}

#[derive(Args)]
struct ReconcileArgs {
    /// The log whose warrants events are joined to (SPEC 9.4).
    #[arg(long)]
    log_dir: PathBuf,
    /// The trust policy its checkpoint must satisfy.
    #[arg(long)]
    log_policy: PathBuf,
    /// Trusted root key identifiers.
    #[arg(long = "root", required = true)]
    roots: Vec<String>,
    /// A managed role ARN; repeat for more.
    #[arg(long = "role", required = true)]
    roles: Vec<String>,
    /// A region to gather events from; repeat. The report speaks for these only.
    #[arg(long = "region", required = true)]
    regions: Vec<String>,
    /// Start of the window, `YYYY-MM-DDTHH:MM:SSZ`.
    #[arg(long)]
    from: String,
    /// End of the window.
    #[arg(long)]
    to: String,
    /// Seconds after the window's end before events are taken as delivered (SPEC section 6,
    /// assumption 5); the report states the value used.
    #[arg(long, default_value_t = remit_reconcile::DEFAULT_SETTLE_SECONDS)]
    settle_seconds: u64,
    /// The reconciler's seed file, which signs the report.
    #[arg(long)]
    key: PathBuf,
    /// Where to write the report; the signature goes beside it as `<out>.sig`.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Subcommand)]
enum ReferenceCmd {
    /// Download AWS's service reference files (public, no AWS account needed).
    Fetch {
        /// The directory to write `<service>.json` files into.
        #[arg(long)]
        out: PathBuf,
        /// Only these services (IAM prefixes such as `s3`); all when absent.
        #[arg(long = "service")]
        services: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate a key from the operating system's secure random source.
    New {
        /// Where to write the seed (created with mode 0600; never overwritten).
        #[arg(long)]
        out: PathBuf,
    },
    /// Print a key's identifier.
    Id {
        /// The seed file.
        #[arg(long)]
        key: PathBuf,
    },
}

#[derive(Args)]
struct GrantArgs {
    /// `ACTIONS=RESOURCES`, each a comma-separated list of patterns; repeat for more grants.
    #[arg(long = "grant", required = true)]
    grants: Vec<String>,
    /// Seconds the warrant is valid for, from `--starts-at` or now.
    #[arg(long)]
    valid_for: u64,
    /// First valid second (UTC seconds since the epoch); now if absent.
    #[arg(long)]
    starts_at: Option<u64>,
    /// Why, in words; recorded, not enforced.
    #[arg(long, default_value = "")]
    purpose: String,
    /// Further delegations permitted.
    #[arg(long, default_value_t = 0)]
    max_depth: u64,
}

#[derive(Subcommand)]
enum WarrantCmd {
    /// Issue a root warrant signed by your key.
    Issue {
        /// Your seed file.
        #[arg(long)]
        key: PathBuf,
        /// The agent's key identifier (or any identifier, if it will never delegate).
        #[arg(long)]
        subject: String,
        #[command(flatten)]
        grant: GrantArgs,
        /// Where to write the one-link chain.
        #[arg(long)]
        out: PathBuf,
    },
    /// Delegate part of a chain's leaf warrant to another agent; refused unless it narrows.
    Delegate {
        /// The delegating agent's seed file: the key the leaf warrant names as subject.
        #[arg(long)]
        key: PathBuf,
        /// The chain to extend.
        #[arg(long)]
        chain: PathBuf,
        /// The receiving agent's identifier.
        #[arg(long)]
        subject: String,
        #[command(flatten)]
        grant: GrantArgs,
        /// Where to write the extended chain.
        #[arg(long)]
        out: PathBuf,
    },
    /// Show a chain, and verify it if roots are given.
    Show {
        /// The chain file.
        #[arg(long)]
        chain: PathBuf,
        /// Trusted root key identifiers.
        #[arg(long = "root")]
        roots: Vec<String>,
    },
}

#[derive(Args)]
struct RunArgs {
    /// The warrant chain.
    #[arg(long)]
    chain: PathBuf,
    /// Trusted root key identifiers; the chain must start at one of them.
    #[arg(long = "root", required = true)]
    roots: Vec<String>,
    /// The role to assume; its trust policy must require a source identity.
    #[arg(long)]
    role: String,
    /// The role's maximum session duration in seconds.
    #[arg(long, default_value_t = 3600)]
    role_max_seconds: u64,
    /// The trust policy for the log (SPEC 9.2): no chain is honoured unless proven logged.
    #[arg(long)]
    log_policy: PathBuf,
    /// The proof that every link of the chain is logged (`remit log prove`).
    #[arg(long)]
    log_proof: PathBuf,
    /// The region for STS and for the command; else the environment's, else us-east-1.
    #[arg(long)]
    region: Option<String>,
    /// The command and its arguments.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

type Result<T> = std::result::Result<T, String>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn read_seed_bytes(path: &Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let hex = text.trim();
    if hex.len() != 64 {
        return Err(format!("{}: not a 32-byte hex seed", path.display()));
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        let at = i.saturating_mul(2);
        let pair = hex.get(at..at.saturating_add(2)).unwrap_or("");
        *byte = u8::from_str_radix(pair, 16).map_err(|_| format!("{}: not hex", path.display()))?;
    }
    Ok(seed)
}

fn read_seed(path: &Path) -> Result<IssuerKey> {
    Ok(IssuerKey::from_seed(&read_seed_bytes(path)?))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e} (never overwritten)", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn read_chain(path: &Path) -> Result<Vec<SignedWarrant>> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    decode_chain(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn roots(ids: &[String]) -> Result<Vec<KeyId>> {
    ids.iter()
        .map(|s| KeyId::parse(s).map_err(|e| e.to_string()))
        .collect()
}

fn build(
    issuer: &IssuerKey,
    subject: &str,
    g: &GrantArgs,
    parent: Option<&Warrant>,
) -> Result<Warrant> {
    let parsed: Vec<(Vec<&str>, Vec<&str>)> = g
        .grants
        .iter()
        .map(|spec| {
            let (a, r) = spec
                .split_once('=')
                .ok_or_else(|| format!("--grant {spec:?}: expected ACTIONS=RESOURCES"))?;
            Ok((a.split(',').collect(), r.split(',').collect()))
        })
        .collect::<Result<_>>()?;
    let refs: Vec<(&[&str], &[&str])> = parsed
        .iter()
        .map(|(a, r)| (a.as_slice(), r.as_slice()))
        .collect();
    let start = g.starts_at.unwrap_or_else(now);
    Warrant::new(&WarrantSpec {
        issuer: issuer.id().as_str(),
        subject,
        purpose: &g.purpose,
        not_before: start,
        not_after: start.saturating_add(g.valid_for),
        grants: &refs,
        parent: parent.map(Warrant::id),
        max_depth: g.max_depth,
    })
    .map_err(|e| e.to_string())
}

fn describe(w: &Warrant) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "  {}  issuer {}", w.id(), w.issuer());
    let _ = writeln!(s, "      subject {}", w.subject());
    let _ = writeln!(
        s,
        "      valid {} .. {}  depth {}",
        w.not_before(),
        w.not_after(),
        w.max_depth()
    );
    for g in w.grants() {
        let a: Vec<&str> = g
            .actions()
            .iter()
            .map(remit_core::ActionPattern::as_str)
            .collect();
        let r: Vec<&str> = g
            .resources()
            .iter()
            .map(remit_core::ResourcePattern::as_str)
            .collect();
        let _ = writeln!(s, "      allow {} on {}", a.join(","), r.join(","));
    }
    if !w.purpose().is_empty() {
        let _ = writeln!(s, "      purpose: {}", w.purpose());
    }
    s
}

/// Variables through which an AWS SDK could find credentials other than the session's.
const CLOSED: &[&str] = &[
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CREDENTIAL_EXPIRATION",
];

async fn run(args: RunArgs) -> Result<ExitCode> {
    let chain = read_chain(&args.chain)?;
    let plan = remit_broker::plan(&chain, &roots(&args.roots)?, now(), args.role_max_seconds)
        .map_err(|e| format!("refused: {e}"))?;
    // Logged before used (SPEC 9.3): checked before anything reaches AWS.
    let logged = log::verify_logged(&args.log_policy, &args.chain, &args.log_proof)
        .map_err(|e| format!("refused: {e}"))?;
    // A machine with no configured region is common; STS still needs one, and the command
    // should run in the same one (found on the first live session, 2026-09-24).
    let chain_of_regions = aws_config::meta::region::RegionProviderChain::first_try(
        args.region.clone().map(aws_config::Region::new),
    )
    .or_default_provider()
    .or_else(aws_config::Region::from_static("us-east-1"));
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(chain_of_regions)
        .load()
        .await;
    let region = config
        .region()
        .map_or_else(|| "us-east-1".to_owned(), ToString::to_string);
    let sts = aws_sdk_sts::Client::new(&config);
    let creds = remit_broker::assume(&sts, &args.role, &plan)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "remit: warrant {} for {}, {} s; logged in {} at size {}",
        plan.warrant_id,
        plan.subject,
        plan.duration_seconds,
        logged.checkpoint.origin(),
        logged.checkpoint.size()
    );

    let (program, rest) = args.command.split_first().ok_or("no command")?;
    let mut cmd = Command::new(program);
    cmd.args(rest);
    for var in CLOSED {
        cmd.env_remove(var);
    }
    // The shared files hold the broker's own credentials; the child sees none of them.
    cmd.env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
        .env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key)
        .env("AWS_SESSION_TOKEN", &creds.session_token)
        .env("AWS_REGION", &region)
        .env("REMIT_WARRANT_ID", plan.warrant_id.as_str());
    let status = cmd.status().map_err(|e| format!("{program}: {e}"))?;
    Ok(status
        .code()
        .and_then(|c| u8::try_from(c).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from))
}

/// The domain report signatures are made in (`remit_core::sign_in_domain`).
const REPORT_DOMAIN: &[u8; 8] = remit_core::RESULT_DOMAIN;

/// IAM returns trust policies percent-encoded (RFC 3986).
fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = s
                .get(i.saturating_add(1)..i.saturating_add(3))
                .ok_or("truncated %-escape")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| format!("bad %-escape {hex:?}"))?);
            i = i.saturating_add(3);
        } else {
            out.push(if b == b'+' { b' ' } else { b });
            i = i.saturating_add(1);
        }
    }
    String::from_utf8(out).map_err(|_| "decoded policy is not UTF-8".to_owned())
}

async fn fetch_events(
    config: &aws_config::SdkConfig,
    region: &str,
    from: u64,
    to: u64,
) -> Result<Vec<remit_reconcile::Event>> {
    let regional = config
        .to_builder()
        .region(aws_config::Region::new(region.to_owned()))
        .build();
    let client = aws_sdk_cloudtrail::Client::new(&regional);
    let (start, end) = (
        aws_sdk_cloudtrail::primitives::DateTime::from_secs(i64::try_from(from).unwrap_or(0)),
        aws_sdk_cloudtrail::primitives::DateTime::from_secs(i64::try_from(to).unwrap_or(i64::MAX)),
    );
    let mut events = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let page = client
            .lookup_events()
            .start_time(start)
            .end_time(end)
            .max_results(50)
            .set_next_token(token.clone())
            .send()
            .await
            .map_err(|e| {
                format!(
                    "{region}: {}",
                    aws_sdk_cloudtrail::error::DisplayErrorContext(&e)
                )
            })?;
        for e in page.events() {
            let raw = e
                .cloud_trail_event()
                .ok_or_else(|| format!("{region}: an event without its record"))?;
            let v: serde_json::Value =
                serde_json::from_str(raw).map_err(|err| format!("{region}: {err}"))?;
            events.push(
                remit_reconcile::Event::from_json(&v).map_err(|err| format!("{region}: {err}"))?,
            );
        }
        token = page.next_token().map(str::to_owned);
        if token.is_none() {
            break;
        }
        // LookupEvents allows two requests a second per region.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    }
    Ok(events)
}

async fn reconcile(args: ReconcileArgs) -> Result<ExitCode> {
    let from = remit_aws_parse(&args.from)?;
    let to = remit_aws_parse(&args.to)?;
    if from >= to {
        return Err("--from must be before --to".into());
    }
    let signer = read_seed(&args.key)?;
    let trusted = roots(&args.roots)?;

    // L: the warrants the log establishes at a checkpoint the policy trusts (SPEC 9.4).
    let policy = log::read_policy(&args.log_policy)?;
    let logged = remit_logstore::logged_warrants(
        &remit_logstore::LogDir::new(&args.log_dir),
        &policy,
        &trusted,
    )
    .map_err(|e| e.to_string())?;
    let warrants = logged.warrants;
    let refused = logged.refused;
    let position = remit_reconcile::LogPosition {
        origin: logged.checkpoint.checkpoint.origin().to_owned(),
        size: logged.checkpoint.checkpoint.size(),
        root: remit_log::base64::encode(logged.checkpoint.checkpoint.root()),
    };

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::from_static("us-east-1"))
        .load()
        .await;
    let iam = aws_sdk_iam::Client::new(&config);
    let mut roles = Vec::new();
    for arn in &args.roles {
        let name = arn.rsplit('/').next().unwrap_or(arn);
        let got = iam
            .get_role()
            .role_name(name)
            .send()
            .await
            .map_err(|e| format!("{arn}: {}", aws_sdk_iam::error::DisplayErrorContext(&e)))?;
        let encoded = got
            .role()
            .and_then(|r| r.assume_role_policy_document())
            .ok_or_else(|| format!("{arn}: no trust policy"))?;
        let doc: serde_json::Value =
            serde_json::from_str(&percent_decode(encoded)?).map_err(|e| format!("{arn}: {e}"))?;
        roles.push(remit_reconcile::ManagedRole {
            arn: arn.clone(),
            trust_problems: remit_reconcile::trust_policy_problems(&doc),
        });
    }

    let mut events = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for region in &args.regions {
        for e in fetch_events(&config, region, from, to).await? {
            if seen.insert(e.id.clone()) {
                events.push(e);
            }
        }
    }

    let mut report = remit_reconcile::reconcile(&remit_reconcile::Input {
        warrants: &warrants,
        roles: &roles,
        events: &events,
        from,
        to,
        now: now(),
        settle_seconds: args.settle_seconds,
        source: remit_reconcile::EventSource::EventHistory,
        regions: &args.regions,
    });
    report.refused_inputs = refused;
    report.log = Some(position);
    let json = report.to_json().map_err(|e| e.to_string())?;
    let signature = remit_core::sign_in_domain(&signer, REPORT_DOMAIN, json.as_bytes())
        .map_err(|e| e.to_string())?;
    let hex = signature
        .iter()
        .fold(String::with_capacity(128), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
    write_new(&args.out, json.as_bytes())?;
    let sig_path = PathBuf::from(format!("{}.sig", args.out.display()));
    let sig =
        serde_json::json!({"domain": "REMITRv1", "key": signer.id().as_str(), "signature": hex});
    write_new(&sig_path, format!("{sig}\n").as_bytes())?;
    println!("{json}");
    eprintln!("remit: signed by {}; {}", signer.id(), sig_path.display());
    Ok(
        if matches!(report.verdict, remit_reconcile::Verdict::Incomplete) {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        },
    )
}

fn remit_aws_parse(text: &str) -> Result<u64> {
    remit_aws::parse_iso8601(text).ok_or_else(|| format!("{text:?} is not YYYY-MM-DDTHH:MM:SSZ"))
}

fn field<'a>(v: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    v.get(key).unwrap_or(&serde_json::Value::Null)
}

/// Reads a report's signature file (SPEC 6.6): the signer's key and the signature. The
/// signature itself is checked by the caller.
fn read_signature_file(signature: &Path) -> Result<(KeyId, [u8; 64])> {
    let sig_text =
        std::fs::read_to_string(signature).map_err(|e| format!("{}: {e}", signature.display()))?;
    let sig: serde_json::Value = serde_json::from_str(&sig_text).map_err(|e| e.to_string())?;
    if sig.get("domain").and_then(serde_json::Value::as_str) != Some("REMITRv1") {
        return Err("signature is not in the report domain".into());
    }
    let key = sig
        .get("key")
        .and_then(serde_json::Value::as_str)
        .ok_or("no key")?;
    let key = KeyId::parse(key).map_err(|e| e.to_string())?;
    let hex = sig
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or("no signature")?;
    let mut raw = [0u8; 64];
    if hex.len() != 128 {
        return Err("signature is not 64 bytes".into());
    }
    for (i, byte) in raw.iter_mut().enumerate() {
        let at = i.saturating_mul(2);
        *byte = u8::from_str_radix(hex.get(at..at.saturating_add(2)).unwrap_or(""), 16)
            .map_err(|_| "signature is not hex")?;
    }
    Ok((key, raw))
}

/// The signature beside a report, at `<report>.sig`.
fn read_report_signature(report: &Path) -> Result<(KeyId, [u8; 64])> {
    read_signature_file(&PathBuf::from(format!("{}.sig", report.display())))
}

fn verify_report(report: &Path, signature: &Path, key_id: &str) -> Result<()> {
    let bytes = std::fs::read(report).map_err(|e| format!("{}: {e}", report.display()))?;
    let (signer, raw) = read_signature_file(signature)?;
    if signer.as_str() != key_id {
        return Err(format!("signed by {signer}, not {key_id}"));
    }
    let key = signer;
    remit_core::verify_in_domain(&key, REPORT_DOMAIN, &bytes, &raw).map_err(|_| {
        "the signature does not verify: the report was changed or not signed by this key".to_owned()
    })?;
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    println!(
        "valid: verdict {}, window {} .. {}, regions {}",
        field(&parsed, "verdict"),
        field(&parsed, "from"),
        field(&parsed, "to"),
        field(&parsed, "regions")
    );
    Ok(())
}

fn key(cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::New { out } => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| format!("random source: {e}"))?;
            let hex = seed.iter().fold(String::with_capacity(65), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
            write_new(&out, format!("{hex}\n").as_bytes())?;
            println!("{}", IssuerKey::from_seed(&seed).id());
        }
        KeyCmd::Id { key } => println!("{}", read_seed(&key)?.id()),
    }
    Ok(())
}

fn warrant(cmd: WarrantCmd) -> Result<()> {
    match cmd {
        WarrantCmd::Issue {
            key,
            subject,
            grant,
            out,
        } => {
            let k = read_seed(&key)?;
            let w = build(&k, &subject, &grant, None)?;
            let signed = k.sign(&w).map_err(|e| e.to_string())?;
            write_new(&out, &encode_chain(&[signed]))?;
            print!("{}", describe(&w));
        }
        WarrantCmd::Delegate {
            key,
            chain,
            subject,
            grant,
            out,
        } => {
            let k = read_seed(&key)?;
            let mut links = read_chain(&chain)?;
            let parent = links.last().ok_or("empty chain")?.warrant().clone();
            let child = build(&k, &subject, &grant, Some(&parent))?;
            check_attenuation(&parent, &child).map_err(|e| format!("refused: {e}"))?;
            links.push(k.sign(&child).map_err(|e| e.to_string())?);
            write_new(&out, &encode_chain(&links))?;
            print!("{}", describe(&child));
        }
        WarrantCmd::Show { chain, roots: ids } => {
            let links = read_chain(&chain)?;
            for l in &links {
                print!("{}", describe(l.warrant()));
            }
            if !ids.is_empty() {
                match verify_chain(&links, &roots(&ids)?) {
                    Ok(leaf) => println!("valid: confers {}", leaf.id()),
                    Err(e) => return Err(format!("invalid: {e}")),
                }
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Top::Key(k) => key(k).map(|()| ExitCode::SUCCESS),
        Top::Warrant(w) => warrant(w).map(|()| ExitCode::SUCCESS),
        Top::Run(r) => run(r).await,
        Top::Reconcile(r) => reconcile(r).await,
        Top::Log(l) => log::command(l).map(|()| ExitCode::SUCCESS),
        Top::Approve(a) => approve::command(&a),
        Top::Reference(ReferenceCmd::Fetch { out, services }) => {
            approve::fetch_reference(&out, &services).map(|()| ExitCode::SUCCESS)
        }
        Top::VerifyReport {
            report,
            signature,
            key_id,
        } => verify_report(&report, &signature, &key_id).map(|()| ExitCode::SUCCESS),
    };
    match outcome {
        Ok(code) => code,
        Err(message) => {
            eprintln!("remit: {message}");
            ExitCode::FAILURE
        }
    }
}
