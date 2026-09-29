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

mod anchor;
mod approve;
mod hook;
mod log;
mod mcp;
mod project;
mod trail;

use clap::{Args, Parser, Subcommand};
use remit_core::{
    IssuerKey, KeyId, SignedWarrant, Warrant, WarrantSpec, check_attenuation, decode_chain,
    encode_chain, escapes, verify_chain,
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
    /// Set Remit up for this project: keys, a witnessed log and its trust policy, and the
    /// AWS role template (docs/GETTING-STARTED.md).
    Init(project::InitArgs),
    /// Issue a warrant for one task, log it, prove it, and make it the agent's current one.
    Task(project::TaskArgs),
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
    /// Run a witness (tlog-witness over HTTP) that cosigns only consistent checkpoints.
    #[command(subcommand)]
    Witness(WitnessCmd),
    /// Serve the Model Context Protocol over stdio: warrant, check and run tools (ADR 0009).
    Mcp(mcp::McpArgs),
    /// Agent-framework hooks: the plugin's guide rail against direct cloud CLIs (ADR 0009).
    #[command(subcommand)]
    Hook(HookCmd),
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

#[derive(Subcommand)]
enum HookCmd {
    /// A Claude Code `PreToolUse` event on stdin; denies a shell command that starts a cloud
    /// CLI directly, so the agent uses `remit_run`.
    PreToolUse,
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
    /// A local copy of the trail's S3 bucket (its `AWSLogs/...` keys as paths): events come
    /// from validated log files instead of event history (SPEC 6.7).
    #[arg(long, requires_all = ["trail_bucket", "trail_keys", "trail_signatures"])]
    trail_dir: Option<PathBuf>,
    /// The bucket the copy was taken from, as its digests record it.
    #[arg(long)]
    trail_bucket: Option<String>,
    /// CloudTrail's public keys: the JSON of `aws cloudtrail list-public-keys`.
    #[arg(long)]
    trail_keys: Option<PathBuf>,
    /// The newest digests' signatures from their S3 metadata: a JSON object mapping each
    /// digest's key to its `x-amz-meta-signature`.
    #[arg(long)]
    trail_signatures: Option<PathBuf>,
    /// The reconciler's seed file, which signs the report.
    #[arg(long)]
    key: PathBuf,
    /// Where to write the report; the signature goes beside it as `<out>.sig`.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Subcommand)]
enum WitnessCmd {
    /// Serve until interrupted.
    Serve(log::WitnessServeArgs),
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
    /// Issue even if a grant reaches an action that lets work escape the warrant
    /// (another role, lasting credentials, IAM or resource policy changes, code that runs
    /// later); refused without it.
    #[arg(long)]
    allow_escape: bool,
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
        /// Also print the AWS session policy compiled from the leaf warrant (SPEC 8.2),
        /// exactly as the broker would pass it, and its length against AWS's 2,048.
        #[arg(long)]
        session_policy: bool,
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
    let w = Warrant::new(&WarrantSpec {
        issuer: issuer.id().as_str(),
        subject,
        purpose: &g.purpose,
        not_before: start,
        not_after: start.saturating_add(g.valid_for),
        grants: &refs,
        parent: parent.map(Warrant::id),
        max_depth: g.max_depth,
    })
    .map_err(|e| e.to_string())?;
    // A delegated warrant can only narrow its parent, so the choice was made at the root.
    let found = escapes(&w);
    if parent.is_none() && !found.is_empty() {
        let mut why = String::from("refused: these grants let work escape the warrant:\n");
        for (i, action, reason) in &found {
            let _ = writeln!(
                why,
                "  grant {}: {action} {}",
                i.saturating_add(1),
                reason.reason()
            );
        }
        if !g.allow_escape {
            why.push_str(
                "The warrant bounds the call that does this, not what happens after it.\n\
                 Narrow the grant, or pass --allow-escape if the role's own permissions are \
                 the bound you mean to rely on.",
            );
            return Err(why);
        }
        eprint!("{}", why.replacen("refused: ", "issued although ", 1));
    }
    Ok(w)
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

/// What `remit run` and the MCP server's `remit_run` both need before a command may start.
pub(crate) struct SessionArgs<'a> {
    pub chain: &'a Path,
    pub roots: &'a [String],
    pub role: &'a str,
    pub role_max_seconds: u64,
    pub log_policy: &'a Path,
    pub log_proof: &'a Path,
    pub region: Option<&'a str>,
}

/// A verified, logged session: the leaf warrant's plan, its STS credentials, the region.
pub(crate) struct Session {
    pub plan: remit_broker::SessionPlan,
    pub creds: remit_broker::SessionCredentials,
    pub region: String,
    pub logged_origin: String,
    pub logged_size: u64,
}

/// Verifies the chain, that every link is proven logged (SPEC 9.3), and obtains an STS
/// session stamped with the leaf warrant's identifier (SPEC 8.1). Nothing reaches AWS
/// unless the chain verifies and is logged.
pub(crate) async fn open_session(a: &SessionArgs<'_>) -> Result<Session> {
    let chain = read_chain(a.chain)?;
    let plan = remit_broker::plan(&chain, &roots(a.roots)?, now(), a.role_max_seconds)
        .map_err(|e| format!("refused: {e}"))?;
    let logged = log::verify_logged(a.log_policy, a.chain, a.log_proof)
        .map_err(|e| format!("refused: {e}"))?;
    // A machine with no configured region is common; STS still needs one, and the command
    // should run in the same one (found on the first live session, 2026-09-24).
    let chain_of_regions = aws_config::meta::region::RegionProviderChain::first_try(
        a.region.map(|r| aws_config::Region::new(r.to_owned())),
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
    let creds = remit_broker::assume(&sts, a.role, &plan)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Session {
        plan,
        creds,
        region,
        logged_origin: logged.checkpoint.origin().to_owned(),
        logged_size: logged.checkpoint.size(),
    })
}

/// The child's environment: every other credential source closed (`CLOSED` removed, the
/// shared files pointed at nothing), and only the session's credentials set.
pub(crate) fn session_env(s: &Session) -> Vec<(&'static str, String)> {
    vec![
        // The shared files hold the broker's own credentials; the child sees none of them.
        ("AWS_SHARED_CREDENTIALS_FILE", "/dev/null".to_owned()),
        ("AWS_CONFIG_FILE", "/dev/null".to_owned()),
        ("AWS_EC2_METADATA_DISABLED", "true".to_owned()),
        ("AWS_ACCESS_KEY_ID", s.creds.access_key_id.clone()),
        ("AWS_SECRET_ACCESS_KEY", s.creds.secret_access_key.clone()),
        ("AWS_SESSION_TOKEN", s.creds.session_token.clone()),
        ("AWS_REGION", s.region.clone()),
        ("REMIT_WARRANT_ID", s.plan.warrant_id.as_str().to_owned()),
    ]
}

async fn run(args: RunArgs) -> Result<ExitCode> {
    let session = open_session(&SessionArgs {
        chain: &args.chain,
        roots: &args.roots,
        role: &args.role,
        role_max_seconds: args.role_max_seconds,
        log_policy: &args.log_policy,
        log_proof: &args.log_proof,
        region: args.region.as_deref(),
    })
    .await?;
    eprintln!(
        "remit: warrant {} for {}, {} s; logged in {} at size {}",
        session.plan.warrant_id,
        session.plan.subject,
        session.plan.duration_seconds,
        session.logged_origin,
        session.logged_size
    );

    let (program, rest) = args.command.split_first().ok_or("no command")?;
    let mut cmd = Command::new(program);
    cmd.args(rest);
    for var in CLOSED {
        cmd.env_remove(var);
    }
    cmd.envs(session_env(&session));
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

/// The events of the window: from validated trail files when a local copy is given
/// (SPEC 6.7), otherwise from CloudTrail event history; with any record problems and the
/// coverage the trail established.
async fn gather_events(
    args: &ReconcileArgs,
    config: &aws_config::SdkConfig,
    from: u64,
    to: u64,
) -> Result<(
    Vec<remit_reconcile::Event>,
    remit_reconcile::EventSource,
    Vec<String>,
    Vec<remit_reconcile::trail::Coverage>,
)> {
    let mut events = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut record_problems = Vec::new();
    let mut coverage = Vec::new();
    let source = if let (Some(dir), Some(bucket), Some(keys), Some(sigs)) = (
        &args.trail_dir,
        &args.trail_bucket,
        &args.trail_keys,
        &args.trail_signatures,
    ) {
        // Delivered from the window's start to its end plus the settling period.
        let need_to = to.saturating_add(args.settle_seconds);
        let local = trail::load(dir, bucket, keys, sigs)?;
        let v = remit_reconcile::trail::validate(
            &local.digests,
            &local.logs,
            &local.keys,
            &args.regions,
            from,
            need_to,
        );
        for r in &v.records {
            let e = remit_reconcile::Event::from_json(r).map_err(|e| e.to_string())?;
            if e.time >= from && e.time <= to && seen.insert(e.id.clone()) {
                events.push(e);
            }
        }
        eprintln!(
            "remit: validated trail: {} digests, {} log files, {} problems",
            v.coverage.iter().map(|c| c.digests).sum::<usize>(),
            v.coverage.iter().map(|c| c.log_files).sum::<usize>(),
            v.problems.len()
        );
        record_problems = v.problems;
        coverage = v.coverage;
        remit_reconcile::EventSource::ValidatedTrail
    } else {
        for region in &args.regions {
            for e in fetch_events(config, region, from, to).await? {
                if seen.insert(e.id.clone()) {
                    events.push(e);
                }
            }
        }
        remit_reconcile::EventSource::EventHistory
    };

    Ok((events, source, record_problems, coverage))
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

    let (events, source, record_problems, coverage) =
        gather_events(&args, &config, from, to).await?;

    let mut report = remit_reconcile::reconcile(&remit_reconcile::Input {
        warrants: &warrants,
        roles: &roles,
        events: &events,
        from,
        to,
        now: now(),
        settle_seconds: args.settle_seconds,
        source,
        regions: &args.regions,
        record_problems: &record_problems,
    });
    report.refused_inputs = refused;
    report.record_coverage = coverage;
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

/// A key from the operating system's secure random source, written as a new file (never
/// over an existing one).
fn new_key(out: &Path) -> Result<IssuerKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("random source: {e}"))?;
    let hex = seed.iter().fold(String::with_capacity(65), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    write_new(out, format!("{hex}\n").as_bytes())?;
    Ok(IssuerKey::from_seed(&seed))
}

fn key(cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::New { out } => println!("{}", new_key(&out)?.id()),
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
        WarrantCmd::Show {
            chain,
            roots: ids,
            session_policy,
        } => {
            let links = read_chain(&chain)?;
            for l in &links {
                print!("{}", describe(l.warrant()));
            }
            if session_policy {
                let leaf = links.last().ok_or("empty chain")?.warrant();
                match remit_aws::compile_session_policy(leaf) {
                    Ok(policy) => println!(
                        "session policy ({} of 2048 characters):\n{policy}",
                        policy.len()
                    ),
                    Err(e) => return Err(format!("does not compile to a session policy: {e}")),
                }
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

/// A reader that stops early (`remit warrant show | head -1`) closes the pipe, and Rust's
/// `println!` then panics. Exit the way a Unix tool killed by SIGPIPE does, status 141,
/// silently, instead of printing a panic. Any other panic is reported as before.
fn quiet_when_the_reader_leaves() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        if message.starts_with("failed printing to std") && message.contains("Broken pipe") {
            std::process::exit(141);
        }
        report(info);
    }));
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    quiet_when_the_reader_leaves();
    let outcome = match Cli::parse().command {
        Top::Init(a) => project::init(&a).map(|()| ExitCode::SUCCESS),
        Top::Task(a) => project::task(a).map(|()| ExitCode::SUCCESS),
        Top::Key(k) => key(k).map(|()| ExitCode::SUCCESS),
        Top::Warrant(w) => warrant(w).map(|()| ExitCode::SUCCESS),
        Top::Run(r) => run(r).await,
        Top::Reconcile(r) => reconcile(r).await,
        Top::Log(l) => log::command(l).map(|()| ExitCode::SUCCESS),
        Top::Witness(WitnessCmd::Serve(a)) => {
            log::serve_witness(a).await.map(|()| ExitCode::SUCCESS)
        }
        Top::Approve(a) => approve::command(&a),
        Top::Mcp(a) => mcp::serve(a).await.map(|()| ExitCode::SUCCESS),
        Top::Hook(HookCmd::PreToolUse) => hook::pre_tool_use().map(|()| ExitCode::SUCCESS),
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

#[cfg(test)]
mod plugin_tests {
    //! The agent plugin (`integrations/claude-plugin/`) launches this binary; these keep its
    //! command lines and this CLI from drifting apart.

    use super::{Cli, HookCmd, Top};
    use clap::Parser;
    use serde_json::Value;

    fn plugin_file(rel: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../integrations/claude-plugin")
            .join(rel);
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn argv(command: &Value, args: &Value) -> Vec<String> {
        let mut out = vec![command.as_str().unwrap_or_default().to_owned()];
        out.extend(
            args.as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
        out
    }

    #[test]
    fn the_plugins_mcp_server_line_is_a_valid_remit_mcp_invocation() {
        let manifest = plugin_file(".claude-plugin/plugin.json");
        let server = &manifest["mcpServers"]["remit"];
        let line = argv(&server["command"], &server["args"]);
        assert_eq!(line.first().map(String::as_str), Some("remit"));
        let parsed = Cli::try_parse_from(&line).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(parsed.command, Top::Mcp(_)));
        // Every ${user_config.KEY} the server line uses is declared, and every required
        // option is used.
        let config = manifest["userConfig"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for word in &line {
            if let Some(key) = word
                .strip_prefix("${user_config.")
                .and_then(|w| w.strip_suffix('}'))
            {
                assert!(config.contains_key(key), "undeclared option {key}");
            }
        }
        for (key, spec) in &config {
            if spec["required"] == true {
                assert!(
                    line.contains(&format!("${{user_config.{key}}}")),
                    "required option {key} is never used"
                );
            }
        }
    }

    #[test]
    fn the_plugins_hook_line_is_a_valid_remit_hook_invocation() {
        let hooks = plugin_file("hooks/hooks.json");
        let handler = &hooks["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(hooks["hooks"]["PreToolUse"][0]["matcher"], "Bash");
        let line = argv(&handler["command"], &handler["args"]);
        let parsed = Cli::try_parse_from(&line).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(parsed.command, Top::Hook(HookCmd::PreToolUse)));
    }
}
