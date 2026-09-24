//! `remit`: keys, warrants, delegation, and `remit run`.
//!
//! `remit run` verifies a warrant chain against trusted roots, obtains an STS session
//! stamped with the leaf warrant's identifier (SPEC section 8.1), and runs a command with
//! those credentials and no other: every other place an AWS SDK looks for credentials is
//! closed in the child's environment, so it cannot fall back to the broker's own.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn read_seed(path: &Path) -> Result<IssuerKey> {
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
    Ok(IssuerKey::from_seed(&seed))
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
        "remit: warrant {} for {}, {} s",
        plan.warrant_id, plan.subject, plan.duration_seconds
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
    };
    match outcome {
        Ok(code) => code,
        Err(message) => {
            eprintln!("remit: {message}");
            ExitCode::FAILURE
        }
    }
}
