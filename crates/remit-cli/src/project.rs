//! `remit init` and `remit task`: Remit set up for a project in one command, and one command
//! per task (docs/GETTING-STARTED.md).
//!
//! Everything lives in the project's `.remit/`: the agent's key, a log with a local witness
//! and the trust policy that names them, a copy of the AWS role template, and every warrant
//! issued with its proof under `warrants/`. `current.chain` and `current.proof` are the
//! warrant the agent works under now; `remit mcp` reads them on every call, so a new task
//! needs no restart. The issuing key is the person's and is kept outside the project
//! (`~/.config/remit/root.key` by default), where the agent should not be able to read it:
//! an agent that can read the key can sign its own warrants.

use std::path::{Path, PathBuf};

use clap::Args;
use remit_core::{IssuerKey, encode_chain};

use crate::log::{self, Kind, LogKeyArgs, WitnessArgs};
use crate::{GrantArgs, Result, build, describe, new_key, read_seed, write_new};

/// The role template, shipped inside the binary so a project needs no clone of the repository.
const ROLE_TEMPLATE: &str = include_str!("../../../deploy/aws/role.yaml");

#[derive(Args)]
pub(crate) struct InitArgs {
    /// Where the project's Remit state goes.
    #[arg(long, default_value = ".remit")]
    dir: PathBuf,
    /// The person's issuing key: made if absent, used as it is if present, never overwritten.
    /// Default: `$XDG_CONFIG_HOME/remit/root.key`, else `~/.config/remit/root.key`.
    #[arg(long)]
    root_key: Option<PathBuf>,
    /// The log's name (its origin). Default: `remit.local/` and the project directory's name.
    #[arg(long)]
    origin: Option<String>,
}

#[derive(Args)]
pub(crate) struct TaskArgs {
    /// The project's Remit state, as `remit init` made it.
    #[arg(long, default_value = ".remit")]
    dir: PathBuf,
    /// The person's issuing key (the same default as `remit init`).
    #[arg(long)]
    root_key: Option<PathBuf>,
    /// `ACTIONS=RESOURCES`, each a comma-separated list of patterns; repeat for more grants.
    #[arg(long = "grant", required = true)]
    grants: Vec<String>,
    /// How long the warrant lasts from now: seconds, or a number followed by s, m, h or d.
    #[arg(long = "for", value_parser = parse_duration)]
    valid_for: u64,
    /// Why, in words. Recorded in the warrant and the log, not enforced.
    #[arg(long)]
    purpose: String,
    /// Issue even if a grant lets work escape the warrant; see `remit warrant issue`.
    #[arg(long)]
    allow_escape: bool,
}

fn default_root_key() -> Result<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })
        .ok_or("neither XDG_CONFIG_HOME nor HOME is set; give --root-key")?;
    Ok(config.join("remit").join("root.key"))
}

/// `remit.local/` and the directory's name, kept to characters a log origin can carry.
fn default_origin() -> Result<String> {
    let cwd = std::env::current_dir().map_err(|e| format!("current directory: {e}"))?;
    let name: String = cwd
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches('-');
    Ok(format!(
        "remit.local/{}",
        if name.is_empty() { "project" } else { name }
    ))
}

fn witness_name(origin: &str) -> String {
    format!("{origin}/witness")
}

fn absolute(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Makes the issuing key if it is missing, in a directory only its owner can read.
fn issuing_key(path: &Path) -> Result<(IssuerKey, bool)> {
    if path.exists() {
        return Ok((read_seed(path)?, false));
    }
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    Ok((new_key(path)?, true))
}

/// `remit init`.
pub(crate) fn init(a: &InitArgs) -> Result<()> {
    let d = &a.dir;
    if d.read_dir()
        .is_ok_and(|mut entries| entries.next().is_some())
    {
        return Err(format!(
            "{} already holds Remit state; issue a warrant with `remit task`, or choose another --dir",
            d.display()
        ));
    }
    std::fs::create_dir_all(d.join("warrants")).map_err(|e| format!("{}: {e}", d.display()))?;
    let root_path = a.root_key.clone().map_or_else(default_root_key, Ok)?;
    let (root, made) = issuing_key(&root_path)?;
    let agent = new_key(&d.join("agent.key"))?;
    new_key(&d.join("log.key"))?;
    new_key(&d.join("witness.key"))?;
    let origin = a.origin.clone().map_or_else(default_origin, Ok)?;
    log::create(&d.join("log"), &d.join("log.key"), &origin)?;
    let policy = format!(
        "log {}\nwitness {}\nquorum 1\n",
        log::vkey(&d.join("log.key"), &origin, Kind::Log)?,
        log::vkey(
            &d.join("witness.key"),
            &witness_name(&origin),
            Kind::Witness
        )?
    );
    write_new(&d.join("log.policy"), policy.as_bytes())?;
    write_new(&d.join("origin"), format!("{origin}\n").as_bytes())?;
    write_new(&d.join("role.yaml"), ROLE_TEMPLATE.as_bytes())?;
    write_new(
        &d.join(".gitignore"),
        b"# Keys never leave this machine; the log, the warrants and the policy may.\n*.key\n# Working files: the log's writer lock and a warrant being swapped in.\nlog/.lock\n*.new\n",
    )?;

    let here = absolute(d)?;
    let root_note = if made {
        "made"
    } else {
        "already there, used as it is"
    };
    println!("Remit is set up in {}.", here.display());
    println!();
    println!("  your issuing key   {} ({root_note})", root_path.display());
    println!("                     {}", root.id());
    println!("  the agent's key    {}", agent.id());
    println!("  the log            {origin}, with one local witness");
    println!();
    println!("This setup is for trying Remit on one machine. Here the agent runs as you, so the");
    println!("issuing key, the log and the broker's credentials are all within its reach: Remit's");
    println!("checks guide it, but cannot bind an agent that tries to get around them. For real");
    println!("use, run the broker as a service, reconcile elsewhere, and give the agent a system");
    println!("of its own: docs/PRODUCTION.md.");
    println!();
    println!("Next:");
    println!();
    // Claude Code reads a rule path with one leading slash as relative to the settings file;
    // an absolute path takes two (code.claude.com/docs/en/permissions).
    let rule_path = format!("/{}", absolute(&root_path)?.display());
    println!("1. Keep the agent away from your issuing key: an agent that can read it can sign");
    println!(
        "   its own warrants. In Claude Code, add to \"permissions\" in ~/.claude/settings.json:"
    );
    println!("     \"deny\": [\"Read({rule_path})\", \"Edit({rule_path})\"]");
    println!("   Those rules stop Claude Code's own tools and commands such as cat; they do not");
    println!("   stop a script that opens the file itself. For that, enable Claude Code's sandbox");
    println!("   or keep the key on another machine.");
    println!();
    println!("2. Once per AWS account, with administrator rights, deploy the role the broker");
    println!("   assumes (read-only ceiling; see the template for others):");
    println!("     aws cloudformation deploy --stack-name remit-agent-readonly \\");
    println!(
        "       --template-file {} \\",
        here.join("role.yaml").display()
    );
    println!("       --capabilities CAPABILITY_NAMED_IAM \\");
    println!("       --parameter-overrides BrokerPrincipalArn=<the broker's IAM user or role ARN>");
    println!();
    println!("3. For each task, sign a warrant for exactly what it needs:");
    println!("     remit task --grant 's3:ListBucket=arn:aws:s3:::my-bucket' --for 1h \\");
    println!("       --purpose \"why the agent needs it\"");
    println!();
    println!("4. Point the agent at the current warrant (Claude Code plugin settings, or any");
    println!("   MCP client running `remit mcp` with these values):");
    println!("     chain       {}", here.join("current.chain").display());
    println!("     root        {}", root.id());
    println!("     role        arn:aws:iam::<account>:role/remit-agent-readonly");
    println!("     log_policy  {}", here.join("log.policy").display());
    println!("     log_proof   {}", here.join("current.proof").display());
    println!();
    println!("The local witness shows the mechanism; it does not protect against whoever runs");
    println!("this machine. Add independent witnesses before relying on the log.");
    Ok(())
}

/// `remit task`.
pub(crate) fn task(a: TaskArgs) -> Result<()> {
    let d = &a.dir;
    let origin_path = d.join("origin");
    let origin = std::fs::read_to_string(&origin_path)
        .map_err(|e| format!("{}: {e} (run `remit init` first)", origin_path.display()))?
        .trim()
        .to_owned();
    let root_path = a.root_key.clone().map_or_else(default_root_key, Ok)?;
    let root = read_seed(&root_path)?;
    let agent = read_seed(&d.join("agent.key"))?;
    let g = GrantArgs {
        grants: a.grants,
        valid_for: a.valid_for,
        starts_at: None,
        purpose: a.purpose,
        max_depth: 0,
        allow_escape: a.allow_escape,
    };
    let w = build(&root, agent.id().as_str(), &g, None)?;
    let signed = root.sign(&w).map_err(|e| e.to_string())?;
    let id = w.id().as_str().to_owned();
    let chain = d.join("warrants").join(format!("{id}.chain"));
    let proof = d.join("warrants").join(format!("{id}.proof"));
    write_new(&chain, &encode_chain(&[signed]))?;
    log::append_chain(
        LogKeyArgs::new(d.join("log"), d.join("log.key"), origin.clone()),
        chain.clone(),
        WitnessArgs::local(
            d.join("witness.key"),
            witness_name(&origin),
            d.join("witness.state"),
        ),
    )?;
    log::prove(&d.join("log"), &d.join("log.policy"), &chain, &proof)?;
    // Replaced whole, by rename, so `remit mcp` never reads half a file. A call that reads
    // the new chain with the old proof fails verification and is refused: closed, not open.
    replace(&proof, &d.join("current.proof"))?;
    replace(&chain, &d.join("current.chain"))?;
    print!("{}", describe(&w));
    println!("logged and proven; the agent works under {id} from its next call");
    Ok(())
}

fn replace(from: &Path, to: &Path) -> Result<()> {
    let tmp = to.with_extension("new");
    std::fs::copy(from, &tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, to).map_err(|e| format!("{}: {e}", to.display()))
}

/// Seconds, or a positive number followed by `s`, `m`, `h` or `d`.
fn parse_duration(text: &str) -> std::result::Result<u64, String> {
    let (number, unit) = [('d', 86_400), ('h', 3_600), ('m', 60), ('s', 1)]
        .iter()
        .find_map(|&(suffix, unit)| text.strip_suffix(suffix).map(|n| (n, unit)))
        .unwrap_or((text, 1));
    number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(unit))
        .filter(|&s| s > 0)
        .ok_or_else(|| format!("{text:?}: expected seconds, or a number followed by s, m, h or d"))
}

#[cfg(test)]
mod tests {
    use super::parse_duration;

    #[test]
    fn durations_are_seconds_or_a_number_with_a_unit() {
        assert_eq!(parse_duration("90"), Ok(90));
        assert_eq!(parse_duration("90s"), Ok(90));
        assert_eq!(parse_duration("30m"), Ok(1_800));
        assert_eq!(parse_duration("1h"), Ok(3_600));
        assert_eq!(parse_duration("2d"), Ok(172_800));
        for bad in [
            "",
            "0",
            "0h",
            "h",
            "1.5h",
            "-1h",
            "1w",
            "1 h",
            "18446744073709551615d",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad:?} was accepted");
        }
    }
}
