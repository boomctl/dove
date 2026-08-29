//! `dove provision` — stand up the simple or full tier backend from your
//! machine, using the `aws` CLI so it rides your existing credentials/SSO.
//!
//! The actual AWS orchestration (create the bucket, block public access, set
//! the lifecycle rule, mint the scoped IAM user/key, and — full tier — the
//! gate's DynamoDB/Lambda/API Gateway/CloudFront/breaker) lives in
//! `dove_core::provision`; this module resolves the interactive bits dove-core
//! can't do itself (which AWS profile, and the "proceed?" confirmation),
//! drives a `CliProgress` through the call, and renders the result — the same
//! way `share`/`get`/`ls` render over `dove_core::backend::SelfHosted`.

use crate::cli_progress::CliProgress;
use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use dove_core::config::{Backend, Registry};
use dove_core::provision::{self, ProvisionArgs as CoreArgs};
use std::io::Write;
use std::process::Command;

/// Which tier to stand up. `full` is designed but not built yet.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum Tier {
    /// Just a bucket + auto-expiry: presigned links, ≤7 days, no servers.
    Simple,
    /// Encrypted, download-limited, optional custom domain. (Not built yet.)
    Full,
}

pub struct ProvisionArgs {
    pub tier: Tier,
    /// Override the derived bucket name (default `dove-shares-<account-id>`).
    pub bucket: Option<String>,
    pub region: String,
    pub profile: Option<String>,
    pub expire_days: u32,
}

pub fn run(args: &ProvisionArgs) -> Result<()> {
    if !provision::have_aws() {
        bail!("the AWS CLI (`aws`) is required for provisioning — https://aws.amazon.com/cli/");
    }
    let full = matches!(args.tier, Tier::Full);
    ui::heading(if full {
        "dove provision · full tier"
    } else {
        "dove provision · simple tier"
    });

    // The only thing dove asks: which profile. Everything else is derived.
    let profile = match &args.profile {
        Some(p) => Some(p.clone()),
        None => choose_profile()?,
    };
    let (account, arn) = provision::caller_identity(profile.as_deref()).with_context(|| {
        format!(
            "resolving the AWS identity for {} — is it logged in (e.g. `aws sso login`)?",
            profile.as_deref().unwrap_or("the default profile")
        )
    })?;
    let bucket = provision::derive_bucket(&account, args.bucket.as_deref());

    ui::field("account", &account);
    ui::field("identity", &arn);
    ui::field("bucket", &format!("{bucket}  ({})", args.region));
    if !confirm("proceed?")? {
        bail!("aborted");
    }
    eprintln!();

    let core_args = CoreArgs {
        bucket: args.bucket.clone(),
        region: args.region.clone(),
        expire_days: args.expire_days,
    };
    let existing = Registry::load()
        .ok()
        .and_then(|r| r.active_self_hosted().ok());
    let progress = CliProgress::new("provisioning");
    let result = if full {
        provision::provision_full(&core_args, profile.clone(), existing, &progress)
    } else {
        provision::provision_simple(&core_args, profile.clone(), &progress)
    };
    if result.is_err() {
        progress.fail_pending();
    }
    let cfg = result?;

    let mut reg = Registry::load().unwrap_or_default();
    reg.upsert(Backend::self_hosted("default", &cfg)?);
    reg.set_active("default")?;
    reg.save()?;

    match &cfg.gate_url {
        Some(url) => ui::done(
            "provisioned (full tier)",
            &format!("gate: {url}\n  `dove share <file>` now encrypts and gates downloads."),
        ),
        None => ui::done(
            "provisioned",
            &format!(
                "dove share <file> is ready — objects auto-delete after {} days",
                args.expire_days
            ),
        ),
    }
    Ok(())
}

/// Configured profile names, via `aws configure list-profiles`.
fn list_profiles() -> Result<Vec<String>> {
    let out = Command::new("aws")
        .args(["configure", "list-profiles"])
        .output()
        .map_err(|e| anyhow!("running aws configure list-profiles: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Pick an AWS profile interactively (or `None` for the default chain).
fn choose_profile() -> Result<Option<String>> {
    let profiles = list_profiles().unwrap_or_default();
    if profiles.is_empty() {
        return Ok(None); // default credential chain
    }
    eprintln!("  {}", ui::dim("which AWS profile?"));
    for (i, p) in profiles.iter().enumerate() {
        eprintln!("    {}  {}", ui::bold(&(i + 1).to_string()), p);
    }
    eprintln!(
        "    {}  {}",
        ui::dim("0"),
        ui::dim("default credential chain")
    );
    eprint!("  {} ", ui::dim("→"));
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let n: usize = line
        .trim()
        .parse()
        .ok()
        .filter(|n| *n <= profiles.len())
        .ok_or_else(|| anyhow!("not a valid choice: {:?}", line.trim()))?;
    eprintln!();
    Ok(if n == 0 {
        None
    } else {
        Some(profiles[n - 1].clone())
    })
}

fn confirm(prompt: &str) -> Result<bool> {
    eprint!("  {} {} ", ui::dim(prompt), ui::dim("[y/N] →"));
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}
