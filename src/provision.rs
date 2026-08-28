//! `dove provision` — stand up the simple-tier share bucket from your machine,
//! using the `aws` CLI so it rides your existing credentials/SSO. It creates a
//! private bucket (all public access blocked) with a lifecycle rule that
//! auto-deletes objects after a ceiling of days, mints a **least-privilege IAM
//! user** scoped to just this bucket, and stores that user's key so `share`
//! signs with it — never your full account credentials, and with a long-term
//! key so presigned links get their full requested lifetime.

use crate::config::Config;
use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
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
    if matches!(args.tier, Tier::Full) {
        bail!(
            "the full tier (encryption, download limits, custom domain) isn't built yet — \
             see https://dove.sh. Use `dove provision simple` for now."
        );
    }
    if !have_aws() {
        bail!("the AWS CLI (`aws`) is required for provisioning — https://aws.amazon.com/cli/");
    }

    ui::heading("dove provision · simple tier");

    // The only thing dove asks: which profile. Everything else is derived.
    let profile = match &args.profile {
        Some(p) => Some(p.clone()),
        None => choose_profile()?,
    };
    let (account, arn) = caller_identity(profile.as_deref()).with_context(|| {
        format!(
            "resolving the AWS identity for {} — is it logged in (e.g. `aws sso login`)?",
            profile.as_deref().unwrap_or("the default profile")
        )
    })?;

    // Derive a unique bucket from the account id, unless overridden.
    let bucket = args
        .bucket
        .clone()
        .unwrap_or_else(|| format!("dove-shares-{account}"));

    ui::field("account", &account);
    ui::field("identity", &arn);
    ui::field("bucket", &format!("{bucket}  ({})", args.region));
    if !confirm("proceed?")? {
        bail!("aborted");
    }
    eprintln!();

    // 1. Create the bucket. us-east-1 must NOT get a LocationConstraint.
    let mut create = vec!["s3api", "create-bucket", "--bucket", &bucket];
    let lc = format!("LocationConstraint={}", args.region);
    if args.region != "us-east-1" {
        create.push("--region");
        create.push(&args.region);
        create.push("--create-bucket-configuration");
        create.push(&lc);
    }
    ui::step("creating bucket", || {
        aws_ok(profile.as_deref(), &create, &["BucketAlreadyOwnedByYou"])
    })?;

    // 2. Block ALL public access — shares are reached by presigned URL only.
    ui::step("blocking public access", || {
        aws_ok(
            profile.as_deref(),
            &[
                "s3api",
                "put-public-access-block",
                "--bucket",
                &bucket,
                "--public-access-block-configuration",
                PUBLIC_ACCESS_BLOCK,
            ],
            &[],
        )
    })?;

    // 3. Lifecycle: auto-delete objects after the ceiling of days.
    let lifecycle = lifecycle_config(args.expire_days);
    ui::step(&format!("lifecycle · {} days", args.expire_days), || {
        aws_ok(
            profile.as_deref(),
            &[
                "s3api",
                "put-bucket-lifecycle-configuration",
                "--bucket",
                &bucket,
                "--lifecycle-configuration",
                &lifecycle,
            ],
            &[],
        )
    })?;

    // 4. A least-privilege IAM user dove signs share links with — so links
    //    aren't signed with your full account creds, and (crucially) their
    //    expiry isn't capped by an SSO session's lifetime. Same name as the
    //    bucket, different namespace.
    let iam_user = bucket.clone();
    ui::step("scoped IAM user", || {
        aws_ok(
            profile.as_deref(),
            &["iam", "create-user", "--user-name", &iam_user],
            &["EntityAlreadyExists"],
        )
    })?;
    ui::step("least-privilege policy", || {
        let policy = share_policy(&bucket);
        aws_ok(
            profile.as_deref(),
            &[
                "iam",
                "put-user-policy",
                "--user-name",
                &iam_user,
                "--policy-name",
                "dove-share",
                "--policy-document",
                &policy,
            ],
            &[],
        )
    })?;
    // Mint a key only if we don't already have one — a re-provision reuses it
    // (an IAM user can hold at most two keys; don't orphan the old one).
    if crate::secrets::Secrets::exists() {
        ui::step("access key (reusing)", || Ok(()))?;
    } else {
        ui::step("minting access key", || {
            let out = aws(
                profile.as_deref(),
                &[
                    "iam",
                    "create-access-key",
                    "--user-name",
                    &iam_user,
                    "--output",
                    "json",
                ],
            )?;
            if !out.status.success() {
                bail!(
                    "creating access key: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            let (id, secret) = parse_access_key(&out.stdout)?;
            crate::secrets::Secrets {
                access_key_id: id,
                secret_access_key: secret,
            }
            .save()
        })?;
    }

    Config {
        bucket,
        region: args.region.clone(),
        profile,
        endpoint: None,
        table: None,
        gate_url: None,
    }
    .save()?;

    ui::done(
        "provisioned",
        &format!(
            "dove share <file> is ready — objects auto-delete after {} days",
            args.expire_days
        ),
    );
    Ok(())
}

/// All four public-access-block switches on.
const PUBLIC_ACCESS_BLOCK: &str = "BlockPublicAcls=true,IgnorePublicAcls=true,\
     BlockPublicPolicy=true,RestrictPublicBuckets=true";

/// The lifecycle configuration JSON: expire every object `days` after creation.
pub fn lifecycle_config(days: u32) -> String {
    format!(
        r#"{{"Rules":[{{"ID":"dove-expire","Status":"Enabled","Filter":{{}},"Expiration":{{"Days":{days}}}}}]}}"#
    )
}

/// The least-privilege IAM policy dove's signing user gets: read/write/delete
/// objects and list — scoped to this one bucket, nothing else in the account.
pub fn share_policy(bucket: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::{bucket}/*"}},{{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":"arn:aws:s3:::{bucket}"}}]}}"#
    )
}

/// Extract `(AccessKeyId, SecretAccessKey)` from `iam create-access-key` JSON.
pub fn parse_access_key(json_bytes: &[u8]) -> Result<(String, String)> {
    let json: serde_json::Value =
        serde_json::from_slice(json_bytes).context("parsing create-access-key output")?;
    let key = json
        .get("AccessKey")
        .ok_or_else(|| anyhow!("create-access-key output missing AccessKey"))?;
    let id = key
        .get("AccessKeyId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("create-access-key output missing AccessKeyId"))?;
    let secret = key
        .get("SecretAccessKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("create-access-key output missing SecretAccessKey"))?;
    Ok((id.to_string(), secret.to_string()))
}

fn have_aws() -> bool {
    Command::new("aws")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

fn caller_identity(profile: Option<&str>) -> Result<(String, String)> {
    let out = aws(profile, &["sts", "get-caller-identity", "--output", "json"])?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let account = v["Account"].as_str().unwrap_or("?").to_string();
    let arn = v["Arn"].as_str().unwrap_or("?").to_string();
    Ok((account, arn))
}

fn confirm(prompt: &str) -> Result<bool> {
    eprint!("  {} {} ", ui::dim(prompt), ui::dim("[y/N] →"));
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// Run `aws [--profile P] <args>`, returning the raw output.
fn aws(profile: Option<&str>, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new("aws");
    if let Some(p) = profile {
        cmd.args(["--profile", p]);
    }
    cmd.args(args)
        .output()
        .map_err(|e| anyhow!("running aws {}: {e}", args.join(" ")))
}

/// Run an `aws` call that must succeed, tolerating stderr substrings in
/// `tolerate` (idempotent re-runs — e.g. the bucket already exists).
fn aws_ok(profile: Option<&str>, args: &[&str], tolerate: &[&str]) -> Result<()> {
    let out = aws(profile, args)?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if tolerate.iter().any(|t| stderr.contains(t)) {
        return Ok(());
    }
    bail!("aws {} failed: {}", args.join(" "), stderr.trim());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_expires_after_the_given_days() {
        let lc = lifecycle_config(7);
        assert!(lc.contains("\"Days\":7"));
        assert!(lc.contains("\"Status\":\"Enabled\""));
        assert!(lc.contains("\"Expiration\""));
    }

    #[test]
    fn share_policy_is_scoped_to_the_one_bucket() {
        let p = share_policy("dove-shares-123");
        assert!(p.contains("s3:PutObject"));
        assert!(p.contains("s3:GetObject"));
        assert!(p.contains("s3:DeleteObject"));
        assert!(p.contains("s3:ListBucket"));
        assert!(p.contains("arn:aws:s3:::dove-shares-123/*"));
        assert!(p.contains("arn:aws:s3:::dove-shares-123\""));
        // No account-wide grant.
        assert!(!p.contains("\"Resource\":\"*\""));
    }

    #[test]
    fn parse_access_key_extracts_id_and_secret() {
        let json =
            br#"{"AccessKey":{"AccessKeyId":"AKIA1","SecretAccessKey":"shh","Status":"Active"}}"#;
        let (id, secret) = parse_access_key(json).unwrap();
        assert_eq!(id, "AKIA1");
        assert_eq!(secret, "shh");
    }

    #[test]
    fn public_access_block_turns_everything_on() {
        for k in [
            "BlockPublicAcls=true",
            "IgnorePublicAcls=true",
            "BlockPublicPolicy=true",
            "RestrictPublicBuckets=true",
        ] {
            assert!(PUBLIC_ACCESS_BLOCK.contains(k), "missing {k}");
        }
    }
}
