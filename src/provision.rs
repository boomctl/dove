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
    if !have_aws() {
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
                gate_secret: None,
            }
            .save()
        })?;
    }

    // 5. Full tier only: the gate (DynamoDB + Lambda + API Gateway + CloudFront).
    let prior_gate_url = Config::load().ok().and_then(|c| c.gate_url);
    let (table, gate_url, distribution_id) = if full {
        let infra = provision_full(profile.as_deref(), &account, &bucket, &args.region)?;
        // If a custom domain was already added (`dove domain add`), keep it —
        // don't revert to the *.cloudfront.net URL on a re-provision.
        let url = match prior_gate_url {
            Some(existing) if !existing.contains(".cloudfront.net") => existing,
            _ => infra.gate_url,
        };
        (Some(infra.table), Some(url), infra.distribution_id)
    } else {
        (None, None, None)
    };

    Config {
        bucket,
        region: args.region.clone(),
        profile,
        endpoint: None,
        table,
        gate_url: gate_url.clone(),
        distribution_id,
    }
    .save()?;

    match &gate_url {
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

/// The full tier's extra infrastructure, standing on the simple-tier bucket.
struct FullInfra {
    table: String,
    gate_url: String,
    distribution_id: Option<String>,
}

/// Provision the gate: DynamoDB (share policies) + the Lambda (role, function) +
/// API Gateway + CloudFront. Idempotent: re-running reuses existing resources
/// (API by name, distribution from the saved config).
fn provision_full(
    profile: Option<&str>,
    account: &str,
    bucket: &str,
    region: &str,
) -> Result<FullInfra> {
    let table = bucket.to_string(); // same name as the bucket, different namespace
    let name = format!("dove-gate-{account}"); // role + lambda share this name

    // Bucket CORS so the browser decryptor can read the ciphertext from the
    // presigned URL cross-origin (the gate 302s to S3; the fetch is cross-site).
    ui::step("bucket CORS", || {
        aws_ok(
            profile,
            &[
                "s3api",
                "put-bucket-cors",
                "--bucket",
                bucket,
                "--cors-configuration",
                BUCKET_CORS,
            ],
            &[],
        )
    })?;

    // DynamoDB table with TTL on expires_at (auto-cleanup of dead policies).
    ui::step("dynamodb table", || {
        aws_ok(
            profile,
            &[
                "dynamodb",
                "create-table",
                "--table-name",
                &table,
                "--attribute-definitions",
                "AttributeName=id,AttributeType=S",
                "--key-schema",
                "AttributeName=id,KeyType=HASH",
                "--billing-mode",
                "PAY_PER_REQUEST",
            ],
            &["ResourceInUseException"],
        )?;
        aws_ok(
            profile,
            &["dynamodb", "wait", "table-exists", "--table-name", &table],
            &[],
        )?;
        aws_ok(
            profile,
            &[
                "dynamodb",
                "update-time-to-live",
                "--table-name",
                &table,
                "--time-to-live-specification",
                "Enabled=true,AttributeName=expires_at",
            ],
            &["TimeToLive is already enabled"],
        )
    })?;

    // The gate's execution role.
    let role_arn = format!("arn:aws:iam::{account}:role/{name}");
    ui::step("gate IAM role", || {
        aws_ok(
            profile,
            &[
                "iam",
                "create-role",
                "--role-name",
                &name,
                "--assume-role-policy-document",
                LAMBDA_TRUST,
            ],
            &["EntityAlreadyExists"],
        )?;
        let policy = gate_role_policy(account, region, &table, bucket);
        aws_ok(
            profile,
            &[
                "iam",
                "put-role-policy",
                "--role-name",
                &name,
                "--policy-name",
                "dove-gate",
                "--policy-document",
                &policy,
            ],
            &[],
        )
    })?;

    // The gate secret — the HMAC key that mints/verifies unforgeable share ids.
    // Stable across re-provision (generated once, kept in secrets.toml). Stored in
    // SSM as a SecureString (encrypted, not readable from the function config);
    // the Lambda reads it at cold start. The env carries only the parameter name.
    let gate_secret = ensure_gate_secret()?;
    let secret_param = format!("/dove/{bucket}/gate-secret");
    ui::step("gate secret (SSM)", || {
        aws_ok(
            profile,
            &[
                "ssm",
                "put-parameter",
                "--name",
                &secret_param,
                "--value",
                &gate_secret,
                "--type",
                "SecureString",
                "--overwrite",
            ],
            &[],
        )
    })?;

    // The gate Lambda. A freshly-created role isn't assumable for a few seconds,
    // so retry create-function on that specific error.
    let zip = temp_path("zip");
    crate::gate::write_deployment_zip(&zip)?;
    let zip_arg = format!("fileb://{}", zip.display());
    let env =
        format!("Variables={{BUCKET={bucket},TABLE={table},GATE_SECRET_PARAM={secret_param}}}");
    let lambda_result = ui::step("gate Lambda", || {
        aws_retry(
            profile,
            &[
                "lambda",
                "create-function",
                "--function-name",
                &name,
                "--runtime",
                crate::gate::RUNTIME,
                "--handler",
                crate::gate::HANDLER,
                "--role",
                &role_arn,
                "--zip-file",
                &zip_arg,
                "--environment",
                &env,
                "--timeout",
                "30",
            ],
            &["ResourceConflictException"],
            "cannot be assumed",
            6,
        )?;
        // A freshly created function is 'Pending'/'Creating' and rejects code
        // updates until it's Active. Wait for that (best-effort — the retry below
        // is the real guard), then push the latest gate code + page. On a re-
        // provision this updates an existing function; on a fresh create it's a
        // no-op redeploy of the same code. The "cannot be performed at this time"
        // message covers every not-ready state (Creating / Pending / InProgress).
        let _ = aws(
            profile,
            &[
                "lambda",
                "wait",
                "function-active-v2",
                "--function-name",
                &name,
            ],
        );
        aws_retry(
            profile,
            &[
                "lambda",
                "update-function-code",
                "--function-name",
                &name,
                "--zip-file",
                &zip_arg,
            ],
            &[],
            "cannot be performed at this time",
            10,
        )?;
        // Let the code update settle before the config update.
        let _ = aws(
            profile,
            &[
                "lambda",
                "wait",
                "function-updated-v2",
                "--function-name",
                &name,
            ],
        );
        // Set the env (BUCKET/TABLE/GATE_SECRET_PARAM) — a fresh create already has it,
        // but a re-provision of an existing function needs it applied here.
        aws_retry(
            profile,
            &[
                "lambda",
                "update-function-configuration",
                "--function-name",
                &name,
                "--environment",
                &env,
            ],
            &[],
            "cannot be performed at this time",
            10,
        )?;
        let _ = aws(
            profile,
            &[
                "lambda",
                "wait",
                "function-updated-v2",
                "--function-name",
                &name,
            ],
        );
        Ok(())
    });
    let _ = std::fs::remove_file(&zip);
    lambda_result?;

    // Public front: API Gateway → Lambda, behind CloudFront. (Public Function URLs
    // don't work in every account; the API Gateway hop uses lambda:InvokeFunction,
    // which is universally allowed.)
    let function_arn = format!("arn:aws:lambda:{region}:{account}:function:{name}");
    let api = crate::apigw::provision_api(profile, region, account, &name, &function_arn)?;
    // Reuse an existing distribution on re-provision (from the saved config).
    let existing_dist = Config::load().ok().and_then(|c| c.distribution_id);
    let front =
        crate::cloudfront::front_gate(profile, account, &api.host, existing_dist.as_deref())?;

    // Cost circuit-breaker: a flood auto-disables the gate before it can run up a
    // bill. A public endpoint on the operator's account should never exist without
    // this backstop.
    crate::breaker::provision_breaker(profile, region, account, &name)?;

    Ok(FullInfra {
        table,
        gate_url: format!("https://{}", front.domain),
        distribution_id: Some(front.distribution_id),
    })
}

/// Load the gate secret, generating and persisting one the first time. Kept in
/// secrets.toml so `share` can mint ids and so it's stable across re-provision
/// (regenerating it would invalidate every outstanding link).
fn ensure_gate_secret() -> Result<String> {
    let mut s = crate::secrets::Secrets::load()?;
    if let Some(g) = &s.gate_secret {
        return Ok(g.clone());
    }
    let g = dove_core::crypto::gen_gate_secret();
    s.gate_secret = Some(g.clone());
    s.save()?;
    Ok(g)
}

/// Trust policy letting Lambda assume the gate's role.
const LAMBDA_TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Bucket CORS: let any origin GET (the browser decryptor fetching ciphertext
/// from the presigned URL). Reads are still gated by the presign + the gate.
const BUCKET_CORS: &str = r#"{"CORSRules":[{"AllowedOrigins":["*"],"AllowedMethods":["GET"],"AllowedHeaders":["*"],"MaxAgeSeconds":3000}]}"#;

/// The gate role's inline policy: log, decrement the one table, presign from the
/// one bucket. Nothing else.
pub fn gate_role_policy(account: &str, region: &str, table: &str, bucket: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:*:{account}:*"}},{{"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:UpdateItem"],"Resource":"arn:aws:dynamodb:{region}:{account}:table/{table}"}},{{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}},{{"Effect":"Allow","Action":"ssm:GetParameter","Resource":"arn:aws:ssm:{region}:{account}:parameter/dove/{bucket}/gate-secret"}},{{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}}]}}"#
    )
}

/// A unique temp path with the given extension.
fn temp_path(ext: &str) -> std::path::PathBuf {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("OS RNG");
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    std::env::temp_dir().join(format!("dove-{hex}.{ext}"))
}

/// Like `aws_ok`, but retry on a specific stderr substring (e.g. IAM
/// propagation delays), sleeping 3s between attempts.
fn aws_retry(
    profile: Option<&str>,
    args: &[&str],
    tolerate: &[&str],
    retry_on: &str,
    attempts: u32,
) -> Result<()> {
    for i in 0..attempts {
        let out = aws(profile, args)?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if tolerate.iter().any(|t| stderr.contains(t)) {
            return Ok(());
        }
        if stderr.contains(retry_on) && i + 1 < attempts {
            std::thread::sleep(std::time::Duration::from_secs(3));
            continue;
        }
        bail!("aws {} failed: {}", args.join(" "), stderr.trim());
    }
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
    fn gate_role_policy_scopes_to_the_one_table_and_bucket() {
        let p = gate_role_policy("123", "us-east-1", "dove-shares-123", "dove-shares-123");
        assert!(p.contains("dynamodb:GetItem")); // /meta + /dl read the item
        assert!(p.contains("dynamodb:UpdateItem"));
        assert!(p.contains("arn:aws:dynamodb:us-east-1:123:table/dove-shares-123"));
        assert!(p.contains("s3:GetObject"));
        assert!(p.contains("arn:aws:s3:::dove-shares-123/*"));
        assert!(p.contains("logs:PutLogEvents"));
        assert!(p.contains("ssm:GetParameter")); // reads the gate secret from SSM
        assert!(p.contains("parameter/dove/dove-shares-123/gate-secret"));
        assert!(p.contains("kms:Decrypt"));
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
