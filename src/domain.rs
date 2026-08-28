//! `dove domain add <domain>` — put a custom subdomain in front of the gate via
//! CloudFront + ACM. The ACM cert must live in us-east-1 (CloudFront's rule).
//! DNS that isn't in Route53 (e.g. Cloudflare) means two records the operator
//! adds by hand: the cert-validation CNAME, and the CNAME to CloudFront. This
//! command prints them and waits.

use crate::config::Config;
use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use std::process::Command;

const ACM_REGION: &str = "us-east-1";
// AWS-managed CloudFront policy IDs.
const CACHE_DISABLED: &str = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad";
// "AllViewerExceptHostHeader" — required for a Lambda Function URL origin, since
// forwarding the viewer Host header breaks the Function URL's host check.
const ALL_VIEWER_EXCEPT_HOST: &str = "b689b0a8-53d0-40ab-baf2-68738e2966ac";

pub fn run(domain: &str) -> Result<()> {
    let cfg = Config::load()?;
    if !cfg.is_full() {
        bail!("`dove domain add` needs the full tier — run `dove provision full` first");
    }
    let gate = cfg
        .gate_url
        .clone()
        .ok_or_else(|| anyhow!("no gate URL in config"))?;
    let origin_host =
        host_of(&gate).ok_or_else(|| anyhow!("couldn't read the gate host from {gate}"))?;
    let profile = cfg.profile.clone();

    ui::heading(&format!("dove domain add · {domain}"));

    // 1. Request the ACM cert (us-east-1) and read its validation record.
    let cert_arn = ui::step("requesting certificate", || {
        request_cert(profile.as_deref(), domain)
    })?;
    let (name, value) = wait_for_validation_record(profile.as_deref(), &cert_arn)?;

    eprintln!();
    eprintln!(
        "  {}",
        ui::bold("① Add this DNS record to validate the certificate:")
    );
    ui::field("type", "CNAME");
    ui::field("name", &name);
    ui::field("value", &value);
    eprintln!();

    // 2. Wait for validation (the operator adds the record during this).
    ui::step("waiting for DNS validation", || {
        wait_cert_issued(profile.as_deref(), &cert_arn, 45)
    })?;

    // 3. CloudFront distribution in front of the gate.
    let dist_domain = ui::step("creating CloudFront distribution", || {
        create_distribution(profile.as_deref(), domain, &origin_host, &cert_arn)
    })?;

    // 4. Point the subdomain at CloudFront.
    eprintln!();
    eprintln!("  {}", ui::bold("② Point your subdomain at CloudFront:"));
    ui::field("type", "CNAME");
    ui::field("name", domain);
    ui::field("value", &dist_domain);
    eprintln!();

    // 5. New shares hand out https://<domain>/… from here on.
    let mut cfg = cfg;
    cfg.gate_url = Some(format!("https://{domain}"));
    cfg.save()?;

    ui::done(
        "domain added",
        &format!(
            "CloudFront is deploying (~15 min). Once record ② propagates, https://{domain} \
             serves your gate — and new shares already use it."
        ),
    );
    Ok(())
}

/// Request a DNS-validated ACM certificate in us-east-1; returns its ARN.
fn request_cert(profile: Option<&str>, domain: &str) -> Result<String> {
    let out = aws(
        profile,
        &[
            "acm",
            "request-certificate",
            "--domain-name",
            domain,
            "--validation-method",
            "DNS",
            "--region",
            ACM_REGION,
            "--output",
            "json",
        ],
    )?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    v["CertificateArn"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("no CertificateArn in response"))
}

/// Poll describe-certificate until the DNS validation record is populated.
fn wait_for_validation_record(profile: Option<&str>, arn: &str) -> Result<(String, String)> {
    for _ in 0..20 {
        let out = aws(
            profile,
            &[
                "acm",
                "describe-certificate",
                "--certificate-arn",
                arn,
                "--region",
                ACM_REGION,
                "--output",
                "json",
            ],
        )?;
        if out.status.success() {
            if let Some(rr) = parse_validation_record(&out.stdout) {
                return Ok(rr);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    bail!("the certificate's DNS validation record didn't appear — try again")
}

/// Poll until the certificate is ISSUED (the operator adds the record meanwhile).
fn wait_cert_issued(profile: Option<&str>, arn: &str, attempts: u32) -> Result<()> {
    for _ in 0..attempts {
        let out = aws(
            profile,
            &[
                "acm",
                "describe-certificate",
                "--certificate-arn",
                arn,
                "--region",
                ACM_REGION,
                "--output",
                "json",
            ],
        )?;
        if out.status.success() && parse_cert_status(&out.stdout).as_deref() == Some("ISSUED") {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(20));
    }
    bail!("the certificate wasn't validated in time — add record ① and re-run `dove domain add`")
}

/// Create the CloudFront distribution fronting the gate; returns its domain.
fn create_distribution(
    profile: Option<&str>,
    domain: &str,
    origin_host: &str,
    cert_arn: &str,
) -> Result<String> {
    let caller_ref = format!("dove-{domain}");
    let config = distribution_config(&caller_ref, domain, origin_host, cert_arn);
    let out = aws(
        profile,
        &[
            "cloudfront",
            "create-distribution",
            "--distribution-config",
            &config,
            "--output",
            "json",
        ],
    )?;
    if out.status.success() {
        return parse_distribution_domain(&out.stdout);
    }
    // A re-run with the same CallerReference already made it — look it up.
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("DistributionAlreadyExists") || stderr.contains("CNAMEAlreadyExists") {
        return find_distribution_domain(profile, domain);
    }
    bail!("create-distribution failed: {}", stderr.trim())
}

fn find_distribution_domain(profile: Option<&str>, domain: &str) -> Result<String> {
    let out = aws(
        profile,
        &["cloudfront", "list-distributions", "--output", "json"],
    )?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let items = v["DistributionList"]["Items"].as_array();
    if let Some(items) = items {
        for d in items {
            let aliases = d["Aliases"]["Items"].as_array();
            let has = aliases
                .map(|a| a.iter().any(|x| x.as_str() == Some(domain)))
                .unwrap_or(false);
            if has {
                if let Some(dn) = d["DomainName"].as_str() {
                    return Ok(dn.to_string());
                }
            }
        }
    }
    bail!("couldn't find the CloudFront distribution for {domain}")
}

// ── pure helpers ──────────────────────────────────────────────────────────

/// The host portion of a URL (`https://x.on.aws/…` → `x.on.aws`).
pub fn host_of(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    Some(after.split('/').next()?.to_string())
}

/// The CloudFront distribution config JSON fronting a Lambda Function URL origin.
pub fn distribution_config(
    caller_ref: &str,
    domain: &str,
    origin_host: &str,
    cert_arn: &str,
) -> String {
    serde_json::json!({
        "CallerReference": caller_ref,
        "Aliases": {"Quantity": 1, "Items": [domain]},
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "gate",
            "DomainName": origin_host,
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}
            }
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "gate",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {
                "Quantity": 2, "Items": ["GET", "HEAD"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}
            },
            "CachePolicyId": CACHE_DISABLED,
            "OriginRequestPolicyId": ALL_VIEWER_EXCEPT_HOST,
            "Compress": true
        },
        "Comment": "dove gate",
        "Enabled": true,
        "ViewerCertificate": {
            "ACMCertificateArn": cert_arn,
            "SSLSupportMethod": "sni-only",
            "MinimumProtocolVersion": "TLSv1.2_2021"
        }
    })
    .to_string()
}

/// The `(Name, Value)` of the cert's DNS validation CNAME, if present.
pub fn parse_validation_record(json: &[u8]) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    let rr = &v["Certificate"]["DomainValidationOptions"][0]["ResourceRecord"];
    Some((
        rr["Name"].as_str()?.to_string(),
        rr["Value"].as_str()?.to_string(),
    ))
}

pub fn parse_cert_status(json: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    v["Certificate"]["Status"].as_str().map(str::to_string)
}

pub fn parse_distribution_domain(json: &[u8]) -> Result<String> {
    let v: serde_json::Value =
        serde_json::from_slice(json).context("parsing create-distribution")?;
    v["Distribution"]["DomainName"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("no distribution DomainName in response"))
}

fn aws(profile: Option<&str>, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new("aws");
    if let Some(p) = profile {
        cmd.args(["--profile", p]);
    }
    cmd.args(args)
        .output()
        .map_err(|e| anyhow!("running aws {}: {e}", args.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_extracts_host() {
        assert_eq!(
            host_of("https://abc.lambda-url.us-east-1.on.aws/d/x").as_deref(),
            Some("abc.lambda-url.us-east-1.on.aws")
        );
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn distribution_config_fronts_the_lambda_origin() {
        let c = distribution_config(
            "dove-share.dove.sh",
            "share.dove.sh",
            "abc.on.aws",
            "arn:cert",
        );
        assert!(c.contains("\"DomainName\":\"abc.on.aws\""));
        assert!(c.contains("\"Items\":[\"share.dove.sh\"]"));
        assert!(c.contains("arn:cert"));
        assert!(c.contains(CACHE_DISABLED));
        assert!(c.contains(ALL_VIEWER_EXCEPT_HOST)); // Host header not forwarded
        assert!(c.contains("https-only"));
    }

    #[test]
    fn parses_acm_validation_and_status() {
        let json = br#"{"Certificate":{"Status":"PENDING_VALIDATION","DomainValidationOptions":[{"ResourceRecord":{"Name":"_x.share.dove.sh.","Type":"CNAME","Value":"_y.acm-validations.aws."}}]}}"#;
        assert_eq!(
            parse_cert_status(json).as_deref(),
            Some("PENDING_VALIDATION")
        );
        let (n, val) = parse_validation_record(json).unwrap();
        assert_eq!(n, "_x.share.dove.sh.");
        assert_eq!(val, "_y.acm-validations.aws.");
    }

    #[test]
    fn parse_distribution_domain_reads_it() {
        let json = br#"{"Distribution":{"DomainName":"d123.cloudfront.net","Id":"E1"}}"#;
        assert_eq!(
            parse_distribution_domain(json).unwrap(),
            "d123.cloudfront.net"
        );
    }
}
