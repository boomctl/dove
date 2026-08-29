//! `dove domain add <domain>` — put a custom subdomain in front of the gate. The
//! CloudFront distribution already exists (from `dove provision full`); this
//! requests a DNS-validated ACM cert (us-east-1, CloudFront's rule) and attaches
//! the domain as an alias. DNS that isn't in Route53 (e.g. Cloudflare) means two
//! records the operator adds by hand; this prints them and waits.

use crate::config::Config;
use crate::ui;
use anyhow::{anyhow, bail, Result};
use std::process::Command;

const ACM_REGION: &str = "us-east-1";

pub fn run(domain: &str) -> Result<()> {
    let cfg = Config::load()?;
    if !cfg.is_full() {
        bail!("`dove domain add` needs the full tier — run `dove provision full` first");
    }
    let dist_id = cfg.distribution_id.clone().ok_or_else(|| {
        anyhow!("no CloudFront distribution in the config — run `dove provision full` first")
    })?;
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

    // 3. Attach the domain (alias + cert) to the existing gate distribution.
    let dist_domain = ui::step("attaching domain to CloudFront", || {
        crate::cloudfront::add_alias(profile.as_deref(), &dist_id, domain, &cert_arn)
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

// ── pure helpers ──────────────────────────────────────────────────────────

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
}
