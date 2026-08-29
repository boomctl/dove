//! CloudFront in front of the gate. dove's full tier keeps the Lambda Function
//! URL **private** (`AWS_IAM`) and puts CloudFront in front with an Origin Access
//! Control that signs every origin request (SigV4). CloudFront is authorized by a
//! resource policy scoped to this one distribution. Anonymous browsers reach the
//! gate through CloudFront; the raw Function URL is never publicly invokable.
//!
//! This is required, not optional: some accounts forbid public (`NONE`-auth)
//! Function URLs outright, and OAC + IAM is the AWS-recommended, more-secure
//! pattern regardless.

use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use std::process::Command;

// AWS-managed CloudFront policies.
const CACHE_DISABLED: &str = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad";
// "AllViewerExceptHostHeader" — required for a Function URL origin: forwarding
// the viewer Host header breaks the origin's host check (and OAC signing).
const ALL_VIEWER_EXCEPT_HOST: &str = "b689b0a8-53d0-40ab-baf2-68738e2966ac";

/// What a fronted gate resolves to.
pub struct Front {
    pub distribution_id: String,
    pub domain: String,
}

/// Stand up (or reuse) the CloudFront front for the gate: an OAC, a distribution
/// over the Function URL origin, and the resource policy authorizing CloudFront.
/// Returns the distribution id + its `*.cloudfront.net` domain.
pub fn front_gate(
    profile: Option<&str>,
    account: &str,
    function_name: &str,
    origin_host: &str,
    existing_distribution: Option<&str>,
) -> Result<Front> {
    // Reuse an existing distribution (a re-provision) — just make sure its origin
    // and the invoke permission are current.
    if let Some(dist_id) = existing_distribution {
        let domain = ui::step("cloudfront (reuse)", || distribution_domain(profile, dist_id))?;
        ui::step("gate invoke permission", || {
            grant_cloudfront_invoke(profile, function_name, account, dist_id)
        })?;
        return Ok(Front {
            distribution_id: dist_id.to_string(),
            domain,
        });
    }

    let oac = ui::step("origin access control", || create_oac(profile, function_name))?;
    let front = ui::step("cloudfront distribution", || {
        create_distribution(profile, function_name, origin_host, &oac)
    })?;
    // Authorize this distribution to invoke the private Function URL.
    ui::step("gate invoke permission", || {
        grant_cloudfront_invoke(profile, function_name, account, &front.distribution_id)
    })?;
    Ok(front)
}

/// Create an OAC that always SigV4-signs to a Lambda origin, reusing one by name
/// if it exists (names are unique enough per gate: the function name).
fn create_oac(profile: Option<&str>, function_name: &str) -> Result<String> {
    let name = format!("{function_name}-oac");
    // Reuse if present.
    let list = aws(profile, &["cloudfront", "list-origin-access-controls", "--output", "json"])?;
    if list.status.success() {
        if let Some(id) = oac_id_by_name(&list.stdout, &name) {
            return Ok(id);
        }
    }
    let config = format!(
        "Name={name},Description=dove gate,SigningProtocol=sigv4,\
         SigningBehavior=always,OriginAccessControlOriginType=lambda"
    );
    let out = aws(
        profile,
        &[
            "cloudfront",
            "create-origin-access-control",
            "--origin-access-control-config",
            &config,
            "--output",
            "json",
        ],
    )?;
    if !out.status.success() {
        bail!(
            "create-origin-access-control: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    v["OriginAccessControl"]["Id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("no OAC Id in response"))
}

fn create_distribution(
    profile: Option<&str>,
    function_name: &str,
    origin_host: &str,
    oac_id: &str,
) -> Result<Front> {
    let caller_ref = format!("dove-{function_name}");
    let config = distribution_config(&caller_ref, origin_host, oac_id);
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
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        let id = v["Distribution"]["Id"]
            .as_str()
            .ok_or_else(|| anyhow!("no distribution Id"))?;
        let domain = v["Distribution"]["DomainName"]
            .as_str()
            .ok_or_else(|| anyhow!("no distribution DomainName"))?;
        return Ok(Front {
            distribution_id: id.to_string(),
            domain: domain.to_string(),
        });
    }
    bail!(
        "create-distribution: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

/// Resource policy: let CloudFront (this distribution only) invoke the IAM-only
/// Function URL. Idempotent — a re-provision tolerates the existing statement.
fn grant_cloudfront_invoke(
    profile: Option<&str>,
    function_name: &str,
    account: &str,
    dist_id: &str,
) -> Result<()> {
    let source_arn = format!("arn:aws:cloudfront::{account}:distribution/{dist_id}");
    let out = aws(
        profile,
        &[
            "lambda",
            "add-permission",
            "--function-name",
            function_name,
            "--statement-id",
            "cloudfront-oac",
            "--action",
            "lambda:InvokeFunctionUrl",
            "--principal",
            "cloudfront.amazonaws.com",
            "--source-arn",
            &source_arn,
            "--function-url-auth-type",
            "AWS_IAM",
        ],
    )?;
    if out.status.success() || String::from_utf8_lossy(&out.stderr).contains("ResourceConflictException") {
        return Ok(());
    }
    bail!(
        "granting CloudFront invoke: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

/// Attach a custom domain (`domain`) with its ACM cert to an existing gate
/// distribution: add the alias + viewer certificate, preserving everything else.
pub fn add_alias(
    profile: Option<&str>,
    dist_id: &str,
    domain: &str,
    cert_arn: &str,
) -> Result<String> {
    let out = aws(
        profile,
        &["cloudfront", "get-distribution-config", "--id", dist_id, "--output", "json"],
    )?;
    if !out.status.success() {
        bail!(
            "get-distribution-config: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let etag = v["ETag"]
        .as_str()
        .ok_or_else(|| anyhow!("no ETag in distribution config"))?
        .to_string();
    let mut cfg = v["DistributionConfig"].clone();
    cfg["Aliases"] = serde_json::json!({"Quantity": 1, "Items": [domain]});
    cfg["ViewerCertificate"] = serde_json::json!({
        "ACMCertificateArn": cert_arn,
        "SSLSupportMethod": "sni-only",
        "MinimumProtocolVersion": "TLSv1.2_2021",
        "CloudFrontDefaultCertificate": false,
    });
    let domain_name = cfg["DomainName"].as_str().unwrap_or_default().to_string();

    let tmp = std::env::temp_dir().join(format!("dove-dist-{dist_id}.json"));
    std::fs::write(&tmp, cfg.to_string())?;
    let cfg_arg = format!("file://{}", tmp.display());
    let out = aws(
        profile,
        &[
            "cloudfront",
            "update-distribution",
            "--id",
            dist_id,
            "--distribution-config",
            &cfg_arg,
            "--if-match",
            &etag,
            "--output",
            "json",
        ],
    );
    let _ = std::fs::remove_file(&tmp);
    let out = out?;
    if !out.status.success() {
        bail!(
            "update-distribution: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(domain_name)
}

fn distribution_domain(profile: Option<&str>, dist_id: &str) -> Result<String> {
    let out = aws(profile, &["cloudfront", "get-distribution", "--id", dist_id, "--output", "json"])?;
    if !out.status.success() {
        bail!(
            "get-distribution: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    v["Distribution"]["DomainName"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("no distribution DomainName"))
}

// ── pure helpers ──────────────────────────────────────────────────────────

/// The host portion of a URL (`https://x.on.aws/` → `x.on.aws`).
pub fn host_of(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    let host = after.split('/').next()?;
    (!host.is_empty()).then(|| host.to_string())
}

/// The distribution config JSON: one Function URL origin signed by the OAC, no
/// caching (the gate is dynamic), the default CloudFront cert (a custom domain is
/// added later by `domain add`). GET/HEAD only — the gate is read-only.
pub fn distribution_config(caller_ref: &str, origin_host: &str, oac_id: &str) -> String {
    serde_json::json!({
        "CallerReference": caller_ref,
        "Comment": "dove gate",
        "Enabled": true,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "gate",
            "DomainName": origin_host,
            "OriginAccessControlId": oac_id,
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
        "ViewerCertificate": {"CloudFrontDefaultCertificate": true}
    })
    .to_string()
}

/// Find an OAC's Id by name in a `list-origin-access-controls` response.
pub fn oac_id_by_name(json: &[u8], name: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    let items = v["OriginAccessControlList"]["Items"].as_array()?;
    for it in items {
        if it["Name"].as_str() == Some(name) {
            return it["Id"].as_str().map(str::to_string);
        }
    }
    None
}

fn aws(profile: Option<&str>, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new("aws");
    if let Some(p) = profile {
        cmd.args(["--profile", p]);
    }
    cmd.args(args)
        .output()
        .with_context(|| format!("running aws {}", args.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_extracts_host() {
        assert_eq!(
            host_of("https://abc.lambda-url.us-east-1.on.aws/").as_deref(),
            Some("abc.lambda-url.us-east-1.on.aws")
        );
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn distribution_config_signs_a_private_origin() {
        let c = distribution_config("dove-fn", "abc.on.aws", "OAC123");
        assert!(c.contains("\"DomainName\":\"abc.on.aws\""));
        assert!(c.contains("\"OriginAccessControlId\":\"OAC123\"")); // OAC signs
        assert!(c.contains(CACHE_DISABLED));
        assert!(c.contains(ALL_VIEWER_EXCEPT_HOST)); // Host not forwarded
        assert!(c.contains("CloudFrontDefaultCertificate")); // custom domain added later
    }

    #[test]
    fn oac_id_by_name_finds_it() {
        let json = br#"{"OriginAccessControlList":{"Items":[
            {"Id":"A1","Name":"other-oac"},{"Id":"B2","Name":"dove-gate-oac"}]}}"#;
        assert_eq!(oac_id_by_name(json, "dove-gate-oac").as_deref(), Some("B2"));
        assert_eq!(oac_id_by_name(json, "missing"), None);
    }
}
