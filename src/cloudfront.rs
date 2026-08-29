//! CloudFront in front of the gate's API Gateway. It gives the gate a stable
//! `*.cloudfront.net` domain (and, via `dove domain add`, a custom one), a place
//! to attach caching/WAF later, and the perpetual free tier. The origin is the
//! HTTP API — a plain public HTTPS origin, no signing needed.

use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use std::process::Command;

// AWS-managed CloudFront policies.
const CACHE_DISABLED: &str = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad";
// "AllViewerExceptHostHeader": forward everything except Host, so CloudFront
// sends the origin's own host — required for an API Gateway origin to route.
const ALL_VIEWER_EXCEPT_HOST: &str = "b689b0a8-53d0-40ab-baf2-68738e2966ac";

/// What a fronted gate resolves to.
pub struct Front {
    pub distribution_id: String,
    pub domain: String,
}

/// Stand up (or reuse) the CloudFront distribution over the gate's API Gateway
/// origin. Returns the distribution id + its `*.cloudfront.net` domain.
pub fn front_gate(
    profile: Option<&str>,
    origin_host: &str,
    existing_distribution: Option<&str>,
) -> Result<Front> {
    if let Some(dist_id) = existing_distribution {
        let domain = ui::step("cloudfront (reuse)", || {
            distribution_domain(profile, dist_id)
        })?;
        return Ok(Front {
            distribution_id: dist_id.to_string(),
            domain,
        });
    }
    ui::step("cloudfront distribution", || {
        create_distribution(profile, origin_host)
    })
}

fn create_distribution(profile: Option<&str>, origin_host: &str) -> Result<Front> {
    let caller_ref = format!("dove-{origin_host}");
    let config = distribution_config(&caller_ref, origin_host);
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
    if !out.status.success() {
        bail!(
            "create-distribution: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(Front {
        distribution_id: v["Distribution"]["Id"]
            .as_str()
            .ok_or_else(|| anyhow!("no distribution Id"))?
            .to_string(),
        domain: v["Distribution"]["DomainName"]
            .as_str()
            .ok_or_else(|| anyhow!("no distribution DomainName"))?
            .to_string(),
    })
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
        &[
            "cloudfront",
            "get-distribution-config",
            "--id",
            dist_id,
            "--output",
            "json",
        ],
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
        .ok_or_else(|| anyhow!("no ETag"))?
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
    if !out?.status.success() {
        bail!("update-distribution failed");
    }
    Ok(domain_name)
}

fn distribution_domain(profile: Option<&str>, dist_id: &str) -> Result<String> {
    let out = aws(
        profile,
        &[
            "cloudfront",
            "get-distribution",
            "--id",
            dist_id,
            "--output",
            "json",
        ],
    )?;
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
        .ok_or_else(|| anyhow!("no DomainName"))
}

// ── pure helpers ──────────────────────────────────────────────────────────

/// The distribution config JSON: one API Gateway origin, no caching (the gate is
/// dynamic), the default CloudFront cert (a custom domain is added later by
/// `domain add`). GET/HEAD only — the gate is read-only.
pub fn distribution_config(caller_ref: &str, origin_host: &str) -> String {
    serde_json::json!({
        "CallerReference": caller_ref,
        "Comment": "dove gate",
        "Enabled": true,
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
        "ViewerCertificate": {"CloudFrontDefaultCertificate": true}
    })
    .to_string()
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
    fn distribution_config_fronts_the_api_gateway_origin() {
        let c = distribution_config("dove-x", "abc.execute-api.us-east-1.amazonaws.com");
        assert!(c.contains("\"DomainName\":\"abc.execute-api.us-east-1.amazonaws.com\""));
        assert!(c.contains(CACHE_DISABLED));
        assert!(c.contains(ALL_VIEWER_EXCEPT_HOST));
        assert!(c.contains("https-only"));
        assert!(!c.contains("OriginAccessControlId")); // no OAC — plain origin
    }
}
