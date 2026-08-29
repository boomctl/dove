//! CloudFront in front of the gate's API Gateway. It gives the gate a stable
//! `*.cloudfront.net` domain (and, via `dove domain add`, a custom one), a place
//! to attach caching/WAF later, and the perpetual free tier. The origin is the
//! HTTP API — a plain public HTTPS origin, no signing needed.

use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use std::process::Command;

// AWS-managed CloudFront policies.
const CACHE_DISABLED: &str = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad";
const CACHING_OPTIMIZED: &str = "658327ea-f89d-4fab-a63d-7e88639e58f6";
// "AllViewerExceptHostHeader": forward everything except Host, so CloudFront
// sends the origin's own host — required for an API Gateway origin to route.
const ALL_VIEWER_EXCEPT_HOST: &str = "b689b0a8-53d0-40ab-baf2-68738e2966ac";

/// A CloudFront Function that collapses every `/d/*` to one path, so all share
/// pages share a single cache entry — the decryptor page is byte-identical for
/// every share (the id is read client-side), and a flood of `/d/<random>` becomes
/// cache hits instead of Lambda invocations. Rewrites the *origin* path only; the
/// browser URL is unchanged, so the page still reads the real id.
const PAGE_REWRITE_JS: &str = r#"function handler(event) {
    var req = event.request;
    if (req.uri.startsWith('/d/')) { req.uri = '/d/p'; }
    return req;
}
"#;

/// What a fronted gate resolves to.
pub struct Front {
    pub distribution_id: String,
    pub domain: String,
}

/// Stand up (or reuse) the CloudFront distribution over the gate's API Gateway
/// origin. Returns the distribution id + its `*.cloudfront.net` domain.
pub fn front_gate(
    profile: Option<&str>,
    account: &str,
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
    // The page cache-key rewrite function must exist before the distribution
    // references it.
    let fn_arn = ui::step("page cache function", || {
        ensure_page_function(profile, account)
    })?;
    ui::step("cloudfront distribution", || {
        create_distribution(profile, origin_host, &fn_arn)
    })
}

/// Create + publish the page-rewrite CloudFront Function, reusing it by name.
/// Its ARN is deterministic per account.
fn ensure_page_function(profile: Option<&str>, account: &str) -> Result<String> {
    let arn = format!("arn:aws:cloudfront::{account}:function/dove-page-rewrite");
    let tmp = std::env::temp_dir().join("dove-page-rewrite.js");
    std::fs::write(&tmp, PAGE_REWRITE_JS)?;
    let code_arg = format!("fileb://{}", tmp.display());
    let out = aws(
        profile,
        &[
            "cloudfront",
            "create-function",
            "--name",
            "dove-page-rewrite",
            "--function-config",
            "Comment=dove page cache-key rewrite,Runtime=cloudfront-js-2.0",
            "--function-code",
            &code_arg,
            "--output",
            "json",
        ],
    );
    let _ = std::fs::remove_file(&tmp);
    let out = out?;
    if out.status.success() {
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        let etag = v["ETag"]
            .as_str()
            .ok_or_else(|| anyhow!("no ETag from create-function"))?;
        let pub_out = aws(
            profile,
            &[
                "cloudfront",
                "publish-function",
                "--name",
                "dove-page-rewrite",
                "--if-match",
                etag,
            ],
        )?;
        if !pub_out.status.success() {
            bail!(
                "publish-function: {}",
                String::from_utf8_lossy(&pub_out.stderr).trim()
            );
        }
    } else if !String::from_utf8_lossy(&out.stderr).contains("FunctionAlreadyExists") {
        bail!(
            "create-function: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(arn)
}

fn create_distribution(
    profile: Option<&str>,
    origin_host: &str,
    page_fn_arn: &str,
) -> Result<Front> {
    let caller_ref = format!("dove-{origin_host}");
    let config = distribution_config(&caller_ref, origin_host, page_fn_arn);
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

/// A cache behavior (all fields CloudFront requires) for a path pattern, with an
/// optional viewer-request function.
fn cache_behavior(path: &str, cache_policy: &str, fn_arn: Option<&str>) -> serde_json::Value {
    let fns = match fn_arn {
        Some(arn) => serde_json::json!({
            "Quantity": 1,
            "Items": [{"EventType": "viewer-request", "FunctionARN": arn}]
        }),
        None => serde_json::json!({"Quantity": 0}),
    };
    serde_json::json!({
        "PathPattern": path,
        "TargetOriginId": "gate",
        "ViewerProtocolPolicy": "redirect-to-https",
        "CachePolicyId": cache_policy,
        "Compress": true,
        "AllowedMethods": {
            "Quantity": 2, "Items": ["GET", "HEAD"],
            "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}
        },
        "FunctionAssociations": fns,
        "SmoothStreaming": false,
        "FieldLevelEncryptionId": "",
        "LambdaFunctionAssociations": {"Quantity": 0},
        "TrustedSigners": {"Enabled": false, "Quantity": 0},
        "TrustedKeyGroups": {"Enabled": false, "Quantity": 0}
    })
}

/// The distribution config JSON. The **default** behavior is the dynamic gate (no
/// caching, API Gateway origin). Two cached behaviors sit in front: `/d/*` (the
/// share-agnostic page, collapsed to one cache entry by the rewrite function) and
/// `/og.png` — both served from the edge, never invoking the Lambda. Default cert;
/// a custom domain is added later by `domain add`.
pub fn distribution_config(caller_ref: &str, origin_host: &str, page_fn_arn: &str) -> String {
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
        "CacheBehaviors": {"Quantity": 2, "Items": [
            cache_behavior("/d/*", CACHING_OPTIMIZED, Some(page_fn_arn)),
            cache_behavior("/og.png", CACHING_OPTIMIZED, None)
        ]},
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
        let c = distribution_config(
            "dove-x",
            "abc.execute-api.us-east-1.amazonaws.com",
            "arn:aws:cloudfront::1:function/dove-page-rewrite",
        );
        assert!(c.contains("\"DomainName\":\"abc.execute-api.us-east-1.amazonaws.com\""));
        assert!(c.contains(CACHE_DISABLED)); // default (dynamic) behavior
        assert!(c.contains(CACHING_OPTIMIZED)); // the cached /d/* and /og.png behaviors
        assert!(c.contains("/d/*") && c.contains("/og.png"));
        assert!(c.contains(ALL_VIEWER_EXCEPT_HOST));
        assert!(!c.contains("OriginAccessControlId")); // no OAC — plain origin
    }
}
