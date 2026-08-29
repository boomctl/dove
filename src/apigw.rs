//! API Gateway HTTP API in front of the gate Lambda — the public → Lambda hop.
//! It reaches the function through `lambda:InvokeFunction` (the universally
//! allowed action), so it works even in accounts that forbid public Lambda
//! Function URLs. The gate Lambda already speaks the HTTP API 2.0 event/response
//! format, so no code change is needed on the Lambda side.

use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use std::process::Command;

/// The provisioned HTTP API's invoke host — a plain HTTPS origin for CloudFront.
pub struct Api {
    pub host: String,
}

/// Create (or reuse) the HTTP API routing everything to the gate Lambda. Reused
/// by name on re-provision — an existing `dove-gate` API is assumed fully wired.
pub fn provision_api(
    profile: Option<&str>,
    region: &str,
    account: &str,
    name: &str,
    function_arn: &str,
) -> Result<Api> {
    let id = ui::step("api gateway", || {
        if let Some(existing) = find_api_by_name(profile, name)? {
            return Ok(existing);
        }
        create_api(profile, region, account, name, function_arn)
    })?;
    Ok(Api {
        host: api_host(&id, region),
    })
}

fn create_api(
    profile: Option<&str>,
    region: &str,
    account: &str,
    name: &str,
    function_arn: &str,
) -> Result<String> {
    let id = out_field(
        aws(
            profile,
            &[
                "apigatewayv2",
                "create-api",
                "--name",
                name,
                "--protocol-type",
                "HTTP",
                "--output",
                "json",
            ],
        )?,
        "ApiId",
    )?;
    // AWS_PROXY integration (payload format 2.0 — what the gate Lambda expects).
    let integration = out_field(
        aws(
            profile,
            &[
                "apigatewayv2",
                "create-integration",
                "--api-id",
                &id,
                "--integration-type",
                "AWS_PROXY",
                "--integration-uri",
                function_arn,
                "--payload-format-version",
                "2.0",
                "--integration-method",
                "POST",
                "--output",
                "json",
            ],
        )?,
        "IntegrationId",
    )?;
    // A catch-all $default route → the integration, on an auto-deploying $default stage.
    aws_ok(
        profile,
        &[
            "apigatewayv2",
            "create-route",
            "--api-id",
            &id,
            "--route-key",
            "$default",
            "--target",
            &format!("integrations/{integration}"),
        ],
    )?;
    aws_ok(
        profile,
        &[
            "apigatewayv2",
            "create-stage",
            "--api-id",
            &id,
            "--stage-name",
            "$default",
            "--auto-deploy",
        ],
    )?;
    // Let API Gateway invoke the function.
    let source = format!("arn:aws:execute-api:{region}:{account}:{id}/*/*");
    let out = aws(
        profile,
        &[
            "lambda",
            "add-permission",
            "--function-name",
            name,
            "--statement-id",
            "apigw-invoke",
            "--action",
            "lambda:InvokeFunction",
            "--principal",
            "apigateway.amazonaws.com",
            "--source-arn",
            &source,
        ],
    )?;
    if !out.status.success()
        && !String::from_utf8_lossy(&out.stderr).contains("ResourceConflictException")
    {
        bail!(
            "granting API Gateway invoke: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(id)
}

fn find_api_by_name(profile: Option<&str>, name: &str) -> Result<Option<String>> {
    let out = aws(profile, &["apigatewayv2", "get-apis", "--output", "json"])?;
    if !out.status.success() {
        return Ok(None); // treat a listing failure as "none" — create will surface real errors
    }
    Ok(api_id_by_name(&out.stdout, name))
}

// ── pure helpers ──────────────────────────────────────────────────────────

/// The invoke host for an HTTP API id — a plain HTTPS origin for CloudFront.
pub fn api_host(api_id: &str, region: &str) -> String {
    format!("{api_id}.execute-api.{region}.amazonaws.com")
}

/// Find an HTTP API's id by name in a `get-apis` response.
pub fn api_id_by_name(json: &[u8], name: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    for item in v["Items"].as_array()? {
        if item["Name"].as_str() == Some(name) {
            return item["ApiId"].as_str().map(str::to_string);
        }
    }
    None
}

fn out_field(out: std::process::Output, field: &str) -> Result<String> {
    if !out.status.success() {
        bail!(
            "apigatewayv2: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    v[field]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("no {field} in API Gateway response"))
}

fn aws_ok(profile: Option<&str>, args: &[&str]) -> Result<()> {
    let out = aws(profile, args)?;
    if out.status.success() || String::from_utf8_lossy(&out.stderr).contains("Conflict") {
        return Ok(());
    }
    bail!(
        "aws {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )
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
    fn api_host_builds_the_invoke_domain() {
        assert_eq!(
            api_host("abcde12345", "us-east-1"),
            "abcde12345.execute-api.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn api_id_by_name_finds_it() {
        let json =
            br#"{"Items":[{"ApiId":"a1","Name":"other"},{"ApiId":"b2","Name":"dove-gate-123"}]}"#;
        assert_eq!(api_id_by_name(json, "dove-gate-123").as_deref(), Some("b2"));
        assert_eq!(api_id_by_name(json, "missing"), None);
    }
}
