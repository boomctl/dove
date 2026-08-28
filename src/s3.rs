//! The S3 layer: upload a share, sign a presigned download URL, delete, list.
//! Built on `rusty-s3` + `ureq`, matching git-ark. Credentials come from the
//! operator's own AWS profile (via the AWS CLI) — the simple tier signs with
//! your credentials directly, so there's no separate IAM user and no host.

// Methods are consumed by later tasks (`share` / `ls` / `revoke`).
#![allow(dead_code)]

use crate::config::Config;
use anyhow::{anyhow, bail, Context, Result};
use rusty_s3::actions::ListObjectsV2;
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use std::time::Duration;

/// TTL for internally-signed operation URLs (put/delete/list). Short — these
/// are signed and used immediately, never handed out.
const OP_TTL: Duration = Duration::from_secs(60);

pub struct Store {
    bucket: Bucket,
    creds: Credentials,
}

impl Store {
    /// Build the store from config, resolving credentials from the configured
    /// AWS profile (or the default chain).
    pub fn new(cfg: &Config) -> Result<Self> {
        let (endpoint, style) = match &cfg.endpoint {
            Some(e) => (e.clone(), UrlStyle::Path), // S3-compatible → path-style
            None => (
                format!("https://s3.{}.amazonaws.com", cfg.region),
                UrlStyle::VirtualHost,
            ),
        };
        let bucket = Bucket::new(
            endpoint.parse().context("parsing S3 endpoint URL")?,
            style,
            cfg.bucket.clone(),
            cfg.region.clone(),
        )
        .map_err(|e| anyhow!("bucket config: {e}"))?;
        let creds = resolve_credentials(cfg.profile.as_deref())?;
        Ok(Self { bucket, creds })
    }

    /// A presigned GET URL for `key`, valid for `ttl`. This is the link handed
    /// to a recipient; `ttl` is capped at 7 days by the caller (SigV4 limit).
    pub fn presign_get(&self, key: &str, ttl: Duration) -> String {
        sign_get(&self.bucket, &self.creds, key, ttl)
    }

    /// Upload `body` to `key`. (Whole-object PUT; multipart streaming for very
    /// large files is a follow-up that pairs with the chunked-encryption work.)
    pub fn put_object(&self, key: &str, body: &[u8]) -> Result<()> {
        let url = self.bucket.put_object(Some(&self.creds), key).sign(OP_TTL);
        let resp = ureq::put(url.as_str())
            .send_bytes(body)
            .map_err(|e| anyhow!("PutObject {key} failed: {}", s3_err(e)))?;
        if resp.status() >= 300 {
            bail!("PutObject {key}: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// Delete `key` — how `dove revoke` kills a share early (the link then 404s).
    pub fn delete_object(&self, key: &str) -> Result<()> {
        let url = self
            .bucket
            .delete_object(Some(&self.creds), key)
            .sign(OP_TTL);
        let resp = ureq::delete(url.as_str())
            .call()
            .map_err(|e| anyhow!("DeleteObject {key} failed: {}", s3_err(e)))?;
        if resp.status() >= 300 {
            bail!("DeleteObject {key}: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// All object keys under `prefix`, following continuation tokens so listings
    /// past the first 1000 aren't silently dropped.
    pub fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut action = self.bucket.list_objects_v2(Some(&self.creds));
            action.with_prefix(prefix);
            if let Some(token) = continuation.clone() {
                action.with_continuation_token(token);
            }
            let url = action.sign(OP_TTL);
            let resp = ureq::get(url.as_str())
                .call()
                .map_err(|e| anyhow!("ListObjectsV2 failed: {}", s3_err(e)))?;
            if resp.status() >= 300 {
                bail!("ListObjectsV2: HTTP {}", resp.status());
            }
            let text = resp.into_string()?;
            let parsed = ListObjectsV2::parse_response(&text)
                .map_err(|e| anyhow!("parsing ListObjectsV2 response: {e}"))?;
            keys.extend(parsed.contents.into_iter().map(|o| o.key));
            match parsed.next_continuation_token {
                Some(token) if !token.is_empty() => continuation = Some(token),
                _ => break,
            }
        }
        Ok(keys)
    }
}

/// Sign a presigned GET URL. Free function so it's unit-testable with fixed
/// credentials, without resolving anything from the environment.
fn sign_get(bucket: &Bucket, creds: &Credentials, key: &str, ttl: Duration) -> String {
    bucket.get_object(Some(creds), key).sign(ttl).to_string()
}

/// Resolve AWS credentials from the configured profile via the AWS CLI
/// (`aws configure export-credentials`), so SSO/role/env all work the way the
/// operator's shell already does. Returns temporary creds (with a session
/// token) when the profile provides them.
fn resolve_credentials(profile: Option<&str>) -> Result<Credentials> {
    let mut cmd = std::process::Command::new("aws");
    cmd.args(["configure", "export-credentials", "--format", "process"]);
    if let Some(p) = profile {
        cmd.args(["--profile", p]);
    }
    let out = cmd
        .output()
        .context("running `aws configure export-credentials` (is the AWS CLI installed?)")?;
    if !out.status.success() {
        bail!(
            "couldn't resolve AWS credentials: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("parsing AWS credentials JSON")?;
    let access = v["AccessKeyId"]
        .as_str()
        .ok_or_else(|| anyhow!("no AccessKeyId in AWS credentials"))?
        .to_string();
    let secret = v["SecretAccessKey"]
        .as_str()
        .ok_or_else(|| anyhow!("no SecretAccessKey in AWS credentials"))?
        .to_string();
    match v["SessionToken"].as_str().filter(|t| !t.is_empty()) {
        Some(token) => Ok(Credentials::new_with_token(
            access,
            secret,
            token.to_string(),
        )),
        None => Ok(Credentials::new(access, secret)),
    }
}

/// Format a ureq error WITHOUT leaking the signed request URL (which carries
/// `X-Amz-Credential` / `X-Amz-Signature`). Never interpolate a signed URL.
fn s3_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("HTTP {code}"),
        ureq::Error::Transport(t) => t.kind().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presign_get_signs_a_url_with_key_and_expiry() {
        let bucket = Bucket::new(
            "https://s3.us-east-1.amazonaws.com".parse().unwrap(),
            UrlStyle::VirtualHost,
            "dove-shares-example".to_string(),
            "us-east-1".to_string(),
        )
        .unwrap();
        let creds = Credentials::new("AKIAEXAMPLE", "secretexample");
        let url = sign_get(
            &bucket,
            &creds,
            "abc123/report.pdf",
            Duration::from_secs(3600),
        );
        assert!(url.contains("report.pdf"), "key not in URL: {url}");
        assert!(
            url.contains("X-Amz-Expires=3600"),
            "expiry not in URL: {url}"
        );
        assert!(url.contains("X-Amz-Signature="), "not signed: {url}");
    }

    #[test]
    fn s3_err_does_not_leak_signed_params() {
        // A real transport error to an unreachable endpoint whose URL carries
        // signed params — s3_err must not surface them.
        let err = ureq::get("http://127.0.0.1:1/x?X-Amz-Signature=leak")
            .call()
            .unwrap_err();
        let msg = s3_err(err);
        assert!(!msg.contains("X-Amz"), "leaked signed params: {msg}");
    }
}
