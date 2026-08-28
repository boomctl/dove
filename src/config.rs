//! dove configuration — where shares are stored and how to reach the bucket.
//! Lives at `~/.config/dove/config.toml`, written by `dove provision`.

// Fields are consumed by later tasks (`s3` / `share` / `provision`).
#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// The S3 bucket dove uploads shares to.
    pub bucket: String,
    pub region: String,
    /// AWS profile whose credentials sign presigned URLs. `None` → the default
    /// credential chain (env / default profile / instance role).
    #[serde(default)]
    pub profile: Option<String>,
    /// Optional S3-compatible endpoint (MinIO, R2, …); omitted → real AWS S3.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// DynamoDB table holding share policies — full tier only.
    #[serde(default)]
    pub table: Option<String>,
    /// The access-gate base URL (a Lambda Function URL). Its presence marks the
    /// config as full-tier: `share` registers a policy and points links at the
    /// gate instead of handing out a raw presigned URL.
    #[serde(default)]
    pub gate_url: Option<String>,
}

impl Config {
    /// Whether this config is provisioned for the full (gated, encrypted) tier.
    pub fn is_full(&self) -> bool {
        self.gate_url.is_some()
    }
}

impl Config {
    /// Load the config, with a clear pointer to `dove provision` when it's
    /// missing — that's the setup step that writes it.
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        let text = std::fs::read_to_string(&path).map_err(|_| {
            anyhow!(
                "no dove config at {} — run `dove provision` first",
                path.display()
            )
        })?;
        Self::parse(&text)
    }

    /// Parse from TOML text (split out so it's unit-testable).
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| anyhow!("parsing dove config: {e}"))
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        std::fs::create_dir_all(path.parent().unwrap())
            .with_context(|| format!("creating {}", path.parent().unwrap().display()))?;
        let text = toml::to_string_pretty(self).context("serializing dove config")?;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
    }
}

/// `~/.config/dove/config.toml`, honoring `$XDG_CONFIG_HOME`.
fn config_path() -> Result<PathBuf> {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return Ok(PathBuf::from(x).join("dove/config.toml"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config/dove/config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_toml() {
        let cfg = Config {
            bucket: "dove-shares-example".into(),
            region: "us-east-1".into(),
            profile: Some("work".into()),
            endpoint: None,
            table: Some("dove-shares-example".into()),
            gate_url: Some("https://x.lambda-url.us-east-1.on.aws".into()),
        };
        let text = toml::to_string(&cfg).unwrap();
        assert_eq!(Config::parse(&text).unwrap(), cfg);
        assert!(cfg.is_full());
    }

    #[test]
    fn optional_fields_default_to_none() {
        let cfg = Config::parse("bucket = \"b\"\nregion = \"us-east-1\"\n").unwrap();
        assert_eq!(cfg.profile, None);
        assert_eq!(cfg.endpoint, None);
    }

    #[test]
    fn missing_required_field_is_an_error() {
        assert!(Config::parse("region = \"us-east-1\"\n").is_err()); // no bucket
    }
}
