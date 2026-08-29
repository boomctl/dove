//! dove's scoped S3 credentials — the access key of the least-privilege IAM
//! user `dove provision` mints. `share` / `ls` / `revoke` sign and act with
//! this key, not your full account credentials. Lives at
//! `~/.config/dove/secrets.toml`, mode 0600, and is never committed.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Secrets {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// The full-tier gate secret (hex): the HMAC key that mints unforgeable share
    /// ids. `share` reads it; the gate Lambda holds the same value to verify.
    #[serde(default)]
    pub gate_secret: Option<String>,
}

impl Secrets {
    pub fn load() -> Result<Self> {
        let path = secrets_path()?;
        let text = std::fs::read_to_string(&path).map_err(|_| {
            anyhow!(
                "no dove credentials at {} — run `dove provision` first",
                path.display()
            )
        })?;
        toml::from_str(&text).map_err(|e| anyhow!("parsing dove secrets: {e}"))
    }

    pub fn save(&self) -> Result<()> {
        let path = secrets_path()?;
        std::fs::create_dir_all(path.parent().unwrap())
            .with_context(|| format!("creating {}", path.parent().unwrap().display()))?;
        let text = toml::to_string_pretty(self).context("serializing dove secrets")?;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
        set_private(&path)
    }

    pub fn exists() -> bool {
        secrets_path().map(|p| p.exists()).unwrap_or(false)
    }
}

/// Lock the secrets file down to the owner (0600) on Unix.
#[cfg(unix)]
fn set_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", path.display()))
}
#[cfg(not(unix))]
fn set_private(_path: &Path) -> Result<()> {
    Ok(())
}

fn secrets_path() -> Result<PathBuf> {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return Ok(PathBuf::from(x).join("dove/secrets.toml"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config/dove/secrets.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_toml() {
        let s = Secrets {
            access_key_id: "AKIAEXAMPLE".into(),
            secret_access_key: "shhh".into(),
            gate_secret: Some("deadbeef".into()),
        };
        let text = toml::to_string(&s).unwrap();
        assert_eq!(toml::from_str::<Secrets>(&text).unwrap(), s);
    }
}
