//! A local record of the full-tier shares this machine created. The server holds
//! only ciphertext under name-free keys — it can't tell you what you shared. But
//! *you* named the file at upload time, so dove keeps a private map here
//! (`~/.config/dove/shares.json`) and `dove ls` reads it. Server stays blind; you
//! keep your own view.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub from: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub downloads: u32,
}

/// Record (or replace) a share in the local ledger.
pub fn record(rec: ShareRecord) -> Result<()> {
    let mut all = load().unwrap_or_default();
    all.retain(|r| r.id != rec.id);
    all.push(rec);
    save(&all)
}

/// Drop a share from the ledger (on revoke).
pub fn remove(id: &str) -> Result<()> {
    let mut all = load().unwrap_or_default();
    all.retain(|r| r.id != id);
    save(&all)
}

/// `id -> filename` for the shares this machine made — what `dove ls` shows.
pub fn names() -> HashMap<String, String> {
    load()
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.id, r.name))
        .collect()
}

pub fn load() -> Result<Vec<ShareRecord>> {
    let path = ledger_path()?;
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).context("parsing the dove shares ledger"),
        Err(_) => Ok(Vec::new()), // no ledger yet
    }
}

fn save(all: &[ShareRecord]) -> Result<()> {
    let path = ledger_path()?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    let text = serde_json::to_string_pretty(all).context("serializing the dove shares ledger")?;
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
}

fn ledger_path() -> Result<PathBuf> {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return Ok(PathBuf::from(x).join("dove/shares.json"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config/dove/shares.json"))
}
