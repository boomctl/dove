//! `dove get <url>` — the symmetric receiver. The actual fetch/decrypt logic
//! (splitting the key out of the URL fragment, resolving a gate page link to
//! its download endpoint, integrity-checked decryption) lives in
//! `dove_core::backend::SelfHosted::get` — this module just parses args, calls
//! it, and renders the result.
//!
//! `get` doesn't need a configured backend: a share link carries its own host,
//! and the decryption key rides the `#fragment`, never sent to any server —
//! so fetching one works from any machine, provisioned or not.

use crate::cli_progress::CliProgress;
use crate::ui;
use anyhow::Result;
use dove_core::backend::SelfHosted;
use dove_core::transfer::{GetRequest, Transfer};
use std::path::Path;

pub fn run(url: &str, out: Option<&Path>, pin: Option<&str>) -> Result<()> {
    let backend = SelfHosted::adhoc();
    let progress = CliProgress::new("downloading");
    let req = GetRequest {
        url: url.to_string(),
        out: out.map(Path::to_path_buf),
        pin: pin.map(str::to_string),
    };
    let result = backend.get(req, &progress);
    if result.is_err() {
        progress.fail_pending();
    }
    let fetched = result?;

    // Trust (who it's from, and their message) was already reported via
    // `progress.field(...)` — inside `SelfHosted::get`, *before* the
    // download started, so the recipient can decide whether to pull the file
    // at all. `fetched.from`/`.message` are still populated here (harmless —
    // available for a caller that isn't rendering through `Progress`), but
    // the CLI doesn't print them a second time.
    ui::done("downloaded", &format!("→ {}", fetched.path.display()));
    Ok(())
}
