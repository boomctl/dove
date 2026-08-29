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

    // Trust: show who the file is from before the "downloaded" banner.
    if let Some(from) = &fetched.from {
        eprintln!("  {} {}", ui::dim("from"), ui::bold(from));
        if let Some(msg) = &fetched.message {
            eprintln!("       {msg}");
        }
    }
    ui::done("downloaded", &format!("→ {}", fetched.path.display()));
    Ok(())
}
