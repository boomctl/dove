//! `dove domain add <domain>` — put a custom subdomain in front of the gate.
//!
//! The actual AWS orchestration (requesting the ACM cert, waiting for DNS
//! validation, attaching the alias to CloudFront) lives in
//! `dove_core::provision::domain::add`; this module resolves the active
//! backend, drives a `CliProgress` through the call (which renders the DNS
//! records as they become known — well before the up-to-15-minute wait for
//! the certificate to validate), and upserts the returned config back into the
//! registry.

use crate::cli_progress::CliProgress;
use crate::ui;
use anyhow::Result;
use dove_core::config::{Backend, Registry};

pub fn run(domain: &str) -> Result<()> {
    let mut reg = Registry::load()?;
    let backend_name = reg.active_backend()?.name.clone();
    let cfg = reg.active_self_hosted()?;

    ui::heading(&format!("dove domain add · {domain}"));

    let progress = CliProgress::new("domain");
    let result = dove_core::provision::domain::add(domain, cfg, &progress);
    if result.is_err() {
        progress.fail_pending();
    }
    let new_cfg = result?;

    reg.upsert(Backend::self_hosted(&backend_name, &new_cfg)?);
    reg.save()?;

    ui::done(
        "domain added",
        &format!(
            "CloudFront is deploying (~15 min). Once record ② propagates, https://{domain} \
             serves your gate — and new shares already use it."
        ),
    );
    Ok(())
}
