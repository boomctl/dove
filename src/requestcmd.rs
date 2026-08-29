//! `dove request` / `dove requests` / `dove requests get` — the receiving
//! side of a transfer: ask someone else to upload a file to you, then check
//! on and collect what comes in.
//!
//! `share` run backwards: the request's creator ends up as the eventual
//! receiver. The actual logic (registering the request with the gate,
//! polling its status, decrypting and downloading whatever lands) lives on
//! `dove_core::backend::SelfHosted` — concrete methods, not the `Transfer`
//! trait, since a request only makes sense against a configured self-hosted
//! backend (there's no adhoc-by-URL form the way `get` has). This module
//! resolves that backend, calls it, and renders the result.

use crate::cli_progress::CliProgress;
use crate::ui;
use anyhow::{bail, Context, Result};
use dove_core::backend::SelfHosted;
use dove_core::config::Registry;
use dove_core::duration as dur;
use dove_core::request::{CreateRequest, RequestStatus};
use dove_core::request_ledger::{self, RequestRecord};
use std::path::PathBuf;

/// `dove request "<description>"` — register an ask with the gate and print
/// the link to hand to whoever's uploading. Full tier only: a request needs
/// the gate (to authorize an upload) and DynamoDB (to hold its policy).
#[allow(clippy::too_many_arguments)]
pub fn create(
    description: &str,
    from: Option<String>,
    message: Option<String>,
    pin: Option<String>,
    expires: &str,
    uploads: u32,
) -> Result<()> {
    let ttl = dur::parse(expires)?;
    let registry = Registry::load()?;
    let cfg = registry.active_self_hosted()?;
    if !cfg.is_full() {
        bail!(
            "dove request is a full-tier feature: it needs the gate (to authorize an upload) \
             and DynamoDB (to hold the request's policy). Provision it with \
             `dove provision full`."
        );
    }

    // A `--pin` with no value means "generate one for me" — resolved here
    // (not in dove-core) so the CLI still has the plaintext PIN in scope
    // afterward to print the PIN callout, mirroring `share::run`.
    let resolved_pin = pin.map(|p| {
        let p = p.trim();
        if p.is_empty() {
            gen_pin()
        } else {
            p.to_string()
        }
    });

    let sh = SelfHosted::from_backend(registry.active_backend()?)?;
    let progress = CliProgress::new("requesting");
    let req = CreateRequest {
        description: description.to_string(),
        from,
        message,
        pin: resolved_pin.clone(),
        expires: ttl,
        uploads,
    };
    let result = sh.create_request(req, &progress);
    if result.is_err() {
        progress.fail_pending();
    }
    let new_request = result?;

    let plural = if uploads == 1 { "" } else { "s" };
    ui::share_result(
        &new_request.link,
        &format!(
            "expires in {} · {uploads} upload{plural}",
            dur::human_long(ttl)
        ),
    );
    if let Some(p) = resolved_pin {
        ui::pin_notice(&p);
    }
    Ok(())
}

/// `dove requests` — every request this machine created, with its live
/// status pulled from the gate.
pub fn list() -> Result<()> {
    let records = request_ledger::all();
    if records.is_empty() {
        eprintln!(r#"no file requests yet — `dove request "..."` to make one"#);
        return Ok(());
    }

    let registry = Registry::load()?;
    let sh = SelfHosted::from_backend(registry.active_backend()?)?;
    for rec in &records {
        let status = sh.request_status(rec)?;
        println!("{}", request_row(rec, &status));
    }
    Ok(())
}

/// `dove requests get <id>` — collect what came in. Checks status first
/// (rather than jumping straight to `collect_request`) so an unfulfilled or
/// failed request gets a clear, specific message instead of a generic
/// collect error.
pub fn get(id: &str, out: Option<PathBuf>) -> Result<()> {
    let rec = request_ledger::get(id)
        .with_context(|| format!("no such request: {id} (see `dove requests`)"))?;

    let registry = Registry::load()?;
    let sh = SelfHosted::from_backend(registry.active_backend()?)?;
    match sh.request_status(&rec)? {
        RequestStatus::Failed { reason } => {
            println!("this request failed: {reason}");
            return Ok(());
        }
        RequestStatus::Waiting => {
            println!("not received yet — nothing to collect");
            return Ok(());
        }
        RequestStatus::Received { .. } => {}
    }

    let progress = CliProgress::new("collecting");
    let result = sh.collect_request(&rec, out, &progress);
    if result.is_err() {
        progress.fail_pending();
    }
    let fetched = result?;
    println!("saved {}", fetched.path.display());
    Ok(())
}

/// A random 6-digit PIN, zero-padded — identical to `share::gen_pin`
/// (duplicated rather than shared across two small, independent CLI
/// modules; see that copy for the rationale on why 6 digits is enough for a
/// gate-checked, rate-limited second factor).
fn gen_pin() -> String {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("OS RNG unavailable");
    format!("{:06}", u32::from_le_bytes(b) % 1_000_000)
}

/// One `dove requests` row: the description, its live state, and the dim id.
/// Pure, so it's testable without a gate to poll.
fn request_row(rec: &RequestRecord, status: &RequestStatus) -> String {
    let state = match status {
        RequestStatus::Waiting => "waiting".to_string(),
        RequestStatus::Received { name, size } => {
            format!("received · {name} · {}", ui::human_size(*size))
        }
        RequestStatus::Failed { reason } => format!("failed · {reason}"),
    };
    format!("  {}  {}  {}", rec.description, state, ui::dim(&rec.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> RequestRecord {
        RequestRecord {
            id: "ab12cd34".into(),
            fragment: "deadbeef".into(),
            description: "invoice".into(),
            created_at: 0,
        }
    }

    #[test]
    fn request_row_shows_waiting() {
        let row = request_row(&rec(), &RequestStatus::Waiting);
        assert!(row.contains("invoice") && row.contains("waiting") && row.contains("ab12cd34"));
    }

    #[test]
    fn request_row_shows_received_name_and_size() {
        let row = request_row(
            &rec(),
            &RequestStatus::Received {
                name: "report.pdf".into(),
                size: 842 * 1024 * 1024,
            },
        );
        assert!(row.contains("received"));
        assert!(row.contains("report.pdf"));
        assert!(row.contains("842 MB"));
    }

    #[test]
    fn request_row_shows_failed_reason() {
        let row = request_row(
            &rec(),
            &RequestStatus::Failed {
                reason: "expired".into(),
            },
        );
        assert!(row.contains("failed") && row.contains("expired"));
    }
}
