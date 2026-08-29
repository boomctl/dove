//! `dove gate disable | enable | status` — the operator's manual switch for the
//! full-tier gate. `disable` sets the gate Lambda's reserved concurrency to 0
//! (every request fails fast, at no cost — the same lever the cost breaker pulls
//! automatically on a flood); `enable` removes it; `status` reports which.
//!
//! The actual gate control — deriving the gate Lambda's name, shelling `aws` —
//! lives in `dove_core::backend::SelfHosted::gate_{disable,enable,status}`; this
//! module just resolves the active backend and renders the result.

use crate::ui;
use anyhow::Result;
use dove_core::backend::SelfHosted;
use dove_core::config::Registry;

pub fn disable() -> Result<()> {
    let backend = active_backend()?;
    ui::step("disabling gate", || {
        backend.gate_disable().map_err(Into::into)
    })?;
    ui::done(
        "gate disabled",
        "requests now fail fast at no cost. `dove gate enable` brings it back.",
    );
    Ok(())
}

pub fn enable() -> Result<()> {
    let backend = active_backend()?;
    ui::step("enabling gate", || {
        backend.gate_enable().map_err(Into::into)
    })?;
    ui::done("gate enabled", "the gate is serving again.");
    Ok(())
}

pub fn status() -> Result<()> {
    let backend = active_backend()?;
    let state = backend.gate_status()?;
    if state.enabled {
        println!("  {} gate enabled", ui::green("●"));
    } else {
        println!(
            "  {} gate disabled (reserved concurrency 0) — `dove gate enable` to restore",
            ui::red("●")
        );
    }
    Ok(())
}

/// The self-hosted backend for the active registry entry.
fn active_backend() -> Result<SelfHosted> {
    Ok(SelfHosted::from_backend(
        Registry::load()?.active_backend()?,
    )?)
}
