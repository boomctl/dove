//! `dove use <name>` — switch the active backend. Just flips `Registry.active`
//! and saves it; the named backend must already exist (added by
//! `dove provision`, or a future `dove backend add`).

use crate::ui;
use anyhow::Result;
use dove_core::config::Registry;

pub fn run(name: &str) -> Result<()> {
    let mut reg = Registry::load()?;
    reg.set_active(name)?;
    reg.save()?;
    ui::done(&format!("now using {name}"), "");
    Ok(())
}
