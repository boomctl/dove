//! `dove gate disable | enable | status` — the operator's manual switch for the
//! full-tier gate. `disable` sets the gate Lambda's reserved concurrency to 0
//! (every request fails fast, at no cost — the same lever the cost breaker pulls
//! automatically on a flood); `enable` removes it; `status` reports which.

use crate::ui;
use anyhow::{bail, Context, Result};
use dove_core::config::Registry;
use std::process::Command;

pub fn disable() -> Result<()> {
    let (profile, function) = gate_function()?;
    ui::step("disabling gate", || {
        run(
            profile.as_deref(),
            &[
                "lambda",
                "put-function-concurrency",
                "--function-name",
                &function,
                "--reserved-concurrent-executions",
                "0",
            ],
        )
    })?;
    ui::done(
        "gate disabled",
        "requests now fail fast at no cost. `dove gate enable` brings it back.",
    );
    Ok(())
}

pub fn enable() -> Result<()> {
    let (profile, function) = gate_function()?;
    ui::step("enabling gate", || {
        run(
            profile.as_deref(),
            &[
                "lambda",
                "delete-function-concurrency",
                "--function-name",
                &function,
            ],
        )
    })?;
    ui::done("gate enabled", "the gate is serving again.");
    Ok(())
}

pub fn status() -> Result<()> {
    let (profile, function) = gate_function()?;
    let out = aws(
        profile.as_deref(),
        &[
            "lambda",
            "get-function-concurrency",
            "--function-name",
            &function,
            "--output",
            "json",
        ],
    )?;
    let reserved = serde_json::from_slice::<serde_json::Value>(&out.stdout)
        .ok()
        .and_then(|v| v["ReservedConcurrentExecutions"].as_i64());
    match reserved {
        Some(0) => println!(
            "  {} gate disabled (reserved concurrency 0) — `dove gate enable` to restore",
            ui::red("●")
        ),
        _ => println!("  {} gate enabled", ui::green("●")),
    }
    Ok(())
}

/// The gate Lambda's `(profile, function name)` from the config + AWS identity.
fn gate_function() -> Result<(Option<String>, String)> {
    let cfg = Registry::load()?.active_self_hosted()?;
    if !cfg.is_full() {
        bail!("this config has no gate — it isn't full tier (`dove provision full`)");
    }
    let out = aws(
        cfg.profile.as_deref(),
        &[
            "sts",
            "get-caller-identity",
            "--query",
            "Account",
            "--output",
            "text",
        ],
    )?;
    if !out.status.success() {
        bail!(
            "resolving the AWS account: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let account = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((cfg.profile, format!("dove-gate-{account}")))
}

fn run(profile: Option<&str>, args: &[&str]) -> Result<()> {
    let out = aws(profile, args)?;
    if out.status.success() {
        return Ok(());
    }
    bail!(
        "aws {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

fn aws(profile: Option<&str>, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new("aws");
    if let Some(p) = profile {
        cmd.args(["--profile", p]);
    }
    cmd.args(args)
        .output()
        .with_context(|| format!("running aws {}", args.join(" ")))
}
