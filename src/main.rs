//! dove — send a file out of your own cloud: encrypted, expiring, one command.
//!
//! Simple tier so far (see `docs/designs/dove-v1.md`): provision a private,
//! auto-expiring bucket and share files as presigned links. The encrypted full
//! tier follows.
//!
//! https://dove.sh

mod config;
mod duration;
mod provision;
mod s3;
mod secrets;
mod share;
mod ui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "dove",
    version,
    about = "Send a file out of your own cloud — encrypted, expiring, one command."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Provision the share bucket in your AWS account. Just `dove provision
    /// simple` — it asks which AWS profile, and derives the rest.
    Provision {
        /// Which tier to stand up: `simple` today (`full` is coming).
        #[arg(value_enum)]
        tier: provision::Tier,
        /// Override the derived bucket name (default: `dove-shares-<account-id>`).
        #[arg(long)]
        bucket: Option<String>,
        #[arg(long, default_value = "us-east-1")]
        region: String,
        /// AWS profile to use; omit to pick interactively.
        #[arg(long)]
        profile: Option<String>,
        /// Days after which shared objects auto-delete.
        #[arg(long, default_value_t = 7)]
        expire_days: u32,
    },
    /// Share a file: upload it and print a presigned link that auto-expires.
    Share {
        /// The file to share.
        file: PathBuf,
        /// How long the link stays valid (≤ 7d): `3d`, `12h`, `30m`.
        #[arg(long, default_value = "3d")]
        expires: String,
    },
    /// List the shares currently in the bucket.
    Ls,
    /// Revoke a share early by its id, so its link 404s.
    Revoke {
        /// The share id (the prefix shown by `dove ls`).
        id: String,
    },
    /// Show what's provisioned and whether the bucket is reachable.
    Status,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Provision {
            tier,
            bucket,
            region,
            profile,
            expire_days,
        } => provision::run(&provision::ProvisionArgs {
            tier,
            bucket,
            region,
            profile,
            expire_days,
        }),
        Command::Share { file, expires } => share::run(&file, &expires),
        Command::Ls => share::list(),
        Command::Revoke { id } => share::revoke(&id),
        Command::Status => share::status(),
    }
}
