//! dove — send a file out of your own cloud: encrypted, expiring, one command.
//!
//! Simple tier so far (see `docs/designs/dove-v1.md`): provision a private,
//! auto-expiring bucket and share files as presigned links. The encrypted full
//! tier follows.
//!
//! https://dove.sh

mod config;
mod crypto;
mod duration;
mod get;
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
    /// Share a file (or a directory, auto-zipped): upload it and print a
    /// presigned link that auto-expires.
    Share {
        /// The file or directory to share. A directory is zipped first.
        file: PathBuf,
        /// How long the link stays valid (≤ 7d): `3d`, `12h`, `30m`.
        #[arg(long, default_value = "3d")]
        expires: String,
        /// Encrypt end-to-end: the file is encrypted before upload and the key
        /// rides the link's `#fragment`, never sent to a server. Fetch with
        /// `dove get`.
        #[arg(long)]
        encrypt: bool,
    },
    /// Fetch and decrypt an encrypted dove share link (key rides the #fragment).
    Get {
        /// The share URL, including its `#key` fragment.
        url: String,
        /// Write to this path instead of the filename from the link.
        #[arg(short, long)]
        out: Option<PathBuf>,
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
        Command::Share {
            file,
            expires,
            encrypt,
        } => share::run(&file, &expires, encrypt),
        Command::Get { url, out } => get::run(&url, out.as_deref()),
        Command::Ls => share::list(),
        Command::Revoke { id } => share::revoke(&id),
        Command::Status => share::status(),
    }
}
