//! dove — send a file out of your own cloud: encrypted, expiring, one command.
//!
//! Simple tier so far (see `docs/designs/dove-v1.md`): provision a private,
//! auto-expiring bucket and share files as presigned links. The encrypted full
//! tier follows.
//!
//! https://dove.sh

mod apigw;
mod breaker;
mod cloudfront;
mod config;
mod crypto;
mod domain;
mod duration;
mod gate;
mod get;
mod ledger;
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
        /// `dove get`. (Always on in the full tier.)
        #[arg(long)]
        encrypt: bool,
        /// Full tier only: how many times the link may be downloaded before it's
        /// spent. Omit for a generous default.
        #[arg(long)]
        downloads: Option<u32>,
        /// Full tier only: PIN-lock the share. The PIN is verified at the gate
        /// (rate-limited, so brute force is prevented) and folded into the key —
        /// send it out of band, separate from the link. `--pin` generates one;
        /// `--pin 4917` sets your own.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        pin: Option<String>,
        /// Full tier only: your name, shown to the recipient *before* they enter
        /// the PIN — a trust signal. Encrypted in the link; the server never sees it.
        #[arg(long)]
        from: Option<String>,
        /// Full tier only: a short message shown alongside your name. Encrypted in
        /// the link; the server never sees it.
        #[arg(long)]
        message: Option<String>,
    },
    /// Fetch and decrypt an encrypted dove share link (key rides the #fragment).
    Get {
        /// The share URL, including its `#key` fragment.
        url: String,
        /// Write to this path instead of the filename from the link.
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// The PIN, if the share is PIN-locked (the sender sends it separately).
        #[arg(long)]
        pin: Option<String>,
    },
    /// Put a custom subdomain in front of the gate (CloudFront + ACM). Full tier.
    Domain {
        #[command(subcommand)]
        action: DomainAction,
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

#[derive(Subcommand)]
enum DomainAction {
    /// Add a custom subdomain (e.g. share.dove.sh) — provisions the cert and
    /// CloudFront, and prints the DNS records to add.
    Add {
        /// The subdomain to serve shares from.
        domain: String,
    },
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
            downloads,
            pin,
            from,
            message,
        } => share::run(&file, &expires, encrypt, downloads, pin, from, message),
        Command::Get { url, out, pin } => get::run(&url, out.as_deref(), pin.as_deref()),
        Command::Domain {
            action: DomainAction::Add { domain },
        } => domain::run(&domain),
        Command::Ls => share::list(),
        Command::Revoke { id } => share::revoke(&id),
        Command::Status => share::status(),
    }
}
