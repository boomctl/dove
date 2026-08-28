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

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Provision the share bucket in your AWS account — private, all public
    /// access blocked, objects auto-delete on a lifecycle rule.
    Provision {
        /// The S3 bucket to create (must be globally unique).
        #[arg(long)]
        bucket: String,
        #[arg(long, default_value = "us-east-1")]
        region: String,
        /// AWS profile to use; omit to pick interactively.
        #[arg(long)]
        profile: Option<String>,
        /// Days after which shared objects auto-delete.
        #[arg(long, default_value_t = 7)]
        expire_days: u32,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Provision {
            bucket,
            region,
            profile,
            expire_days,
        } => provision::run(&provision::ProvisionArgs {
            bucket,
            region,
            profile,
            expire_days,
        }),
    }
}
