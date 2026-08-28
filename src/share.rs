//! `dove share <file> --expires <dur>` — upload a file and print an expiring
//! presigned link. The terminal echo of the marketing mock: a dotted upload
//! bar, the size, the URL, and a quiet "expires in …" line.

use crate::config::Config;
use crate::s3::Store;
use crate::{duration as dur, ui};
use anyhow::{anyhow, bail, Result};
use std::path::Path;

pub fn run(file: &Path, expires: &str) -> Result<()> {
    let ttl = dur::parse(expires)?;
    if !dur::within_presign_limit(ttl) {
        bail!(
            "--expires {expires} is over the 7-day limit for the simple tier's presigned links.\n\
             Use 7d or less. Longer-lived shares (and download limits, and encryption) are the \
             full tier — see https://dove.sh."
        );
    }
    if !file.is_file() {
        bail!("not a file: {}", file.display());
    }
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("{} has no usable filename", file.display()))?;

    let cfg = Config::load()?;
    let store = Store::new(&cfg)?;
    let key = share_key(name);

    let size = std::fs::metadata(file)?.len();
    let bar = ui::Progress::new("uploading", size);
    store.put_file(&key, file, |done| bar.set(done))?;
    bar.finish();
    ui::status("uploaded", &ui::human_size(size));

    let url = store.presign_get(&key, ttl);
    ui::share_result(&url, &format!("expires in {}", dur::human_long(ttl)));
    Ok(())
}

/// A share object key: a random prefix so filenames neither collide nor expose
/// a guessable listing — `<8 hex>/<filename>`.
fn share_key(filename: &str) -> String {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("OS RNG unavailable");
    format!(
        "{:02x}{:02x}{:02x}{:02x}/{filename}",
        b[0], b[1], b[2], b[3]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_key_has_random_prefix_and_keeps_the_name() {
        let k = share_key("report.pdf");
        assert!(k.ends_with("/report.pdf"), "{k}");
        let prefix = k.split('/').next().unwrap();
        assert_eq!(prefix.len(), 8);
        assert!(prefix.chars().all(|c| c.is_ascii_hexdigit()));
        // Randomised: two keys for the same name differ.
        assert_ne!(share_key("report.pdf"), share_key("report.pdf"));
    }
}
