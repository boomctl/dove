//! `dove share <file> --expires <dur>` — upload a file and print an expiring
//! link. The terminal echo of the marketing mock: a dotted upload bar, the
//! size, the URL, and a quiet "expires in …" line.
//!
//! The actual share logic (both the simple-tier presigned-URL path and the
//! full-tier gated/encrypted path) lives in `dove_core::backend::SelfHosted`
//! — this module just resolves what to upload (zipping a directory if
//! needed), asks the active backend to share it, and renders the result.

use crate::cli_progress::CliProgress;
use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use dove_core::config::Registry;
use dove_core::s3::Store;
use dove_core::transfer::{ShareRequest, Transfer};
use dove_core::{backend::SelfHosted, duration as dur};
use std::fs::File;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub fn run(
    path: &Path,
    expires: &str,
    encrypt: bool,
    downloads: Option<u32>,
    pin: Option<String>,
    from: Option<String>,
    message: Option<String>,
) -> Result<()> {
    let ttl = dur::parse(expires)?;
    // Fail fast if not provisioned or the request needs the full tier, before
    // we spend time zipping/encrypting. `SelfHosted::share` re-checks these
    // (it's the source of truth), but bailing here preserves the original
    // fail-before-zip behavior for a directory share.
    let registry = Registry::load()?;
    let cfg = registry.active_self_hosted()?;
    if pin.is_some() && !cfg.is_full() {
        bail!(
            "--pin is a full-tier feature: it's checked at the gate, which the simple tier \
             doesn't have. Provision it with `dove provision full`."
        );
    }
    if (from.is_some() || message.is_some()) && !cfg.is_full() {
        bail!(
            "--from/--message ride an encrypted metadata blob in the full-tier link. \
             Provision it with `dove provision full`."
        );
    }
    // A `--pin` with no value means "generate one for me" — resolved here (not
    // in dove-core) so the CLI still has the plaintext PIN in scope afterward
    // to print the PIN callout; dove-core's `ShareRequest.pin` always carries
    // the final, concrete value.
    let resolved_pin = pin.map(|p| {
        let p = p.trim();
        if p.is_empty() {
            gen_pin()
        } else {
            p.to_string()
        }
    });

    let (upload_path, zip_temp) = prepare_upload(path)?;

    let backend = SelfHosted::from_backend(registry.active_backend()?)?;
    let progress = CliProgress::new("uploading");
    let req = ShareRequest {
        path: upload_path,
        expires: ttl,
        encrypt,
        downloads,
        pin: resolved_pin.clone(),
        from,
        message,
    };
    let result = backend.share(req, &progress);
    if let Some(t) = zip_temp {
        let _ = std::fs::remove_file(&t);
        if let Some(parent) = t.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
    if result.is_err() {
        progress.fail_pending();
    }
    let share = result?;

    if cfg.is_full() {
        let downloads = downloads.unwrap_or(100);
        let plural = if downloads == 1 { "" } else { "s" };
        ui::share_result(
            &share.link,
            &format!(
                "expires in {} · {downloads} download{plural}",
                dur::human_long(ttl)
            ),
        );
        if let Some(p) = resolved_pin {
            ui::pin_notice(&p);
        }
    } else {
        ui::share_result(&share.link, &format!("expires in {}", dur::human_long(ttl)));
    }
    Ok(())
}

/// A random 6-digit PIN, zero-padded. Uniform enough for a gate-checked,
/// rate-limited second factor (the gate locks after a handful of wrong tries).
fn gen_pin() -> String {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("OS RNG unavailable");
    format!("{:06}", u32::from_le_bytes(b) % 1_000_000)
}

/// Resolve what to upload and under what name: a file as-is, or a directory
/// zipped into a temp `<dirname>.zip` — kept in its own throwaway temp
/// directory so the archive's filename is exactly `<dirname>.zip` (dove-core
/// derives the share's name from the uploaded path's filename, and that name
/// rides the link/metadata, so it must match what a recipient would expect).
/// The second element is that temp path, to clean up afterward, if any.
fn prepare_upload(path: &Path) -> Result<(PathBuf, Option<PathBuf>)> {
    if path.is_file() {
        Ok((path.to_path_buf(), None))
    } else if path.is_dir() {
        let dirname = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("{} has no usable directory name", path.display()))?;
        let dir = temp_zip_dir();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let tmp = dir.join(format!("{dirname}.zip"));
        ui::step("zipping directory", || zip_dir(path, &tmp))?;
        Ok((tmp.clone(), Some(tmp)))
    } else {
        bail!("not a file or directory: {}", path.display())
    }
}

/// A unique, freshly-created temp directory to hold the zip built from a
/// shared directory (so the zip's own filename can stay `<dirname>.zip`).
fn temp_zip_dir() -> PathBuf {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("OS RNG unavailable");
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    std::env::temp_dir().join(format!("dove-{hex}"))
}

/// Zip `dir` into `dest`, with the directory's own name as the top-level folder
/// inside the archive. Deflate-compressed. Symlinks are skipped (no loops, no
/// escaping the tree).
fn zip_dir(dir: &Path, dest: &Path) -> Result<()> {
    let file = File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let base = dir.parent().unwrap_or(dir);
    add_tree(&mut zip, base, dir, opts)?;
    zip.finish()?;
    Ok(())
}

fn add_tree<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    base: &Path,
    dir: &Path,
    opts: SimpleFileOptions,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if file_type.is_dir() {
            zip.add_directory(&rel, opts)?;
            add_tree(zip, base, &path, opts)?;
        } else if file_type.is_file() {
            zip.start_file(&rel, opts)?;
            let mut f = File::open(&path)?;
            std::io::copy(&mut f, zip)?;
        }
        // symlinks (file_type.is_symlink()) are intentionally skipped
    }
    Ok(())
}

/// `dove ls` — the shares currently in the bucket. Full-tier shares are listed by
/// id only: their filenames are end-to-end encrypted in the link, so the server
/// (and therefore `ls`) genuinely doesn't have them.
pub fn list() -> Result<()> {
    let cfg = Registry::load()?.active_self_hosted()?;
    let store = Store::new(&cfg.bucket, &cfg.region, cfg.endpoint.as_deref())?;
    let keys = store.list("")?;
    if keys.is_empty() {
        eprintln!("no shares yet — `dove share <file>` to make one");
        return Ok(());
    }
    let names = dove_core::ledger::names(); // local id → filename map
    for key in keys {
        println!("{}", share_row(&key, &names));
    }
    Ok(())
}

/// `dove revoke <id>` — delete a share early, so its link 404s (it would have
/// been reaped by the lifecycle rule anyway). Handles both name-free full-tier
/// keys (`<id>`) and simple-tier keys (`<id>/<name>`).
pub fn revoke(id: &str) -> Result<()> {
    let cfg = Registry::load()?.active_self_hosted()?;
    let store = Store::new(&cfg.bucket, &cfg.region, cfg.endpoint.as_deref())?;
    let keys = store.list(id)?;
    let key = keys
        .first()
        .ok_or_else(|| anyhow!("no share with id {id}"))?;
    store.delete_object(key)?;
    let _ = dove_core::ledger::remove(id);
    println!("revoked {id} — the link now 404s");
    Ok(())
}

/// `dove status` — what's provisioned, and whether the bucket is reachable.
pub fn status() -> Result<()> {
    let cfg = Registry::load()?.active_self_hosted()?;
    println!("  {} {}", ui::dim("bucket "), cfg.bucket);
    println!("  {} {}", ui::dim("region "), cfg.region);
    if let Some(p) = &cfg.profile {
        println!("  {} {}", ui::dim("profile"), p);
    }
    match Store::new(&cfg.bucket, &cfg.region, cfg.endpoint.as_deref()).and_then(|s| s.list("")) {
        Ok(keys) => println!("  {} {}", ui::dim("shares "), keys.len()),
        Err(e) => eprintln!("  {} couldn't reach the bucket: {e:#}", ui::dim("shares ")),
    }
    Ok(())
}

/// One `ls` row: filename then the dim share id. The filename comes from the key
/// itself for simple-tier shares (`<id>/<name>`), or from the local ledger for
/// full-tier name-free keys (`<id>`). Pure, so it's testable.
fn share_row(key: &str, names: &std::collections::HashMap<String, String>) -> String {
    match key.split_once('/') {
        Some((id, name)) => format!("  {}  {}", name, ui::dim(id)),
        None => match names.get(key) {
            Some(name) => format!("  {}  {}", name, ui::dim(key)),
            None => format!("  {}  {}", ui::dim("(encrypted name)"), ui::dim(key)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_row_shows_name_and_id() {
        use std::collections::HashMap;
        // simple-tier key: filename comes from the key itself
        let row = share_row("ab12cd34/report.pdf", &HashMap::new());
        assert!(
            row.contains("report.pdf") && row.contains("ab12cd34"),
            "{row}"
        );
        // full-tier name-free key: filename comes from the local ledger
        let names = HashMap::from([("890ad620f2c0b442".to_string(), "vault.txt".to_string())]);
        let row = share_row("890ad620f2c0b442", &names);
        assert!(
            row.contains("vault.txt") && row.contains("890ad620f2c0b442"),
            "{row}"
        );
        // unknown id → placeholder, still shows the id
        let row = share_row("deadbeefdeadbeef", &HashMap::new());
        assert!(
            row.contains("encrypted name") && row.contains("deadbeef"),
            "{row}"
        );
    }

    #[test]
    fn zip_dir_archives_the_tree_under_the_dir_name() {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).unwrap();
        let tag: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("dove-ziptest-{tag}"));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"hi").unwrap();
        std::fs::write(dir.join("sub/b.txt"), b"yo").unwrap();

        let zip_path = temp_zip_path();
        zip_dir(&dir, &zip_path).unwrap();

        let f = File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(f).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        let dirname = dir.file_name().unwrap().to_string_lossy();
        assert!(
            names.iter().any(|n| *n == format!("{dirname}/a.txt")),
            "{names:?}"
        );
        assert!(names.iter().any(|n| n.ends_with("sub/b.txt")), "{names:?}");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_file(&zip_path).ok();
    }

    /// A standalone temp zip path for the test above (prepare_upload uses
    /// `temp_zip_dir` instead, so the archive's own filename isn't lost).
    fn temp_zip_path() -> PathBuf {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).unwrap();
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir().join(format!("dove-{hex}.zip"))
    }
}
