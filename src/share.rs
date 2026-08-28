//! `dove share <file> --expires <dur>` — upload a file and print an expiring
//! presigned link. The terminal echo of the marketing mock: a dotted upload
//! bar, the size, the URL, and a quiet "expires in …" line.

use crate::config::Config;
use crate::s3::Store;
use crate::{duration as dur, ui};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub fn run(path: &Path, expires: &str) -> Result<()> {
    let ttl = dur::parse(expires)?;
    if !dur::within_presign_limit(ttl) {
        bail!(
            "--expires {expires} is over the 7-day limit for the simple tier's presigned links.\n\
             Use 7d or less. Longer-lived shares (and download limits, and encryption) are the \
             full tier — see https://dove.sh."
        );
    }
    // Fail fast if not provisioned, before we spend time zipping a directory.
    let cfg = Config::load()?;
    let store = Store::new(&cfg)?;

    // A file uploads as-is; a directory is zipped to a temp file first.
    let (upload, name, temp) = prepare_upload(path)?;
    let key = share_key(&name);

    let size = std::fs::metadata(&upload)?.len();
    let bar = ui::Progress::new("uploading", size);
    let uploaded = store.put_file(&key, &upload, |done| bar.set(done));
    if let Some(tmp) = &temp {
        let _ = std::fs::remove_file(tmp); // clean the temp zip, success or not
    }
    uploaded?;
    bar.finish();
    ui::status("uploaded", &ui::human_size(size));

    let url = store.presign_get(&key, ttl);
    ui::share_result(&url, &format!("expires in {}", dur::human_long(ttl)));
    Ok(())
}

/// Resolve what to upload and under what name: a file as-is, or a directory
/// zipped into a temp `<dirname>.zip` (the third element is the temp path to
/// clean up afterward, if any).
fn prepare_upload(path: &Path) -> Result<(PathBuf, String, Option<PathBuf>)> {
    if path.is_file() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("{} has no usable filename", path.display()))?;
        Ok((path.to_path_buf(), name.to_string(), None))
    } else if path.is_dir() {
        let dirname = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("{} has no usable directory name", path.display()))?;
        let tmp = temp_zip_path();
        ui::step("zipping directory", || zip_dir(path, &tmp))?;
        Ok((tmp.clone(), format!("{dirname}.zip"), Some(tmp)))
    } else {
        bail!("not a file or directory: {}", path.display())
    }
}

/// A unique temp path for the zip we build before upload.
fn temp_zip_path() -> PathBuf {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("OS RNG unavailable");
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    std::env::temp_dir().join(format!("dove-{hex}.zip"))
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

/// `dove ls` — the shares currently in the bucket (filename + share id).
pub fn list() -> Result<()> {
    let store = Store::new(&Config::load()?)?;
    let keys = store.list("")?;
    if keys.is_empty() {
        eprintln!("no shares yet — `dove share <file>` to make one");
        return Ok(());
    }
    for key in keys {
        println!("{}", share_row(&key));
    }
    Ok(())
}

/// `dove revoke <id>` — delete a share early, so its link 404s (it would have
/// been reaped by the lifecycle rule anyway).
pub fn revoke(id: &str) -> Result<()> {
    let store = Store::new(&Config::load()?)?;
    let keys = store.list(&format!("{id}/"))?;
    let key = keys
        .first()
        .ok_or_else(|| anyhow!("no share with id {id}"))?;
    store.delete_object(key)?;
    let name = key.split_once('/').map(|(_, n)| n).unwrap_or(key);
    println!("revoked {name} ({id}) — the link now 404s");
    Ok(())
}

/// `dove status` — what's provisioned, and whether the bucket is reachable.
pub fn status() -> Result<()> {
    let cfg = Config::load()?;
    println!("  {} {}", ui::dim("bucket "), cfg.bucket);
    println!("  {} {}", ui::dim("region "), cfg.region);
    if let Some(p) = &cfg.profile {
        println!("  {} {}", ui::dim("profile"), p);
    }
    match Store::new(&cfg).and_then(|s| s.list("")) {
        Ok(keys) => println!("  {} {}", ui::dim("shares "), keys.len()),
        Err(e) => eprintln!("  {} couldn't reach the bucket: {e:#}", ui::dim("shares ")),
    }
    Ok(())
}

/// One `ls` row: filename then the dim share id. Pure, so it's testable.
fn share_row(key: &str) -> String {
    match key.split_once('/') {
        Some((id, name)) => format!("  {}  {}", name, ui::dim(id)),
        None => format!("  {key}"),
    }
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

    #[test]
    fn share_row_shows_name_and_id() {
        let row = share_row("ab12cd34/report.pdf");
        assert!(row.contains("report.pdf"), "{row}");
        assert!(row.contains("ab12cd34"), "{row}");
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
}
