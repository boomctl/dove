//! `dove share <file> --expires <dur>` — upload a file and print an expiring
//! presigned link. The terminal echo of the marketing mock: a dotted upload
//! bar, the size, the URL, and a quiet "expires in …" line.

use crate::config::Config;
use crate::s3::Store;
use crate::{crypto, duration as dur, ui};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{BufWriter, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    // Fail fast if not provisioned, before we spend time zipping/encrypting.
    let cfg = Config::load()?;
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
    let store = Store::new(&cfg)?;
    let (source, name, zip_temp) = prepare_upload(path)?;

    if cfg.is_full() {
        return share_full(
            &cfg,
            &store,
            &source,
            &name,
            ttl,
            downloads.unwrap_or(100),
            pin,
            from,
            message,
            zip_temp,
        );
    }

    // Simple tier: presigned links, capped at 7 days, optional --encrypt.
    if !dur::within_presign_limit(ttl) {
        bail!(
            "--expires {expires} is over the 7-day limit for the simple tier's presigned links.\n\
             Use 7d or less. Longer-lived shares and download limits are the full tier — \
             provision it with `dove provision full`."
        );
    }
    let (upload, ct_temp, fragment) = if encrypt {
        let content_key = crypto::gen_key();
        let ct = temp_zip_path();
        ui::step("encrypting", || {
            let reader = File::open(&source)?;
            let writer = BufWriter::new(File::create(&ct)?);
            crypto::encrypt(&content_key, crypto::DEFAULT_CHUNK, reader, writer)
        })?;
        (
            ct.clone(),
            Some(ct),
            Some(crypto::key_to_fragment(&content_key)),
        )
    } else {
        (source.clone(), None, None)
    };

    let object_key = share_key(&name);
    let size = std::fs::metadata(&upload)?.len();
    let bar = ui::Progress::new("uploading", size);
    let uploaded = store.put_file(&object_key, &upload, |done| bar.set(done));
    for t in [zip_temp, ct_temp].into_iter().flatten() {
        let _ = std::fs::remove_file(t);
    }
    uploaded?;
    bar.finish();
    ui::status("uploaded", &ui::human_size(size));

    let mut url = store.presign_get(&object_key, ttl);
    if let Some(frag) = fragment {
        url.push('#');
        url.push_str(&frag);
    }
    ui::share_result(&url, &format!("expires in {}", dur::human_long(ttl)));
    Ok(())
}

/// Full tier: always encrypt, register a download policy in DynamoDB, and hand
/// out a gate link (`<gate>/d/<id>#<secret>.<meta>`). The gate enforces the
/// budget; the key **and** the filename + trust metadata ride the fragment, so
/// the server sees neither the content nor the real filename.
#[allow(clippy::too_many_arguments)]
fn share_full(
    cfg: &Config,
    store: &Store,
    source: &Path,
    name: &str,
    ttl: Duration,
    downloads: u32,
    pin: Option<String>,
    from: Option<String>,
    message: Option<String>,
    zip_temp: Option<PathBuf>,
) -> Result<()> {
    let share_id = random_id();

    // The fragment always carries a random secret. Without a PIN it *is* the
    // content key. With a PIN, the content key is PBKDF2(PIN, secret) — the PIN
    // (delivered out of band) is the second factor and the gate also verifies it.
    let fragment_secret = crypto::gen_key();
    let (content_key, resolved_pin) = match &pin {
        Some(p) => {
            let value = if p.trim().is_empty() {
                gen_pin()
            } else {
                p.trim().to_string()
            };
            (crypto::derive_key(&value, &fragment_secret), Some(value))
        }
        None => (fragment_secret, None),
    };
    let pin_hash = resolved_pin
        .as_ref()
        .map(|p| crypto::pin_hash(&share_id, p));

    let ct = temp_zip_path();
    ui::step("encrypting", || {
        let reader = File::open(source)?;
        let writer = BufWriter::new(File::create(&ct)?);
        crypto::encrypt(&content_key, crypto::DEFAULT_CHUNK, reader, writer)
    })?;

    let object_key = share_id.clone(); // name-free: the filename is E2E, in the fragment
    let size = std::fs::metadata(&ct)?.len();
    let bar = ui::Progress::new("uploading", size);
    let uploaded = store.put_file(&object_key, &ct, |done| bar.set(done));
    for t in [zip_temp, Some(ct)].into_iter().flatten() {
        let _ = std::fs::remove_file(t);
    }
    uploaded?;
    bar.finish();
    ui::status("uploaded", &ui::human_size(size));

    // The filename + trust (sender name, message) ride the fragment, encrypted
    // with the secret — the server never sees them. Shown pre-PIN by the page.
    let meta_json = serde_json::json!({
        "name": name,
        "from": from.as_deref().unwrap_or(""),
        "msg": message.as_deref().unwrap_or(""),
    })
    .to_string();
    let meta_blob = crypto::encrypt_meta(&fragment_secret, meta_json.as_bytes());

    let expires_at = now_epoch() + ttl.as_secs();
    ui::step("registering policy", || {
        put_policy_item(
            cfg,
            &share_id,
            &object_key,
            downloads,
            expires_at,
            size,
            pin_hash.as_deref(),
        )
    })?;

    // Keep a local id → filename record so `dove ls` can show it (the server,
    // holding only a name-free key, can't). Best-effort; never fails the share.
    let _ = crate::ledger::record(crate::ledger::ShareRecord {
        id: share_id.clone(),
        name: name.to_string(),
        from: from.clone(),
        created_at: now_epoch(),
        expires_at,
        downloads,
    });

    let gate = cfg
        .gate_url
        .as_ref()
        .ok_or_else(|| anyhow!("no gate URL in config"))?;
    let url = format!(
        "{gate}/d/{share_id}#{}.{}",
        crypto::key_to_fragment(&fragment_secret),
        meta_blob
    );
    let plural = if downloads == 1 { "" } else { "s" };
    ui::share_result(
        &url,
        &format!(
            "expires in {} · {downloads} download{plural}",
            dur::human_long(ttl)
        ),
    );
    if let Some(p) = resolved_pin {
        ui::pin_notice(&p);
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

/// Write the share's policy row to DynamoDB via the AWS CLI (operator profile).
fn put_policy_item(
    cfg: &Config,
    id: &str,
    s3_key: &str,
    downloads: u32,
    expires_at: u64,
    size: u64,
    pin_hash: Option<&str>,
) -> Result<()> {
    let table = cfg
        .table
        .as_ref()
        .ok_or_else(|| anyhow!("no table in config"))?;
    // `size` is stored so /meta reads it from DynamoDB instead of a per-request
    // S3 HeadObject (cheaper, and one fewer thing the gate touches).
    let mut item = serde_json::json!({
        "id": {"S": id},
        "s3_key": {"S": s3_key},
        "downloads_remaining": {"N": downloads.to_string()},
        "downloads_total": {"N": downloads.to_string()},
        "expires_at": {"N": expires_at.to_string()},
        "created_at": {"N": now_epoch().to_string()},
        "size": {"N": size.to_string()},
    });
    if let Some(hash) = pin_hash {
        // pin_attempts starts at 0; the gate increments on each wrong guess and
        // locks the share once it hits the ceiling.
        item["pin_hash"] = serde_json::json!({"S": hash});
        item["pin_attempts"] = serde_json::json!({"N": "0"});
    }
    let item = item.to_string();
    let mut cmd = Command::new("aws");
    if let Some(p) = &cfg.profile {
        cmd.args(["--profile", p]);
    }
    cmd.args([
        "dynamodb",
        "put-item",
        "--table-name",
        table,
        "--item",
        &item,
    ]);
    let out = cmd.output().context("running aws dynamodb put-item")?;
    if !out.status.success() {
        bail!(
            "registering the share policy failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A 16-hex-char share id — the gate access token in the URL. Unguessable, so a
/// share's download budget can't be exhausted by guessing ids.
fn random_id() -> String {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("OS RNG unavailable");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod full_tests {
    use super::*;

    #[test]
    fn random_id_is_16_hex_and_unique() {
        let a = random_id();
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, random_id());
    }
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

/// `dove ls` — the shares currently in the bucket. Full-tier shares are listed by
/// id only: their filenames are end-to-end encrypted in the link, so the server
/// (and therefore `ls`) genuinely doesn't have them.
pub fn list() -> Result<()> {
    let store = Store::new(&Config::load()?)?;
    let keys = store.list("")?;
    if keys.is_empty() {
        eprintln!("no shares yet — `dove share <file>` to make one");
        return Ok(());
    }
    let names = crate::ledger::names(); // local id → filename map
    for key in keys {
        println!("{}", share_row(&key, &names));
    }
    Ok(())
}

/// `dove revoke <id>` — delete a share early, so its link 404s (it would have
/// been reaped by the lifecycle rule anyway). Handles both name-free full-tier
/// keys (`<id>`) and simple-tier keys (`<id>/<name>`).
pub fn revoke(id: &str) -> Result<()> {
    let store = Store::new(&Config::load()?)?;
    let keys = store.list(id)?;
    let key = keys
        .first()
        .ok_or_else(|| anyhow!("no share with id {id}"))?;
    store.delete_object(key)?;
    let _ = crate::ledger::remove(id);
    println!("revoked {id} — the link now 404s");
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
}
