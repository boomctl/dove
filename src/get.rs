//! `dove get <url>` — the symmetric receiver. Split the key out of the URL
//! fragment (never sent to any server), fetch the ciphertext, and stream-decrypt
//! it to a file. Works on any dove share link that carries a `#key`.

use crate::{crypto, ui};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};

pub fn run(url: &str, out: Option<&Path>, pin: Option<&str>) -> Result<()> {
    let (base, fragment) = url.rsplit_once('#').ok_or_else(|| {
        anyhow!("this link has no key — it isn't a dove-encrypted share (nothing after `#`)")
    })?;
    // The fragment is `<secret>` or `<secret>.<encrypted-metadata>`. Without a PIN
    // the secret *is* the key; with one, the key is PBKDF2(PIN, secret). The
    // metadata (filename + trust) is decrypted with the secret — the server never
    // saw it.
    let (secret, meta) = parse_fragment(fragment)?;
    let key = match pin {
        Some(p) => crypto::derive_key(p, &secret),
        None => secret,
    };
    // Trust: show who the file is from before pulling it.
    if let Some((_, from, msg)) = &meta {
        if !from.is_empty() {
            eprintln!("  {} {}", ui::dim("from"), ui::bold(from));
            if !msg.is_empty() {
                eprintln!("       {msg}");
            }
        }
    }
    let meta_name = meta
        .as_ref()
        .map(|(n, _, _)| n.clone())
        .filter(|n| !n.is_empty());
    let out_path = out
        .map(PathBuf::from)
        .or_else(|| meta_name.map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(filename_from_url(base)));

    // A full-tier link is the browser page URL (`…/d/<id>/<name>`); the CLI
    // wants the gate's download endpoint (`…/dl/<id>`, which decrements + 302s).
    // A simple-tier presigned URL is fetched as-is. The PIN rides a query param
    // the gate checks (only on a gate link — never on a signed presigned URL).
    let mut fetch_url = to_download_url(base);
    if let Some(p) = pin {
        if fetch_url.contains("/dl/") {
            fetch_url.push_str(&format!("?pin={p}"));
        }
    }
    let resp = match ureq::get(&fetch_url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, resp)) => bail!("{}", gate_error(code, resp, pin.is_some())),
        Err(e @ ureq::Error::Transport(_)) => {
            bail!("fetching the share failed: {}", transport_err(e))
        }
    };
    let total: u64 = resp
        .header("Content-Length")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let bar = ui::Progress::new("downloading", total.max(1));
    let reader = CountingReader {
        inner: resp.into_reader(),
        seen: 0,
        bar: &bar,
    };
    let file = BufWriter::new(
        File::create(&out_path).with_context(|| format!("creating {}", out_path.display()))?,
    );
    crypto::decrypt(&key, reader, file)?;
    bar.finish();
    ui::done("downloaded", &format!("→ {}", out_path.display()));
    Ok(())
}

/// Split the fragment into the secret and (optional) decrypted metadata. The
/// fragment is `<secret>` (older/simple links) or `<secret>.<meta>` (full tier).
/// Returns the 32-byte secret and, if present, `(filename, from, message)`.
#[allow(clippy::type_complexity)]
fn parse_fragment(fragment: &str) -> Result<([u8; 32], Option<(String, String, String)>)> {
    let (secret_b64, meta_b64) = match fragment.split_once('.') {
        Some((s, m)) => (s, Some(m)),
        None => (fragment, None),
    };
    let secret = crypto::key_from_fragment(secret_b64)?;
    let meta = match meta_b64 {
        Some(m) => {
            let plain = crypto::decrypt_meta(&secret, m)?;
            let v: serde_json::Value =
                serde_json::from_slice(&plain).map_err(|_| anyhow!("unreadable link metadata"))?;
            let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
            Some((s("name"), s("from"), s("msg")))
        }
        None => None,
    };
    Ok((secret, meta))
}

/// Derive the output filename from the URL's last path segment (percent-decoded),
/// ignoring the query string. Fallback when a link carries no metadata.
fn filename_from_url(base: &str) -> String {
    let path = base.split('?').next().unwrap_or(base);
    let name = path.rsplit('/').next().unwrap_or("download");
    let decoded = percent_decode(name);
    if decoded.is_empty() {
        "download".to_string()
    } else {
        decoded
    }
}

/// Turn a full-tier page URL (`scheme://host/d/<id>/<name>`) into the gate's
/// download endpoint (`scheme://host/dl/<id>`). Any other URL (e.g. a simple-tier
/// presigned URL) is returned unchanged.
fn to_download_url(base: &str) -> String {
    if let Some(scheme_end) = base.find("://") {
        let after = &base[scheme_end + 3..];
        if let Some(slash) = after.find('/') {
            let host = &base[..scheme_end + 3 + slash];
            let path = after[slash..].split('?').next().unwrap_or("");
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if segs.len() >= 2 && segs[0] == "d" {
                return format!("{host}/dl/{}", segs[1]);
            }
        }
    }
    base.to_string()
}

/// Minimal percent-decoding for a URL path segment (`%20` → space, etc.).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Turn a gate error status (+ its JSON body) into a message a recipient can act
/// on: needs a PIN, wrong PIN with tries left, locked out, or gone.
fn gate_error(code: u16, resp: ureq::Response, had_pin: bool) -> String {
    let body = resp.into_string().unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let attempts = json.get("attempts_remaining").and_then(|v| v.as_u64());
    match code {
        401 if !had_pin => {
            "this share is PIN-locked — pass --pin <PIN> (the sender sent it separately)".into()
        }
        401 => match attempts {
            Some(n) => format!(
                "wrong PIN — {n} attempt{} left",
                if n == 1 { "" } else { "s" }
            ),
            None => "wrong PIN".into(),
        },
        423 => "this share is locked — too many wrong PINs. Ask the sender to re-share.".into(),
        410 => "this share has expired or reached its download limit".into(),
        _ => format!("the share link returned HTTP {code} — it may have expired or been revoked"),
    }
}

/// A short transport-error string that never echoes the (signed) request URL.
fn transport_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("HTTP {code}"),
        ureq::Error::Transport(t) => t.kind().to_string(),
    }
}

/// Wraps the response body to drive the download progress bar.
struct CountingReader<'a, R> {
    inner: R,
    seen: u64,
    bar: &'a ui::Progress,
}

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.seen += k as u64;
        self.bar.set(self.seen);
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_download_url_maps_gate_page_to_dl_endpoint() {
        assert_eq!(
            to_download_url("https://abc.lambda-url.us-east-1.on.aws/d/8f3a/report.pdf"),
            "https://abc.lambda-url.us-east-1.on.aws/dl/8f3a"
        );
        // A simple-tier presigned URL is untouched.
        let presigned = "https://b.s3.amazonaws.com/ab12/report.pdf?X-Amz-Sig=x";
        assert_eq!(to_download_url(presigned), presigned);
    }

    #[test]
    fn filename_from_url_takes_last_segment_and_decodes() {
        assert_eq!(
            filename_from_url("https://b.s3.amazonaws.com/ab12/report.pdf?X-Amz-Sig=x"),
            "report.pdf"
        );
        assert_eq!(
            filename_from_url("https://b/ab12/quarterly%20report.pdf?q=1"),
            "quarterly report.pdf"
        );
    }
}
