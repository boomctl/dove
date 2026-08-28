//! `dove get <url>` — the symmetric receiver. Split the key out of the URL
//! fragment (never sent to any server), fetch the ciphertext, and stream-decrypt
//! it to a file. Works on any dove share link that carries a `#key`.

use crate::{crypto, ui};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};

pub fn run(url: &str, out: Option<&Path>) -> Result<()> {
    let (base, fragment) = url.rsplit_once('#').ok_or_else(|| {
        anyhow!("this link has no key — it isn't a dove-encrypted share (nothing after `#`)")
    })?;
    let key = crypto::key_from_fragment(fragment)?;
    let out_path = out
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(filename_from_url(base)));

    let resp = ureq::get(base)
        .call()
        .map_err(|e| anyhow!("fetching the share failed: {}", transport_err(e)))?;
    if resp.status() >= 300 {
        bail!(
            "the share link returned HTTP {} — it may have expired or been revoked",
            resp.status()
        );
    }
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

/// Derive the output filename from the URL's last path segment (percent-decoded),
/// ignoring the query string.
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
