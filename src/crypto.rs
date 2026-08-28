//! The full tier's encryption engine: chunked AES-256-GCM, streaming, with a
//! random key destined for the URL fragment. Same bytes on both ends (Rust and
//! WebCrypto both speak AES-GCM), so `dove get` and the browser page decrypt
//! the same container.
//!
//! Container format (all integers big-endian):
//!
//! ```text
//! header:  "DOVE" (4) | version:u8 | nonce_prefix:[u8;8] | chunk_size:u32
//! chunk:   is_last:u8 | ct_len:u32 | ciphertext(ct_len)      (repeated)
//! ```
//!
//! Each chunk is AES-256-GCM over one plaintext block. The 12-byte nonce is
//! `nonce_prefix || counter` (counter never repeats within a file, prefix is
//! random per file — so nonces never reuse). The **counter and the is_last flag
//! are the AAD**, so reordering chunks, flipping the terminal flag, or dropping
//! the last chunk all fail authentication. A stream that ends before an
//! `is_last = 1` chunk is a truncation and is rejected.

// Consumed by `dove get` and encrypted `share` (next slices).
#![allow(dead_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::io::{Read, Write};

const MAGIC: &[u8; 4] = b"DOVE";
const VERSION: u8 = 1;
/// Default plaintext chunk size: 1 MiB. Small enough to stream, big enough that
/// per-chunk overhead (16-byte tag + 5-byte framing) is negligible.
pub const DEFAULT_CHUNK: usize = 1 << 20;

/// A fresh random 256-bit content key.
pub fn gen_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("OS RNG unavailable");
    k
}

/// Encode a key for the URL fragment (base64url, no padding).
pub fn key_to_fragment(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

/// Decode a key from a URL fragment.
pub fn key_from_fragment(s: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|_| anyhow!("invalid key in the link"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("key in the link is the wrong length"))
}

/// PBKDF2 iterations for PIN-locked shares. High enough that a leaked ciphertext
/// (past the gate) resists offline PIN brute force; fast enough (~100-200ms) that
/// a legitimate unlock is instant. Both Rust and WebCrypto run the same count.
pub const PBKDF2_ITERS: u32 = 600_000;

/// Derive the content key for a PIN-locked share: `PBKDF2-HMAC-SHA256(PIN,
/// salt = fragment_secret)`. The fragment carries only `fragment_secret` (high
/// entropy); the PIN (delivered out of band) is the second factor folded in. The
/// server never sees either, so end-to-end confidentiality holds. WebCrypto's
/// PBKDF2 with the same inputs produces byte-identical output.
pub fn derive_key(pin: &str, fragment_secret: &[u8; 32]) -> [u8; 32] {
    pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(pin.as_bytes(), fragment_secret, PBKDF2_ITERS)
}

/// The salted hash the gate stores to verify a PIN online: `hex(SHA-256(id ":"
/// pin))`. The gate rate-limits and locks, so this need only resist a DB leak,
/// not an online guessing attack. The Python gate computes the same string.
pub fn pin_hash(share_id: &str, pin: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(share_id.as_bytes());
    h.update(b":");
    h.update(pin.as_bytes());
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Encrypt `reader` into `writer` as the chunked container above.
pub fn encrypt<R: Read, W: Write>(
    key: &[u8; 32],
    chunk_size: usize,
    mut reader: R,
    mut writer: W,
) -> Result<()> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut prefix = [0u8; 8];
    getrandom::getrandom(&mut prefix).expect("OS RNG unavailable");

    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION])?;
    writer.write_all(&prefix)?;
    writer.write_all(&(chunk_size as u32).to_be_bytes())?;

    let mut buf = vec![0u8; chunk_size];
    let mut counter: u32 = 0;
    loop {
        let n = read_full(&mut reader, &mut buf)?;
        let is_last = n < chunk_size; // a short (incl. empty) read means EOF
        let ct = cipher
            .encrypt(
                &nonce(&prefix, counter),
                Payload {
                    msg: &buf[..n],
                    aad: &aad(counter, is_last),
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?;
        writer.write_all(&[is_last as u8])?;
        writer.write_all(&(ct.len() as u32).to_be_bytes())?;
        writer.write_all(&ct)?;
        if is_last {
            break;
        }
        counter += 1;
    }
    Ok(())
}

/// Decrypt the chunked container from `reader` into `writer`. Fails on a wrong
/// key, any tampering, reordering, or truncation.
pub fn decrypt<R: Read, W: Write>(key: &[u8; 32], mut reader: R, mut writer: W) -> Result<()> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");

    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|_| anyhow!("not a dove-encrypted file"))?;
    if &magic != MAGIC {
        bail!("not a dove-encrypted file");
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver)?;
    if ver[0] != VERSION {
        bail!("unsupported dove format version {}", ver[0]);
    }
    let mut prefix = [0u8; 8];
    reader.read_exact(&mut prefix)?;
    let mut _chunk_size = [0u8; 4];
    reader.read_exact(&mut _chunk_size)?; // informational

    let mut counter: u32 = 0;
    loop {
        let mut flag = [0u8; 1];
        if reader.read(&mut flag)? == 0 {
            bail!("truncated: the file ended before its final chunk");
        }
        let is_last = flag[0];
        let mut len = [0u8; 4];
        reader.read_exact(&mut len)?;
        let mut ct = vec![0u8; u32::from_be_bytes(len) as usize];
        reader.read_exact(&mut ct)?;

        let pt = cipher
            .decrypt(
                &nonce(&prefix, counter),
                Payload {
                    msg: &ct,
                    aad: &aad(counter, is_last == 1),
                },
            )
            .map_err(|_| anyhow!("decryption failed — wrong key, or the data was tampered with"))?;
        writer.write_all(&pt)?;
        if is_last == 1 {
            break;
        }
        counter += 1;
    }
    Ok(())
}

/// The 12-byte GCM nonce for a chunk: `prefix(8) || counter(4)`.
fn nonce(prefix: &[u8; 8], counter: u32) -> Nonce<aes_gcm::aead::consts::U12> {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(prefix);
    n[8..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&n)
}

/// The additional authenticated data for a chunk: `counter(4) || is_last(1)`.
fn aad(counter: u32, is_last: bool) -> Vec<u8> {
    let mut a = counter.to_be_bytes().to_vec();
    a.push(is_last as u8);
    a
}

/// Read until `buf` is full or EOF; returns bytes read.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match reader.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8], chunk: usize) -> Vec<u8> {
        let key = gen_key();
        let mut ct = Vec::new();
        encrypt(&key, chunk, data, &mut ct).unwrap();
        let mut pt = Vec::new();
        decrypt(&key, &ct[..], &mut pt).unwrap();
        pt
    }

    #[test]
    fn roundtrips_across_sizes_and_chunk_boundaries() {
        // empty, sub-chunk, exact chunk, exact multiple, and multi-chunk.
        assert_eq!(roundtrip(b"", 16), b"");
        assert_eq!(roundtrip(b"hi", 16), b"hi");
        assert_eq!(roundtrip(&[7u8; 16], 16), vec![7u8; 16]);
        assert_eq!(roundtrip(&[8u8; 32], 16), vec![8u8; 32]);
        assert_eq!(roundtrip(&[9u8; 1000], 64), vec![9u8; 1000]);
    }

    #[test]
    fn wrong_key_fails() {
        let mut ct = Vec::new();
        encrypt(&gen_key(), 16, &b"secret"[..], &mut ct).unwrap();
        let mut pt = Vec::new();
        assert!(decrypt(&gen_key(), &ct[..], &mut pt).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let key = gen_key();
        let mut ct = Vec::new();
        encrypt(&key, 16, &[1u8; 50][..], &mut ct).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1; // flip a bit in the final chunk
        let mut pt = Vec::new();
        assert!(decrypt(&key, &ct[..], &mut pt).is_err());
    }

    #[test]
    fn truncation_is_detected() {
        let key = gen_key();
        let mut ct = Vec::new();
        encrypt(&key, 16, &[1u8; 50][..], &mut ct).unwrap(); // multi-chunk
        ct.truncate(ct.len() / 2); // drop the tail, incl. the terminal chunk
        let mut pt = Vec::new();
        assert!(decrypt(&key, &ct[..], &mut pt).is_err());
    }

    #[test]
    fn key_fragment_round_trips() {
        let key = gen_key();
        assert_eq!(key_from_fragment(&key_to_fragment(&key)).unwrap(), key);
    }

    #[test]
    fn pbkdf2_matches_standard_vector() {
        // Known PBKDF2-HMAC-SHA256 vector (password="password", salt="salt",
        // 1 iteration, 32 bytes) — locks us to standard PBKDF2 so WebCrypto's
        // deriveBits with the same inputs is byte-identical.
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"password", b"salt", 1, &mut key);
        let expect = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(key, expect);
    }

    #[test]
    fn derive_key_binds_pin_and_fragment() {
        let frag = [7u8; 32];
        // Same inputs → same key; different PIN or fragment → different key.
        assert_eq!(derive_key("4917", &frag), derive_key("4917", &frag));
        assert_ne!(derive_key("4917", &frag), derive_key("0000", &frag));
        assert_ne!(derive_key("4917", &frag), derive_key("4917", &[8u8; 32]));
    }

    #[test]
    fn pin_hash_is_stable_and_salted_by_id() {
        // Deterministic, and the id salts it so the same PIN hashes differently
        // per share (must match the Python gate's sha256(id ":" pin)).
        assert_eq!(pin_hash("abc123", "4917"), pin_hash("abc123", "4917"));
        assert_ne!(pin_hash("abc123", "4917"), pin_hash("def456", "4917"));
        assert_eq!(pin_hash("abc123", "4917").len(), 64);
    }
}
