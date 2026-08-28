//! The access-gate Lambda: its embedded source and a helper to package it for
//! deployment. The gate enforces the download policy (DynamoDB) and redirects to
//! a short-lived presigned S3 URL — it never sees the decryption key.

// Consumed by `dove provision full` (next slice).
#![allow(dead_code)]

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// The gate handler source (Python), embedded so provisioning deploys it with
/// no external files or build step.
pub const SOURCE: &str = include_str!("../assets/gate.py");

/// The Lambda handler entrypoint: file `lambda_function.py`, function `handler`.
pub const HANDLER: &str = "lambda_function.handler";
/// The Lambda runtime the gate targets.
pub const RUNTIME: &str = "python3.12";

/// Write a Lambda deployment zip (containing `lambda_function.py`) to `dest`.
pub fn write_deployment_zip(dest: &Path) -> Result<()> {
    let file =
        std::fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut zip = ZipWriter::new(file);
    zip.start_file("lambda_function.py", SimpleFileOptions::default())?;
    zip.write_all(SOURCE.as_bytes())?;
    zip.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_source_is_the_handler() {
        assert!(SOURCE.contains("def handler(event, _context):"));
        assert!(SOURCE.contains("ConditionExpression"));
        assert!(SOURCE.contains("generate_presigned_url"));
    }

    #[test]
    fn deployment_zip_contains_the_handler_file() {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).unwrap();
        let tag: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dest = std::env::temp_dir().join(format!("dove-gate-{tag}.zip"));
        write_deployment_zip(&dest).unwrap();

        let f = std::fs::File::open(&dest).unwrap();
        let mut archive = zip::ZipArchive::new(f).unwrap();
        assert!(archive.by_name("lambda_function.py").is_ok());
        std::fs::remove_file(&dest).ok();
    }
}
