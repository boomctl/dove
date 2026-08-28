//! Compact share durations like `3d`, `12h`, `30m`, `90s` — how long a share's
//! link stays valid.

// Consumed by later tasks (`share` / `provision`); allow until they wire it in.
#![allow(dead_code)]

use anyhow::{anyhow, bail, Result};
use std::time::Duration;

/// The SigV4 presigned-URL ceiling: a presigned URL can't outlive its signing
/// credential, and that caps at 7 days. Shares in the simple tier can't exceed
/// this; longer-lived shares are what the full tier is for.
pub const PRESIGN_MAX: Duration = Duration::from_secs(7 * 86_400);

/// Parse `<n><unit>` where unit is `d`/`h`/`m`/`s` (e.g. `3d`, `12h`, `90s`).
/// `n` must be a positive integer.
pub fn parse(s: &str) -> Result<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    if num.is_empty() {
        bail!("duration needs a number, e.g. 3d (got {s:?})");
    }
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow!("duration number out of range in {s:?}"))?;
    if n == 0 {
        bail!("duration must be greater than zero (got {s:?})");
    }
    let secs = match unit {
        "d" => n * 86_400,
        "h" => n * 3_600,
        "m" => n * 60,
        "s" => n,
        "" => bail!("duration needs a unit d/h/m/s, e.g. 3d (got {s:?})"),
        other => bail!("unknown duration unit {other:?} — use d, h, m, or s"),
    };
    Ok(Duration::from_secs(secs))
}

/// Whether `d` is within the presigned-URL ceiling (≤ 7 days).
pub fn within_presign_limit(d: Duration) -> bool {
    d <= PRESIGN_MAX
}

/// Render a duration back to a compact string, using the largest unit that
/// divides it evenly (`259200s` → `3d`, `5400s` → `90m`).
pub fn human(d: Duration) -> String {
    let s = d.as_secs();
    if s == 0 {
        return "0s".to_string();
    }
    if s.is_multiple_of(86_400) {
        format!("{}d", s / 86_400)
    } else if s.is_multiple_of(3_600) {
        format!("{}h", s / 3_600)
    } else if s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

/// A friendly, spelled-out duration for status lines: `2 days`, `1 day`,
/// `12 hours`. Uses the largest unit that divides evenly.
pub fn human_long(d: Duration) -> String {
    let s = d.as_secs();
    let (n, unit) = if s.is_multiple_of(86_400) {
        (s / 86_400, "day")
    } else if s.is_multiple_of(3_600) {
        (s / 3_600, "hour")
    } else if s.is_multiple_of(60) {
        (s / 60, "minute")
    } else {
        (s, "second")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_long_spells_it_out() {
        assert_eq!(human_long(parse("2d").unwrap()), "2 days");
        assert_eq!(human_long(parse("1d").unwrap()), "1 day");
        assert_eq!(human_long(parse("12h").unwrap()), "12 hours");
    }

    #[test]
    fn parses_each_unit() {
        assert_eq!(parse("3d").unwrap(), Duration::from_secs(3 * 86_400));
        assert_eq!(parse("12h").unwrap(), Duration::from_secs(12 * 3_600));
        assert_eq!(parse("30m").unwrap(), Duration::from_secs(30 * 60));
        assert_eq!(parse("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse("  5d ").unwrap(), Duration::from_secs(5 * 86_400));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse("0d").is_err()); // zero
        assert!(parse("d").is_err()); // no number
        assert!(parse("5").is_err()); // no unit
        assert!(parse("5x").is_err()); // bad unit
        assert!(parse("5days").is_err()); // only single-char units
        assert!(parse("").is_err());
    }

    #[test]
    fn presign_limit_is_seven_days() {
        assert!(within_presign_limit(parse("7d").unwrap()));
        assert!(within_presign_limit(parse("168h").unwrap())); // exactly 7d
        assert!(!within_presign_limit(parse("8d").unwrap()));
        assert!(!within_presign_limit(parse("169h").unwrap()));
    }

    #[test]
    fn human_uses_largest_even_unit() {
        assert_eq!(human(parse("3d").unwrap()), "3d");
        assert_eq!(human(parse("12h").unwrap()), "12h");
        assert_eq!(human(parse("90m").unwrap()), "90m");
        assert_eq!(human(Duration::from_secs(90)), "90s");
    }
}
