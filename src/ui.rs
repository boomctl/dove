//! The dove CLI look: muted labels, bright values, a dotted progress bar, and a
//! prominent share URL — the terminal echo of the marketing mock. Everything is
//! TTY-aware: on a real terminal you get the styled, animated version; piped or
//! in CI, `dove share` prints just the bare URL on stdout so `URL=$(dove share
//! f)` works and nothing else is in the way.

use std::io::{IsTerminal, Write};

fn tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Style only when attached to a terminal and `NO_COLOR` isn't set.
fn colored() -> bool {
    tty() && std::env::var_os("NO_COLOR").is_none()
}

fn wrap(s: &str, code: &str) -> String {
    if colored() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn dim(s: &str) -> String {
    wrap(s, "2")
}
pub fn bold(s: &str) -> String {
    wrap(s, "1")
}
pub fn green(s: &str) -> String {
    wrap(s, "32")
}
pub fn red(s: &str) -> String {
    wrap(s, "31")
}

/// A section heading (bold, with breathing room) — e.g. `dove provision · simple`.
pub fn heading(s: &str) {
    eprintln!("\n  {}\n", bold(s));
}

/// An aligned `label   value` line: dim, left-padded label then the value.
pub fn field(label: &str, value: &str) {
    eprintln!("  {}  {}", dim(&format!("{label:<8}")), value);
}

/// A dotted step's opening half: the dim, padded label followed by a midline
/// dot, with no trailing newline — `step_end` (or `step`'s own
/// closure-wrapping) finishes the line in place via `\r`. Split out of `step`
/// so a caller that reports progress through a callback (rather than a
/// wrapped closure — see `CliProgress`) can drive the same two-line dance.
pub fn step_begin(label: &str) {
    let padded = format!("{label:<24}");
    if tty() {
        eprint!("  {} {}", dim(&padded), dim("·"));
        let _ = std::io::stderr().flush();
    }
}

/// Finish a dotted step opened by `step_begin`, overwriting the trailing dot
/// with a green ✓ (or red ✗ on failure).
pub fn step_end(label: &str, ok: bool) {
    let padded = format!("{label:<24}");
    let mark = if ok { green("✓") } else { red("✗") };
    if tty() {
        eprintln!("\r  {} {}", dim(&padded), mark);
    }
}

/// Run a provisioning step with a trailing ✓/✗ — dim label, green check on
/// success, red cross on failure. Returns the step's result unchanged.
pub fn step<T>(label: &str, work: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
    step_begin(label);
    let result = work();
    step_end(label, result.is_ok());
    result
}

/// A final success line: green ✓, a bold subject, and a dim note beneath.
pub fn done(subject: &str, note: &str) {
    eprintln!("\n  {} {}", green("✓"), bold(subject));
    if !note.is_empty() {
        eprintln!("  {}", dim(note));
    }
}

/// Human-readable byte size: `842 MB`, `1.4 GB`. Bytes/KB/MB are whole; GB/TB
/// carry one decimal.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut b = bytes as f64;
    let mut i = 0;
    while b >= 1024.0 && i < UNITS.len() - 1 {
        b /= 1024.0;
        i += 1;
    }
    if i <= 2 {
        format!("{} {}", b.round() as u64, UNITS[i])
    } else {
        format!("{b:.1} {}", UNITS[i])
    }
}

/// How many of `dots` are "filled" at `done/total` — the pure core of the bar,
/// so the fill math is testable without a terminal.
pub fn filled_dots(done: u64, total: u64, dots: usize) -> usize {
    let total = total.max(1);
    let frac = (done as f64 / total as f64).clamp(0.0, 1.0);
    (frac * dots as f64).round() as usize
}

/// A single-line dotted progress bar: `  <label> • • • • • • •   NN%`, redrawn
/// in place. Silent when not a TTY (so piped output stays clean).
pub struct Progress {
    label: String,
    total: u64,
    dots: usize,
}

impl Progress {
    pub fn new(label: &str, total: u64) -> Self {
        let p = Self {
            label: label.to_string(),
            total: total.max(1),
            dots: 12,
        };
        p.render(0);
        p
    }

    pub fn set(&self, done: u64) {
        self.render(done);
    }

    pub fn finish(&self) {
        self.render(self.total);
        if tty() {
            eprintln!();
        }
    }

    fn render(&self, done: u64) {
        if !tty() {
            return;
        }
        let filled = filled_dots(done, self.total, self.dots);
        let mut bar = String::new();
        for i in 0..self.dots {
            if i > 0 {
                bar.push(' ');
            }
            bar.push_str(&if i < filled { bold("•") } else { dim("•") });
        }
        let pct = (done as f64 / self.total as f64 * 100.0).round() as u32;
        eprint!(
            "\r  {} {}  {}",
            dim(&self.label),
            bar,
            bold(&format!("{pct:>3}%"))
        );
        let _ = std::io::stderr().flush();
    }
}

/// A muted `label value` status line (to stderr, so it doesn't pollute stdout).
pub fn status(label: &str, value: &str) {
    if tty() {
        eprintln!("  {} {}", dim(label), value);
    }
}

/// The final share result: the URL prominent on stdout (always, so it's
/// capturable), with a quiet meta line to stderr on a terminal.
pub fn share_result(url: &str, meta: &str) {
    if tty() {
        eprintln!();
        println!("  {}", bold(url));
        eprintln!("  {}", dim(meta));
    } else {
        println!("{url}");
    }
}

/// The PIN callout after a PIN-locked share: the PIN stands out, with a reminder
/// to send it over a *separate* channel from the link. To stderr (informational),
/// so it never pollutes a captured URL.
pub fn pin_notice(pin: &str) {
    if tty() {
        eprintln!("\n  {}  {}", dim("PIN     "), bold(pin));
        eprintln!(
            "  {}",
            dim("send this out of band (text, call) — separate from the link")
        );
    } else {
        eprintln!("PIN {pin}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_scales() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(842 * 1024 * 1024), "842 MB");
        assert_eq!(human_size(1024), "1 KB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024 / 2), "1.5 GB");
    }

    #[test]
    fn filled_dots_tracks_progress() {
        assert_eq!(filled_dots(0, 100, 10), 0);
        assert_eq!(filled_dots(100, 100, 10), 10);
        assert_eq!(filled_dots(50, 100, 10), 5);
        assert_eq!(filled_dots(999, 0, 10), 10); // zero total → full, no div-by-zero
    }
}
