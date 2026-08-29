//! Adapts dove-core's `Progress` callback trait onto the CLI's existing
//! dotted-step / progress-bar look (`ui.rs`) — the terminal echo the
//! marketing mock promised, now driven from outside dove-core instead of
//! wrapped around a local closure.

use crate::ui;
use dove_core::progress::Progress;
use std::cell::RefCell;

pub struct CliProgress {
    /// The `ui::Progress` bar's label for `bytes()` calls — "uploading" for
    /// `share`, "downloading" for `get`. `bytes()` carries no label of its
    /// own, so the caller fixes it at construction.
    bytes_label: &'static str,
    /// The label of a `step()` that hasn't been closed out by `done()` yet —
    /// so a caller whose `Transfer` call errors mid-step can flush the ✗ that
    /// `ui::step`'s closure-wrapping used to print automatically.
    pending: RefCell<Option<String>>,
    bar: RefCell<Option<ui::Progress>>,
}

impl CliProgress {
    pub fn new(bytes_label: &'static str) -> Self {
        Self {
            bytes_label,
            pending: RefCell::new(None),
            bar: RefCell::new(None),
        }
    }

    /// Call after a `Transfer` method returns `Err`: closes out any dotted
    /// step still shown as in-progress with the same red ✗ `ui::step` would
    /// have printed had the failure happened inside its own closure.
    pub fn fail_pending(&self) {
        if let Some(label) = self.pending.borrow_mut().take() {
            ui::step_end(&label, false);
        }
    }
}

impl Progress for CliProgress {
    fn step(&self, label: &str) {
        *self.pending.borrow_mut() = Some(label.to_string());
        ui::step_begin(label);
    }

    fn done(&self, label: &str) {
        self.pending.borrow_mut().take();
        ui::step_end(label, true);
    }

    fn field(&self, key: &str, value: &str) {
        ui::field(key, value);
    }

    fn bytes(&self, uploaded: u64, total: u64) {
        let mut bar = self.bar.borrow_mut();
        if uploaded >= total {
            if let Some(b) = bar.take() {
                b.finish();
                // The simple/full-tier share paths follow the bar with an
                // "uploaded <size>" status line; `get`'s download bar has no
                // equivalent (its final line is the "downloaded → path"
                // banner, printed by `get::run` once `Transfer::get` returns).
                if self.bytes_label == "uploading" {
                    ui::status("uploaded", &ui::human_size(total));
                }
            }
            return;
        }
        if bar.is_none() {
            *bar = Some(ui::Progress::new(self.bytes_label, total.max(1)));
        }
        if let Some(b) = bar.as_ref() {
            b.set(uploaded);
        }
    }
}
