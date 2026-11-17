//! Minimal leveled logger for the node.
//!
//! The v1 server printed `DISPATCH: ...` on stderr for every request, leaking
//! paths and identifiers into production logs. v2 routes all diagnostics
//! through this module. Set `HDAP_LOG=error|warn|info|debug` to choose the
//! verbosity; the default is `warn`. `HDAP_LOG=off` silences everything.

use std::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(2); // warn

pub const OFF: u8 = 0;
pub const ERROR: u8 = 1;
pub const WARN: u8 = 2;
pub const INFO: u8 = 3;
pub const DEBUG: u8 = 4;

/// Initialize from `HDAP_LOG`. Safe to call more than once.
pub fn init() {
    let level = match std::env::var("HDAP_LOG").unwrap_or_default().to_ascii_lowercase().as_str() {
        "off" => OFF,
        "error" => ERROR,
        "warn" | "" => WARN,
        "info" => INFO,
        "debug" | "trace" => DEBUG,
        _ => WARN,
    };
    LEVEL.store(level, Ordering::Relaxed);
}

#[doc(hidden)]
pub fn enabled(level: u8) -> bool {
    LEVEL.load(Ordering::Relaxed) >= level
}

#[doc(hidden)]
pub fn emit(level: u8, tag: &str, args: std::fmt::Arguments<'_>) {
    if enabled(level) {
        let name = match level {
            ERROR => "ERROR",
            WARN => "WARN",
            INFO => "INFO",
            _ => "DEBUG",
        };
        eprintln!("[{name} {tag}] {args}");
    }
}

#[macro_export]
macro_rules! hlog {
    (error, $tag:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::ERROR, $tag, format_args!($($arg)*))
    };
    (warn, $tag:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::WARN, $tag, format_args!($($arg)*))
    };
    (info, $tag:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::INFO, $tag, format_args!($($arg)*))
    };
    (debug, $tag:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::DEBUG, $tag, format_args!($($arg)*))
    };
}
