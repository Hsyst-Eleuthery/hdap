//! HDAP desktop client (egui). Thin: no protocol logic here, the heavy work
//! is delegated to `hdap-cli::flow` (skill.md principle 6).
//!
//! The `App` state machine is GUI-agnostic and unit-testable; `view` is the
//! egui renderer.

pub mod app;
pub mod editor;
pub mod i18n;
pub mod theme;
pub mod view;

pub use app::{App, Session};
pub use hdap_cli::flow::{fetch_prices, publish_alias, resolve, TimiQuote};
