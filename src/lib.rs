//! Shared core for the `encrypt` CLI and the `encrypt-web` service.
//!
//! `crypto` is dependency-light and side-effect free. `fsops` is gated behind
//! the `cli` feature so the web binary cannot link the code that deletes files.

pub mod crypto;

#[cfg(feature = "cli")]
pub mod fsops;
