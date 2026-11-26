//! RPF — a fast, secure RPM package manager for Fedora.
//!
//! The crate is deliberately dependency-free: everything from version
//! comparison to RPM header parsing is implemented here, so that RPF has no
//! supply chain beyond `std`.

pub mod bigint;
pub mod cache;
pub mod config;
pub mod db;
pub mod deps;
pub mod digest;
pub mod error;
pub mod fetch;
pub mod ini;
pub mod install;
pub mod pgp;
pub mod pkg;
pub mod repomd;
pub mod rpm;
pub mod solver;
pub mod verify;
pub mod version;
pub mod xml;

pub use error::{Error, Result};

/// Version of the RPF implementation itself.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
