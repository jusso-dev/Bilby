//! Read-only Windows collectors that fill a `SystemSnapshot`.
//!
//! Everything here is Windows only. On other platforms the crate is empty.
//! Collectors gather facts and never decide what's bad, and they never write
//! (ADR 0003): files are opened for reading only and registry keys with read
//! access only.
#![cfg(windows)]

pub mod browser;
pub mod cache;
pub mod defender;
pub mod drivers;
pub mod elevation;
pub mod files;
pub mod handle;
pub mod hash;
pub mod network;
pub mod paths;
pub mod persistence;
pub mod processes;
pub mod registry;
pub mod scan;
pub mod sig;
pub mod tamper;
