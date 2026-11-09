//! Read-only Windows collectors that fill a `SystemSnapshot`.
//!
//! Everything here is Windows only. On other platforms the crate is empty.
//! Collectors gather facts and never decide what's bad, and they never write.
#![cfg(windows)]
