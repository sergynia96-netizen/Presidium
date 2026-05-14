//! Presidium cryptographic primitives.
#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used)]

pub mod identity;

/// Temporary function for fuzz target testing.
#[doc(hidden)]
pub fn dummy_function(_data: &[u8]) {}
