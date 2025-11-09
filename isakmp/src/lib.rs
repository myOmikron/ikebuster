//! # isakmp
//!
//! The low level definitions for the protocol "ISAKMP"

#![warn(missing_docs, clippy::unwrap_used, clippy::expect_used)]

pub mod v1;
pub mod v2;

pub use strum;
pub use zerocopy;
