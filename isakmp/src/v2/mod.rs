//! Implementation of parsers, definitions and message generation for IKEv2

pub mod definitions;
pub mod generator;
pub mod parser;
pub mod utils;

#[cfg(test)]
mod tests;

/// Constant value for IKEv2 in ISAKMP packets, as <major>.<minor> in 4 bits each,
/// where the <major> is 2 and the <minor> is zero.
pub const IKE_2_VERSION_VALUE: u8 = 0b00100000;
