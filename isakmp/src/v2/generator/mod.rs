//! Implementations for the associated function [build] of various IKEv2 packet
//! types that converts high-level Rust structs into network-encoded byte arrays

use thiserror::Error;

mod attribute;
mod deletion;
mod key_exchange;
mod notification;
mod packet;
mod payload;
mod proposal;
mod security_association;
mod transform;

/// Typical length of a payload in bytes estimated by testing and network inspection.
/// The payload for anything other than a Security Association is typically smaller than
/// this limit, while an SA may be a lot bigger due to the combination of proposals.
pub(crate) const ESTIMATED_PAYLOAD_LENGTH: usize = 256 + 64;

/// Typical length of a proposal in bytes estimated by testing and network inspection.
/// It might be a lot bigger, up to the maximum size of an ISAKMP packet minus
/// the headers, but this is not the case in most real scenarios.
pub(crate) const ESTIMATED_PROPOSAL_LENGTH: usize = 256;

/// Length of a transformation for a proposal in a Security Association. Typically, this is
/// 8 bytes, but it might be 12 bytes when fixed-length attributes are used. In theory,
/// variable-length attributes are supported by the protocol, which makes this number
/// less useful; but this project does not use them and has not implemented support for them.
pub(crate) const EXPECTED_TRANSFORM_LENGTH: usize = 12;

/// Failures when generating a network-level packet from an [IKEv2] struct
#[derive(Debug, Error, PartialEq)]
#[allow(missing_docs)]
pub enum GeneratorError {
    #[error("SPI length exceeded 255 bytes")]
    MaxSpiLengthExceeded,
    #[error("Nonce must be between 16 and 256 bytes")]
    InvalidNonceLength,
    #[error("At most 254 proposals are allowed in one SA")]
    TooManyProposals,
    #[error("At most 254 payloads are allowed in one packet")]
    TooManyPayloads,
    #[error("One or more mandatory transformations are missing")]
    MissingMandatoryTransform,
}
