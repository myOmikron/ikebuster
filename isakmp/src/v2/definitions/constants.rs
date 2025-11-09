//! Constant values and bit flags for IKEv2

/// Minimum size of a single IKE message (including ISAKMP header but excluding
/// UDP header) that must be supported by all IKE peers according to RFC 7296
pub const MIN_SUPPORTED_MSG_SIZE: usize = 1280;

/// Bitflag for IKEv2 (ISAKMP) header to indicate whether the sender of the packet is
/// an initiator (bit set) or a responder (bit not set); see RFC 7296, section 3.1
pub const FLAG_INITIATOR: u8 = 0b1000;

/// Bitflag for IKEv2 (ISAKMP) header to indicate whether the sender is able to speak a
/// higher version of IKE than IKEv2; it must be unset for IKEv2; see RFC 7296, section 3.1
pub const FLAG_HIGHER_VERSION: u8 = 0b10000;

/// Bitflag for IKEv2 (ISAKMP) header to indicate that a message is a response to a message
/// containing the same message ID; it must be cleared in all requests and must be set in all
/// responses; receiving see RFC 7296, section 3.1
pub const FLAG_RESPONSE: u8 = 0b100000;

/// Bitflag for IKEv2 payload header to indicate whether the recipient of the message should skip it
/// if the message is not understood (bit not set) or reject the entire message (bit set), where the
/// flag must be zero for all officially described types found in the RFC; see RFC 7296, section 2.5
pub const FLAG_CRITICAL: u8 = 0b10000000;

/// Bitflag for the [super::header::AttributeHeader] that indicates
/// whether the data attribute follows the Type/Length/Value (TLV) format or
/// a shortened Type/Value (TV) format. If the AF bit is zero (0), then
/// the attribute uses TLV format; if the AF bit is one (1), the TV
/// format (with two-byte value) is used. Currently only TV is supported.
pub const FLAG_ATTRIBUTE_FORMAT: u16 = 0b1000000000000000;

/// Flag that specifies whether this is the last Proposal Substructure
/// in the [SecurityAssociation]. The respective field has a value of 0
/// if this was the last Proposal Substructure, and a value of 2 if
/// there are more Proposal Substructures. This syntax is inherited
/// from ISAKMP, but is unnecessary because the last Proposal could be
/// identified from the length of the SA. The value (2) corresponds
/// to a payload type of Proposal in IKEv1, and the first four octets
/// of the Proposal structure are designed to look somewhat like the
/// header of a payload.
pub const FLAG_MORE_FOLLOWING_PROPOSALS: u8 = 2;

/// Flag that specifies whether this is the last Transform
/// Substructure in the [Proposal]. The respective field has a
/// value of 0 if this was the last Transform Substructure, and a
/// value of 3 if there are more Transform Substructures. This syntax
/// is inherited from ISAKMP, but is unnecessary because the last
/// transform could be identified from the length of the proposal.
/// The value (3) corresponds to a payload type of Transform in IKEv1,
/// and the first four octets of the Transform structure are designed
/// to look somewhat like the header of a payload.
pub const FLAG_MORE_FOLLOWING_TRANSFORMS: u8 = 3;

/// Constant of the value for the smallest possible
/// [NotifyStatusMessage](super::NotifyStatusMessage)
pub const MINIMAL_NOTIFY_STATUS_MESSAGE_VALUE: u16 = 16384;

/// The maximum size of a single notification cookie payload
pub const MAX_COOKIE_DATA_SIZE: usize = 64;

/// Microsoft Win32 error code for invalid parameters, as found in the
/// [docs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d).
/// It is used to detect INVALID_SYNTAX responses because instead of using
/// the RFC-compliant payload, Windows Server responds with this value
/// as notification data in the [super::NotifyErrorMessage::MicrosoftWindowsStatusNotify].
pub const WIN32_ERROR_INVALID_PARAMETER: u32 = 0x00000057;
