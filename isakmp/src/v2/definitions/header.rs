//! Module containing network level header structs for pieces of the protocol

use zerocopy::network_endian::U16;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;
use zerocopy::Unaligned;

use crate::v2::definitions::constants::FLAG_ATTRIBUTE_FORMAT;

/// Protocol header for a Proposal
///
/// For IKEv2, a proposal must include transformations for encryption,
/// pseudo-random number generation, integrity and the Diffie-Hellman group.
///
///                          1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     | Last Substruc |   RESERVED    |         Proposal Length       |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     ~                        SPI (variable)                         ~
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                                                               |
///     ~                        <Transforms>                           ~
///     |                                                               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct ProposalHeader {
    /// Specification whether the Proposal is the last of the Security Association, uses
    /// value 0 for the last and value 2 for any other (although it could be inferred
    /// from the size information in each header, it is still mandated by the spec)
    pub last_substruct: u8,
    /// Reserved, must be zero and must be ignored on receipt
    pub reserved: u8,
    /// Length in octets of the current Proposal, including the header itself
    pub proposal_length: U16,
    /// Number of this Proposal in the Security Association; it must be 1 for the first
    /// Proposal, and it must be incremented by 1 for each following Proposal; when the
    /// receiver accepts a proposal, the number must match exactly this number
    pub proposal_num: u8,
    /// Identifier for the protocol inside the Proposal, it is IKE in this project
    /// and therefore should be set to 1; see [SecurityProtocol]
    pub protocol_id: u8,
    /// Size of the SPI (Security Parameter Indexes) in octets used in subsequent SA
    /// negotiations; it must be 0 for the first negotiation, but since this project
    /// does not support subsequent negotiations, it is always 0
    pub spi_size: u8,
    /// Number of transformations
    pub num_transforms: u8,
    // omitted: the variable-size sending entity's SPI for re-negotiations
    // following: a list of Transforms
}

/// Protocol header for a Transform
///
///                          1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     | Last Substruc |   RESERVED    |        Transform Length       |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |Transform Type |   RESERVED    |          Transform ID         |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                                                               |
///     ~                      Transform Attributes                     ~
///     |                                                               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// The transform attributes are not part of the header and thus not included in the struct.
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct TransformHeader {
    /// Specification whether the Transform is the last of the Proposal, uses
    /// value 0 for the last and value 3 for any other (although it could be inferred
    /// from the size information in each header, it is still mandated by the spec)
    pub last_substruct: u8,
    /// Reserved, must be zero and must be ignored on receipt
    pub reserved: u8,
    /// Length in octets of the current Transform, including the header itself
    pub transform_length: U16,
    /// Type of transformation found in the body of this payload;
    /// see RFC 7296, section 3.3.2; also see [TransformType]
    pub transform_type: u8,
    /// Reserved, must be zero and must be ignored on receipt
    pub reserved2: u8,
    /// Identifier for the actually used transformation inside the Transform body,
    /// where the ID depends on the [TransformType]; for example, if the transform type
    /// was 1 (encryption algorithms) and the transform ID was 20, then the selected
    /// encryption algorithm of this transform was AES-GCM256
    pub transform_id: U16,
}

/// Protocol field for attributes of a Transform as per RFC 7296, section 3.3.5
///
///                         1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |A|       Attribute Type        |    AF=0  Attribute Length     |
///     |F|                             |    AF=1  Attribute Value      |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                   AF=0  Attribute Value                       |
///     |                   AF=1  Not Transmitted                       |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// This header only includes the type and attribute length or fixed-size value in
/// it. The fixed-length variant can be solely parsed using this header, while
/// the variable-length variant requires extra parsing capabilities. The
/// data for variable-length attributes is not stored in the header.
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct AttributeHeader {
    /// Type of the attribute encoded in the value field; the top bit must be set to 1
    pub attribute_type: U16,
    /// Fixed-length attribute value specific for a transformation, currently only the
    /// key length is supported as valid attribute
    pub attribute_value: U16,
}

impl AttributeHeader {
    /// Determine whether the fixed-length TV variant is used or the variable-length TLV variant
    pub fn is_fixed_length(&self) -> bool {
        u16::from(self.attribute_type) & FLAG_ATTRIBUTE_FORMAT == FLAG_ATTRIBUTE_FORMAT
    }
}

/// Protocol header for key exchange payloads
///
/// The Diffie-Hellman Group Num identifies the Diffie-Hellman group in
/// which the Key Exchange Data was computed (see RFC 7296, section 3.3.2).
/// This Diffie-Hellman Group Num MUST match a Diffie-Hellman group specified
/// in a proposal in the SA payload that is sent in the same message, and
/// SHOULD match the Diffie-Hellman group in the first group in the first
/// proposal, if such exists. If none of the proposals in that SA payload
/// specifies a Diffie-Hellman group, the KE payload MUST NOT be present.
///
///                          1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |   Diffie-Hellman Group Num    |           RESERVED            |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                                                               |
///     ~                       Key Exchange Data                       ~
///     |                                                               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// The key exchange data is not part of the header and thus not included in the struct.
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct KeyExchangeHeader {
    /// DH group number as per [KeyExchangeMethod]
    pub dh_group_num: U16,
    /// Ignored but must be set to 0
    pub reserved: U16,
}

/// Protocol header for Certificate Request as well as Certificate Payload payloads
///
///                          1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     | Cert Encoding |                                               |
///     +-+-+-+-+-+-+-+-+                                               |
///     ~          Certificate Data / Certification Authority           ~
///     |                                                               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Section 3.6 and 3.7 of RFC 7296 use this payload type. The variable-length
/// data is not part of the header and needs separate parsing; thus, the header
/// only consist of a single `u8` field.
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct CertificateHeader {
    /// Definition of the encoded data following the header,
    /// see [CertificateEncoding](super::params::CertificateEncoding)
    pub encoding: u8,
}

/// Protocol header for notify payloads
///
///                          1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |  Protocol ID  |   SPI Size    |      Notify Message Type      |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                                                               |
///     ~                Security Parameter Index (SPI)                 ~
///     |                                                               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                                                               |
///     ~                       Notification Data                       ~
///     |                                                               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Neither the Security Parameter Index nor the notification data is part
/// of the header and thus not included in the struct. The value in the
/// notification data is type specific for each message type.
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct NotifyHeader {
    /// If this notification concerns an existing SA whose SPI is given in the
    /// SPI field, this field indicates the type of that SA. For notifications
    /// concerning Child SAs, this field MUST contain either (2) to indicate AH
    /// or (3) to indicate ESP. Of the notifications defined in RFC 7296,
    /// the SPI is included only with INVALID_SELECTORS, REKEY_SA, and
    /// CHILD_SA_NOT_FOUND. If the SPI field is empty, this field MUST be
    /// sent as zero and MUST be ignored on receipt.
    pub protocol_id: u8,
    /// Length in octets of the SPI as defined by the IPsec protocol ID or zero
    /// if no SPI is applicable. For a notification concerning the IKE SA, the
    /// SPI Size MUST be zero and the field must be empty.
    pub spi_size: u8,
    /// Specifies the type of notification message, see [NotifyErrorMessageType]
    /// and [NotifyMessageStatus], because both are used in the same field here.
    ///
    /// Types in the range 0 - 16383 are intended for reporting errors. An
    /// implementation receiving a Notify payload with one of these types
    /// that it does not recognize in a response MUST assume that the
    /// corresponding request has failed entirely. Unrecognized error types
    /// in a request and status types in a request or response MUST be
    /// ignored, and they should be logged. Notify payloads with status types
    /// greater than 16383 MAY be added to any message and MUST be ignored if not
    /// recognized. They are intended to indicate capabilities, and as part
    /// of SA negotiation, are used to negotiate non-cryptographic parameters.
    pub notify_message_type: U16,
}

/// Protocol header for delete payloads
///
///                          1                   2                   3
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     | Protocol ID   |   SPI Size    |          Num of SPIs          |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                                                               |
///     ~               Security Parameter Index(es) (SPI)              ~
///     |                                                               |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// The Delete payload contains a protocol-specific Security Association identifier
/// that the sender has removed from its Security Association database and is, therefore,
/// no longer valid. It is possible to send multiple SPIs in a Delete payload; however,
/// each SPI MUST be for the same protocol. Mixing of protocol identifiers
/// MUST NOT be performed in the Delete payload. It is permitted,
/// however, to include multiple Delete payloads in a single
/// INFORMATIONAL exchange where each Delete payload lists SPIs for a
/// different protocol.
///
/// Deletion of the IKE SA is indicated by a protocol ID of 1 (IKE) but no SPIs.
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct DeleteHeader {
    /// Must be 1 for an IKE SA, 2 for AH, or 3 for ESP.
    pub protocol_id: u8,
    /// Length in octets of the SPI as defined by the protocol ID. It MUST be
    /// zero for IKE (SPI is in message header) or four for AH and ESP.
    pub spi_size: u8,
    /// The number of SPIs contained in the Delete payload.
    /// The size of each SPI is defined by the SPI Size field.
    pub number_of_spi: U16,
    // following: a list of variable-length SPI to delete
}
