//! IKEv2 parameters and their parsers as defined in the IANA IKEv2 list
//! found at https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml!
//! Also take a look at RFC 8247, section 2.4 for further security considerations.

use serde::Deserialize;
use serde::Serialize;
use strum::Display;
use strum::EnumIter;

use super::Payload;
use super::Transform;
use super::UnparseableParameter;

/// Type of the exchanged being used
///
/// This constrains the payloads sent in each message in an exchange.
/// Notably, values 0-33 are reserved, 45-239 are currently unassigned
/// and 240-255 reserved for private use. Also see [UnparseableParameter].
#[derive(Debug, Display, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum ExchangeType {
    // RFC 7296
    IkeSaInit = 34,
    // RFC 7296
    IkeAuth = 35,
    // RFC 7296
    CreateChildSa = 36,
    // RFC 7296
    Informational = 37,
    // RFC 5723
    IkeSessionResume = 38,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaAuth = 39,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaRegistration = 40,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaRekey = 41,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaInbandRekey = 42,
    // RFC 9242
    IkeIntermediate = 43,
    // RFC 9370
    IkeFollowupKeyExchange = 44,
}

impl TryFrom<u8> for ExchangeType {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=33 => Err(UnparseableParameter::Reserved),
            34 => Ok(ExchangeType::IkeSaInit),
            35 => Ok(ExchangeType::IkeAuth),
            36 => Ok(ExchangeType::CreateChildSa),
            37 => Ok(ExchangeType::Informational),
            38 => Ok(ExchangeType::IkeSessionResume),
            39 => Ok(ExchangeType::GsaAuth),
            40 => Ok(ExchangeType::GsaRegistration),
            41 => Ok(ExchangeType::GsaRekey),
            42 => Ok(ExchangeType::GsaInbandRekey),
            43 => Ok(ExchangeType::IkeIntermediate),
            44 => Ok(ExchangeType::IkeFollowupKeyExchange),
            45..=239 => Err(UnparseableParameter::Unassigned),
            240..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Type of the payload being used
///
/// This constrains the payloads sent in each message in an exchange.
/// Refer to https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
/// for details. Notably, values 1-33 are reserved, 55-127 are currently unassigned
/// and 128-255 reserved for private use. Also see [UnparseableParameter].
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum PayloadType {
    // RFC 7296, this also matches the IKEv1 value while all other values do not
    NoNextPayload = 0,
    // RFC 7296, includes GM supported transforms as per draft-ietf-ipsecme-g-ikev2-22
    SecurityAssociation = 33,
    // RFC 7296
    KeyExchange = 34,
    // RFC 7296
    IdentificationInitiator = 35,
    // RFC 7296
    IdentificationResponder = 36,
    // RFC 7296
    Certificate = 37,
    // RFC 7296
    CertificateRequest = 38,
    // RFC 7296
    Authentication = 39,
    // RFC 7296
    Nonce = 40,
    // RFC 7296
    Notify = 41,
    // RFC 7296
    Delete = 42,
    // RFC 7296
    VendorID = 43,
    // RFC 7296
    TrafficSelectorInitiator = 44,
    // RFC 7296
    TrafficSelectorResponder = 45,
    // RFC 7296
    EncryptedAndAuthenticated = 46,
    // RFC 7296
    Configuration = 47,
    // RFC 7296
    ExtensibleAuthentication = 48,
    // RFC 6467
    GenericSecurePasswordMethod = 49,
    // draft-ietf-ipsecme-g-ikev2-22
    GroupIdentification = 50,
    // draft-ietf-ipsecme-g-ikev2-22
    GroupSecureAssociation = 51,
    // draft-ietf-ipsecme-g-ikev2-22
    KeyDownload = 52,
    // RFC 7383
    EncryptedAndAuthenticatedFragment = 53,
    // RFC 8019
    PuzzleSolution = 54,
}

impl TryFrom<u8> for PayloadType {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PayloadType::NoNextPayload),
            1..=32 => Err(UnparseableParameter::Reserved),
            33 => Ok(PayloadType::SecurityAssociation),
            34 => Ok(PayloadType::KeyExchange),
            35 => Ok(PayloadType::IdentificationInitiator),
            36 => Ok(PayloadType::IdentificationResponder),
            37 => Ok(PayloadType::Certificate),
            38 => Ok(PayloadType::CertificateRequest),
            39 => Ok(PayloadType::Authentication),
            40 => Ok(PayloadType::Nonce),
            41 => Ok(PayloadType::Notify),
            42 => Ok(PayloadType::Delete),
            43 => Ok(PayloadType::VendorID),
            44 => Ok(PayloadType::TrafficSelectorInitiator),
            45 => Ok(PayloadType::TrafficSelectorResponder),
            46 => Ok(PayloadType::EncryptedAndAuthenticated),
            47 => Ok(PayloadType::Configuration),
            48 => Ok(PayloadType::ExtensibleAuthentication),
            49 => Ok(PayloadType::GenericSecurePasswordMethod),
            50 => Ok(PayloadType::GroupIdentification),
            51 => Ok(PayloadType::GroupSecureAssociation),
            52 => Ok(PayloadType::KeyDownload),
            53 => Ok(PayloadType::EncryptedAndAuthenticatedFragment),
            54 => Ok(PayloadType::PuzzleSolution),
            55..=127 => Err(UnparseableParameter::Unassigned),
            128..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

impl From<&Payload> for PayloadType {
    fn from(value: &Payload) -> Self {
        match value {
            Payload::SecurityAssociation(_) => Self::SecurityAssociation,
            Payload::KeyExchange(_) => Self::KeyExchange,
            Payload::CertificateRequest(_) => Self::CertificateRequest,
            Payload::Nonce(_) => Self::Nonce,
            Payload::Notify(_) => Self::Notify,
            Payload::Delete(_) => Self::Delete,
            Payload::VendorID(_) => Self::VendorID,
            Payload::EncryptedAndAuthenticated(_) => Self::EncryptedAndAuthenticated,
        }
    }
}

/// Type of the transform being used
///
/// Value 0 is reserved, 15-240 is unassigned and 241-255 is
/// reserved for private use. Also see [UnparseableParameter].
///
/// The "Key Exchange Method (KE)" transform type was originally
/// named "Diffie-Hellman Group (D-H)" and was referenced by
/// that name in a number of RFCs published prior
/// to RFC 9370, which gave it the current title.
///
/// All "Additional Key Exchange (ADDKE)" entries use the same
/// "Transform Type 4 - Key Exchange Method Transform IDs"
/// registry as the "Key Exchange Method (KE)" entry.
///
/// "Sequence Numbers (SN)" transform type was originally named
/// "Extended Sequence Numbers (ESN)" and was referenced by
/// that name in a number of RFCs published before RFC 9370.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum TransformType {
    EncryptionAlgorithm = 1,
    PseudoRandomFunction = 2,
    IntegrityAlgorithm = 3,
    KeyExchangeMethod = 4,
    SequenceNumber = 5,
    // RFC 9370
    AdditionalKeyExchange1 = 6,
    // RFC 9370
    AdditionalKeyExchange2 = 7,
    // RFC 9370
    AdditionalKeyExchange3 = 8,
    // RFC 9370
    AdditionalKeyExchange4 = 9,
    // RFC 9370
    AdditionalKeyExchange5 = 10,
    // RFC 9370
    AdditionalKeyExchange6 = 11,
    // RFC 9370
    AdditionalKeyExchange7 = 12,
    // RFC 9370
    KeyWrapAlgorithm = 13,
    GroupControllerAuthenticationMethod = 14,
}

impl TryFrom<u8> for TransformType {
    type Error = UnparseableParameter;

    /// Determine the [TransformType] from an u8 value as used in the network packet structure
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(TransformType::EncryptionAlgorithm),
            2 => Ok(TransformType::PseudoRandomFunction),
            3 => Ok(TransformType::IntegrityAlgorithm),
            4 => Ok(TransformType::KeyExchangeMethod),
            5 => Ok(TransformType::SequenceNumber),
            6 => Ok(TransformType::AdditionalKeyExchange1),
            7 => Ok(TransformType::AdditionalKeyExchange2),
            8 => Ok(TransformType::AdditionalKeyExchange3),
            9 => Ok(TransformType::AdditionalKeyExchange4),
            10 => Ok(TransformType::AdditionalKeyExchange5),
            11 => Ok(TransformType::AdditionalKeyExchange6),
            12 => Ok(TransformType::AdditionalKeyExchange7),
            13 => Ok(TransformType::KeyWrapAlgorithm),
            14 => Ok(TransformType::GroupControllerAuthenticationMethod),
            15..=240 => Err(UnparseableParameter::Unassigned),
            241..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

impl From<&Transform> for TransformType {
    fn from(value: &Transform) -> Self {
        match value {
            Transform::Encryption(_, _) => TransformType::EncryptionAlgorithm,
            Transform::PseudoRandomFunction(_) => TransformType::PseudoRandomFunction,
            Transform::Integrity(_) => TransformType::IntegrityAlgorithm,
            Transform::KeyExchange(_) => TransformType::KeyExchangeMethod,
            Transform::SequenceNumber(_) => TransformType::SequenceNumber,
        }
    }
}

/// Values for attribute types used to describe extra data for any transformation
///
/// Values 0-13 and 15-17 are reserved, 19-16383 are unassigned and
/// 16384-32767 reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum AttributeType {
    /// Definition for the key length of variable-length encryption algorithms like AES-CBC;
    /// requires TV (type/value) format for the attribute payload packet
    KeyLength = 14,
    /// Definition for the signature algorithm used in Group Controller authentication;
    /// defined in draft-ietf-ipsecme-g-ikev2-22 and therefore not implemented in this project;
    /// requires TLV (type/length/value) format for the attribute payload packet
    SignatureAlgorithm = 18,
}

impl TryFrom<u16> for AttributeType {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0..=13 => Err(UnparseableParameter::Reserved),
            14 => Ok(AttributeType::KeyLength),
            15..=17 => Err(UnparseableParameter::Reserved),
            18 => Ok(AttributeType::SignatureAlgorithm),
            19..=16383 => Err(UnparseableParameter::Reserved),
            16384..=32767 => Err(UnparseableParameter::Reserved),
            32768..=65535 => Err(UnparseableParameter::OutOfRange),
        }
    }
}

/// Values for valid encryption algorithm transformations
///
/// Values 0, 10 and 22 are reserved, 17 and 36-1023 are unassigned
/// and 1024-65535 are reserved for private use. See also [UnparseableParameter].
/// The values 11, 21, 29, 30, 31, 34 and 35 are assigned by IANA but not allowed
/// for use in IKE and will therefore respond to [UnparseableParameter::NotAllowed]
/// when parsed from u16; they are allowed for building the packets though.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(non_camel_case_types, missing_docs)]
// On the following CCM and GCM ciphers, the number that follows the cipher indicates
// the size of the ICV and not the key size, which is negotiated separately
pub enum EncryptionAlgorithm {
    DES_IV64 = 1, // deprecated
    DES = 2,      // deprecated
    TRIPLE_DES = 3,
    RC5 = 4,         // deprecated
    IDEA = 5,        // deprecated
    CAST = 6,        // deprecated
    BLOWFISH = 7,    // deprecated
    TRIPLE_IDEA = 8, // deprecated
    DES_IV32 = 9,    // deprecated
    NULL = 11,       // not allowed in IKE
    AES_CBC = 12,
    AES_CTR = 13,
    AES_CCM_8 = 14,          // AEAD, see RFC 5282
    AES_CCM_12 = 15,         // AEAD, see RFC 5282; not recommended
    AES_CCM_16 = 16,         // AEAD, see RFC 5282
    AES_GCM_8 = 18,          // AEAD, see RFC 5282
    AES_GCM_12 = 19,         // AEAD, see RFC 5282; not recommended
    AES_GCM_16 = 20,         // AEAD, see RFC 5282
    NULL_AUTH_AES_GMAC = 21, // not allowed in IKE
    CAMELLIA_CBC = 23,
    CAMELLIA_CTR = 24,
    CAMELLIA_CCM_8 = 25,
    CAMELLIA_CCM_12 = 26,
    CAMELLIA_CCM_16 = 27,
    CHACHA20_POLY1305 = 28,
    AES_CCM_8_IIV = 29,            // not allowed in IKE
    AES_GCM_16_IIV = 30,           // not allowed in IKE
    CHACHA20_POLY1305_IIV = 31,    // not allowed in IKE
    KUZNYECHIK_MGM_KTREE = 32,     // AEAD, see RFC 9227
    MAGMA_MGM_KTREE = 33,          // AEAD, see RFC 9227
    KUZNYECHIK_MGM_MAC_KTREE = 34, // not allowed in IKE
    MAGMA_MGM_MAC_KTREE = 35,      // not allowed in IKE
}

impl TryFrom<u16> for EncryptionAlgorithm {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(EncryptionAlgorithm::DES_IV64),
            2 => Ok(EncryptionAlgorithm::DES),
            3 => Ok(EncryptionAlgorithm::TRIPLE_DES),
            4 => Ok(EncryptionAlgorithm::RC5),
            5 => Ok(EncryptionAlgorithm::IDEA),
            6 => Ok(EncryptionAlgorithm::CAST),
            7 => Ok(EncryptionAlgorithm::BLOWFISH),
            8 => Ok(EncryptionAlgorithm::TRIPLE_IDEA),
            9 => Ok(EncryptionAlgorithm::DES_IV32),
            10 => Err(UnparseableParameter::Reserved),
            11 => Err(UnparseableParameter::NotAllowed(Self::NULL)),
            12 => Ok(EncryptionAlgorithm::AES_CBC),
            13 => Ok(EncryptionAlgorithm::AES_CTR),
            14 => Ok(EncryptionAlgorithm::AES_CCM_8),
            15 => Ok(EncryptionAlgorithm::AES_CCM_12),
            16 => Ok(EncryptionAlgorithm::AES_CCM_16),
            17 => Err(UnparseableParameter::Unassigned),
            18 => Ok(EncryptionAlgorithm::AES_GCM_8),
            19 => Ok(EncryptionAlgorithm::AES_GCM_12),
            20 => Ok(EncryptionAlgorithm::AES_GCM_16),
            21 => Err(UnparseableParameter::NotAllowed(Self::NULL_AUTH_AES_GMAC)),
            22 => Err(UnparseableParameter::Reserved),
            23 => Ok(EncryptionAlgorithm::CAMELLIA_CBC),
            24 => Ok(EncryptionAlgorithm::CAMELLIA_CTR),
            25 => Ok(EncryptionAlgorithm::CAMELLIA_CCM_8),
            26 => Ok(EncryptionAlgorithm::CAMELLIA_CCM_12),
            27 => Ok(EncryptionAlgorithm::CAMELLIA_CCM_16),
            28 => Ok(EncryptionAlgorithm::CHACHA20_POLY1305),
            29 => Err(UnparseableParameter::NotAllowed(Self::AES_CCM_8_IIV)),
            30 => Err(UnparseableParameter::NotAllowed(Self::AES_GCM_16_IIV)),
            31 => Err(UnparseableParameter::NotAllowed(
                Self::CHACHA20_POLY1305_IIV,
            )),
            32 => Ok(EncryptionAlgorithm::KUZNYECHIK_MGM_KTREE),
            33 => Ok(EncryptionAlgorithm::MAGMA_MGM_KTREE),
            34 => Err(UnparseableParameter::NotAllowed(
                Self::KUZNYECHIK_MGM_MAC_KTREE,
            )),
            35 => Err(UnparseableParameter::NotAllowed(Self::MAGMA_MGM_MAC_KTREE)),
            36..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for valid pseudorandom functions used in transformations
///
/// To find out requirement levels for PRFs for IKEv2, see RFC 8247.
/// Values 0 is reserved, 10-1023 are unassigned and 1024-65535 reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(non_camel_case_types, missing_docs)]
pub enum PseudorandomFunction {
    HMAC_MD5 = 1, // deprecated
    HMAC_SHA1 = 2,
    HMAC_TIGER = 3, // deprecated
    AES128_XCBC = 4,
    HMAC_SHA2_256 = 5,
    HMAC_SHA2_384 = 6,
    HMAC_SHA2_512 = 7,
    AES128_CMAC = 8,
    HMAC_STREEBOG_512 = 9,
}

impl TryFrom<u16> for PseudorandomFunction {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(PseudorandomFunction::HMAC_MD5),
            2 => Ok(PseudorandomFunction::HMAC_SHA1),
            3 => Ok(PseudorandomFunction::HMAC_TIGER),
            4 => Ok(PseudorandomFunction::AES128_XCBC),
            5 => Ok(PseudorandomFunction::HMAC_SHA2_256),
            6 => Ok(PseudorandomFunction::HMAC_SHA2_384),
            7 => Ok(PseudorandomFunction::HMAC_SHA2_512),
            8 => Ok(PseudorandomFunction::AES128_CMAC),
            9 => Ok(PseudorandomFunction::HMAC_STREEBOG_512),
            10..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for valid integrity algorithms used in transformations
///
/// To find out requirement levels for encryption algorithms for
/// ESP/AH, see RFC 8221. For IKEv2, see RFC 8247.
/// Values 15-1023 are unassigned and 1024-65535 reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(non_camel_case_types, missing_docs)]
pub enum IntegrityAlgorithm {
    NONE = 0,
    HMAC_MD5_96 = 1, // deprecated
    HMAC_SHA1_96 = 2,
    DES_MAC = 3,  // deprecated
    KPDK_MD5 = 4, // deprecated
    AES_XCBC_96 = 5,
    HMAC_MD5_128 = 6,  // deprecated
    HMAC_SHA1_160 = 7, // deprecated
    AES_CMAC_96 = 8,
    AES_128_GMAC = 9,
    AES_192_GMAC = 10,
    AES_256_GMAC = 11,
    HMAC_SHA2_256_128 = 12,
    HMAC_SHA2_384_192 = 13,
    HMAC_SHA2_512_256 = 14,
}

impl TryFrom<u16> for IntegrityAlgorithm {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IntegrityAlgorithm::NONE),
            1 => Ok(IntegrityAlgorithm::HMAC_MD5_96),
            2 => Ok(IntegrityAlgorithm::HMAC_SHA1_96),
            3 => Ok(IntegrityAlgorithm::DES_MAC),
            4 => Ok(IntegrityAlgorithm::KPDK_MD5),
            5 => Ok(IntegrityAlgorithm::AES_XCBC_96),
            6 => Ok(IntegrityAlgorithm::HMAC_MD5_128),
            7 => Ok(IntegrityAlgorithm::HMAC_SHA1_160),
            8 => Ok(IntegrityAlgorithm::AES_CMAC_96),
            9 => Ok(IntegrityAlgorithm::AES_128_GMAC),
            10 => Ok(IntegrityAlgorithm::AES_192_GMAC),
            11 => Ok(IntegrityAlgorithm::AES_256_GMAC),
            12 => Ok(IntegrityAlgorithm::HMAC_SHA2_256_128),
            13 => Ok(IntegrityAlgorithm::HMAC_SHA2_384_192),
            14 => Ok(IntegrityAlgorithm::HMAC_SHA2_512_256),
            15..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for valid key exchange methods used in transformations
///
/// This registry was originally named "Transform Type 4 -
/// Diffie-Hellman Group Transform IDs" and was referenced
/// using that name in a number of RFCs published prior to
/// RFC 9370, which gave it its current title.
///
/// This registry is used by the "Key Exchange Method (KE)"
/// transform type and by all "Additional Key Exchange (ADDKE)"
/// transform types. To find out requirement levels for key
/// exchange methods for IKEv2, see RFC 8247.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(non_camel_case_types, missing_docs)]
pub enum KeyExchangeMethod {
    None = 0,
    MODP_768 = 1, // deprecated
    MODP_1024 = 2,
    MODP_1536 = 5,
    MODP_2048 = 14,
    MODP_3072 = 15,
    MODP_4096 = 16,
    MODP_6144 = 17,
    MODP_8192 = 18,
    ECP_Random_256 = 19,
    ECP_Random_384 = 20,
    ECP_Random_521 = 21,
    MODP_1024_Prime_160 = 22, // deprecated
    MODP_2048_Prime_224 = 23, // unsafe
    MODP_2048_Prime_256 = 24, // unsafe
    ECP_Random_192 = 25,
    ECP_Random_224 = 26,
    ECP_Brainpool_224 = 27,
    ECP_Brainpool_256 = 28,
    ECP_Brainpool_384 = 29,
    ECP_Brainpool_512 = 30,
    Curve_25519 = 31,
    Curve_448 = 32,
    GOST3410_2012_256 = 33,
    GOST3410_2012_512 = 34,
    ML_KEM_512 = 35,
    ML_KEM_768 = 36,
    ML_KEM_1024 = 37,
}

impl TryFrom<u16> for KeyExchangeMethod {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyExchangeMethod::None),
            1 => Ok(KeyExchangeMethod::MODP_768),
            2 => Ok(KeyExchangeMethod::MODP_1024),
            3..=4 => Err(UnparseableParameter::Reserved),
            5 => Ok(KeyExchangeMethod::MODP_1536),
            6..=13 => Err(UnparseableParameter::Unassigned),
            14 => Ok(KeyExchangeMethod::MODP_2048),
            15 => Ok(KeyExchangeMethod::MODP_3072),
            16 => Ok(KeyExchangeMethod::MODP_4096),
            17 => Ok(KeyExchangeMethod::MODP_6144),
            18 => Ok(KeyExchangeMethod::MODP_8192),
            19 => Ok(KeyExchangeMethod::ECP_Random_256),
            20 => Ok(KeyExchangeMethod::ECP_Random_384),
            21 => Ok(KeyExchangeMethod::ECP_Random_521),
            22 => Ok(KeyExchangeMethod::MODP_1024_Prime_160),
            23 => Ok(KeyExchangeMethod::MODP_2048_Prime_224),
            24 => Ok(KeyExchangeMethod::MODP_2048_Prime_256),
            25 => Ok(KeyExchangeMethod::ECP_Random_192),
            26 => Ok(KeyExchangeMethod::ECP_Random_224),
            27 => Ok(KeyExchangeMethod::ECP_Brainpool_224),
            28 => Ok(KeyExchangeMethod::ECP_Brainpool_256),
            29 => Ok(KeyExchangeMethod::ECP_Brainpool_384),
            30 => Ok(KeyExchangeMethod::ECP_Brainpool_512),
            31 => Ok(KeyExchangeMethod::Curve_25519),
            32 => Ok(KeyExchangeMethod::Curve_448),
            33 => Ok(KeyExchangeMethod::GOST3410_2012_256),
            34 => Ok(KeyExchangeMethod::GOST3410_2012_512),
            35 => Ok(KeyExchangeMethod::ML_KEM_512),
            36 => Ok(KeyExchangeMethod::ML_KEM_768),
            37 => Ok(KeyExchangeMethod::ML_KEM_1024),
            38..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for sequence number types
///
/// The default is likely to be [SequenceNumberType::Sequential32bit],
/// as it was originally called "No Extended Sequence Numbers".
/// Values 3-1023 are unassigned and 1024-65535 are reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum SequenceNumberType {
    Sequential32bit = 0,
    PartiallyTransmitted64bit = 1,
    Unspecified32bit = 2, // not used, since defined only in draft-ietf-ipsecme-g-ikev2-22
}

impl TryFrom<u16> for SequenceNumberType {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SequenceNumberType::Sequential32bit),
            1 => Ok(SequenceNumberType::PartiallyTransmitted64bit),
            2 => Ok(SequenceNumberType::Unspecified32bit),
            3..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Indicator for the encoding of certificates and related data
///
/// Values 0 and 5 are reserved, 16-200 are unassigned and 201-255 are reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum CertificateEncoding {
    PKCS7WrappedX509Certificate = 1,
    PGPCertificate = 2,
    DNSSignedKey = 3,
    X509CertificateSignature = 4,
    KerberosTokens = 6,
    CertificateRevocationList = 7,
    AuthorityRevocationList = 8,
    SPKICertificate = 9,
    X509CertificateAttribute = 10,
    RawRSAKey = 11, // deprecated
    HashUrlX509Certificate = 12,
    HashUrlX509Bundle = 13,
    OCSPContent = 14,
    RawPublicKey = 15,
}

impl TryFrom<u8> for CertificateEncoding {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(CertificateEncoding::PKCS7WrappedX509Certificate),
            2 => Ok(CertificateEncoding::PGPCertificate),
            3 => Ok(CertificateEncoding::DNSSignedKey),
            4 => Ok(CertificateEncoding::X509CertificateSignature),
            5 => Err(UnparseableParameter::Reserved),
            6 => Ok(CertificateEncoding::KerberosTokens),
            7 => Ok(CertificateEncoding::CertificateRevocationList),
            8 => Ok(CertificateEncoding::AuthorityRevocationList),
            9 => Ok(CertificateEncoding::SPKICertificate),
            10 => Ok(CertificateEncoding::X509CertificateAttribute),
            11 => Ok(CertificateEncoding::RawRSAKey),
            12 => Ok(CertificateEncoding::HashUrlX509Certificate),
            13 => Ok(CertificateEncoding::HashUrlX509Bundle),
            14 => Ok(CertificateEncoding::OCSPContent),
            15 => Ok(CertificateEncoding::RawPublicKey),
            16..=200 => Err(UnparseableParameter::Unassigned),
            201..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Type of authentication method being used
///
/// Value 0 is reserved, values 4-8 and 15-200 are unassigned and
/// values 201-255 are reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
#[allow(non_camel_case_types, missing_docs)]
pub enum AuthenticationMethod {
    RSADigitalSignature = 1,
    SharedKeyMessageIntegrityCode = 2,
    DSSDigitalSignature = 3,
    ECDSA_SHA_256_ECP_256 = 9,
    ECDSA_SHA_384_ECP_384 = 10,
    ECDSA_SHA_512_ECP_521 = 11,
    GenericSecurePassword = 12,
    NULLAuthentication = 13,
    DigitalSignature = 14,
}

impl TryFrom<u8> for AuthenticationMethod {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(AuthenticationMethod::RSADigitalSignature),
            2 => Ok(AuthenticationMethod::SharedKeyMessageIntegrityCode),
            3 => Ok(AuthenticationMethod::DSSDigitalSignature),
            4..=8 => Err(UnparseableParameter::Unassigned),
            9 => Ok(AuthenticationMethod::ECDSA_SHA_256_ECP_256),
            10 => Ok(AuthenticationMethod::ECDSA_SHA_384_ECP_384),
            11 => Ok(AuthenticationMethod::ECDSA_SHA_512_ECP_521),
            12 => Ok(AuthenticationMethod::GenericSecurePassword),
            13 => Ok(AuthenticationMethod::NULLAuthentication),
            14 => Ok(AuthenticationMethod::DigitalSignature),
            15..=200 => Err(UnparseableParameter::Unassigned),
            201..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for the notify error message types
///
/// The values 0, 2, 3, 6, 8, 10, 12, 13, 15, 16, 18-23, 25-33 are reserved.
/// Values 50-8191 are currently unassigned and 8192-65535 reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum NotifyErrorMessage {
    UnsupportedCriticalPayload = 1,
    InvalidIkeSpi = 4,
    InvalidMajorVersion = 5,
    /// Indicates the IKE message that was received was invalid because
    /// some type, length, or value was out of range or because the
    /// request was rejected for policy reasons. To avoid a DoS
    /// attack using forged messages, this status may only be
    /// returned for and in an encrypted packet if the Message ID and
    /// cryptographic checksum were valid. To avoid leaking information
    /// to someone probing a node, this status MUST be sent in response
    /// to any error not covered by one of the other status types.
    /// To aid debugging, more detailed error information should be
    /// written to a console or log.
    InvalidSyntax = 7,
    InvalidMessageId = 9,
    InvalidSpi = 11,
    NoProposalChosen = 14,
    InvalidKeyExchangePayload = 17,
    AuthenticationFailed = 24,
    SinglePairRequired = 34,
    NoAdditionalSas = 35,
    InternalAddressFailure = 36,
    FailedCpRequired = 37,
    TsUnacceptable = 38,
    InvalidSelectors = 39,
    UnacceptableAddresses = 40,
    UnexpectedNatDetected = 41,
    UseAssignedHoA = 42,
    TemporaryFailure = 43,
    ChildSaNotFound = 44,
    InvalidGroupId = 45,
    AuthorizationFailed = 46,
    StateNotFound = 47,
    TsMaxQueue = 48,
    RegistrationFailed = 49,
    /// Windows uses the code 12345 (0x3039) from the 'private use' range to transmit status
    /// information to other Windows peers. See strongSwan's docs for infos
    /// [here](https://docs.strongswan.org/docs/latest/interop/microsoftStatusNotify.html).
    /// The notification data is expected to be a 32-bit integer status code,
    /// where its meaning can be looked up in the document
    /// [here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/1bc92ddf-b79e-413c-bbaa-99a5281a6c90).
    /// For example, `0x000035ED` means `ERROR_IPSEC_IKE_TIMED_OUT` and `0x000035F0`
    /// is `ERROR_IPSEC_IKE_SA_REAPED`. These codes will not be interpreted by this library though.
    MicrosoftWindowsStatusNotify = 12345,
}

impl TryFrom<u16> for NotifyErrorMessage {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(NotifyErrorMessage::UnsupportedCriticalPayload),
            2..=3 => Err(UnparseableParameter::Reserved),
            4 => Ok(NotifyErrorMessage::InvalidIkeSpi),
            5 => Ok(NotifyErrorMessage::InvalidMajorVersion),
            6 => Err(UnparseableParameter::Reserved),
            7 => Ok(NotifyErrorMessage::InvalidSyntax),
            8 => Err(UnparseableParameter::Reserved),
            9 => Ok(NotifyErrorMessage::InvalidMessageId),
            10 => Err(UnparseableParameter::Reserved),
            11 => Ok(NotifyErrorMessage::InvalidSpi),
            12..=13 => Err(UnparseableParameter::Reserved),
            14 => Ok(NotifyErrorMessage::NoProposalChosen),
            15..=16 => Err(UnparseableParameter::Reserved),
            17 => Ok(NotifyErrorMessage::InvalidKeyExchangePayload),
            18..=23 => Err(UnparseableParameter::Reserved),
            24 => Ok(NotifyErrorMessage::AuthenticationFailed),
            25..=33 => Err(UnparseableParameter::Reserved),
            34 => Ok(NotifyErrorMessage::SinglePairRequired),
            35 => Ok(NotifyErrorMessage::NoAdditionalSas),
            36 => Ok(NotifyErrorMessage::InternalAddressFailure),
            37 => Ok(NotifyErrorMessage::FailedCpRequired),
            38 => Ok(NotifyErrorMessage::TsUnacceptable),
            39 => Ok(NotifyErrorMessage::InvalidSelectors),
            40 => Ok(NotifyErrorMessage::UnacceptableAddresses),
            41 => Ok(NotifyErrorMessage::UnexpectedNatDetected),
            42 => Ok(NotifyErrorMessage::UseAssignedHoA),
            43 => Ok(NotifyErrorMessage::TemporaryFailure),
            44 => Ok(NotifyErrorMessage::ChildSaNotFound),
            45 => Ok(NotifyErrorMessage::InvalidGroupId),
            46 => Ok(NotifyErrorMessage::AuthorizationFailed),
            47 => Ok(NotifyErrorMessage::StateNotFound),
            48 => Ok(NotifyErrorMessage::TsMaxQueue),
            49 => Ok(NotifyErrorMessage::RegistrationFailed),
            50..=8191 => Err(UnparseableParameter::Unassigned),
            8192..=12344 => Err(UnparseableParameter::PrivateUse),
            12345 => Ok(NotifyErrorMessage::MicrosoftWindowsStatusNotify),
            12346..=16383 => Err(UnparseableParameter::PrivateUse),
            16384..=65535 => Err(UnparseableParameter::OutOfRange),
        }
    }
}

/// Values for the security protocol identifiers
///
/// These are used in a proposal to specify the type of protocol to use
/// to negotiate the Security Association. Value 0 is reserved but used
/// in the protocol in various cases and thus not an error. The
/// values 7-200 are unassigned and 201-255 reserved for private use.
///
/// In this project, only [SecurityProtocol::InternetKeyExchange] is relevant.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum SecurityProtocol {
    Reserved = 0,
    InternetKeyExchange = 1,
    AuthenticationHeader = 2,
    EncapsulatingSecurityPayload = 3,
    FcEncapsulatingSecurityPayloadHeader = 4,
    FcCtAuthentication = 5,
    GroupIKEUpdate = 6,
}

impl TryFrom<u8> for SecurityProtocol {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SecurityProtocol::Reserved),
            1 => Ok(SecurityProtocol::InternetKeyExchange),
            2 => Ok(SecurityProtocol::AuthenticationHeader),
            3 => Ok(SecurityProtocol::EncapsulatingSecurityPayload),
            4 => Ok(SecurityProtocol::FcEncapsulatingSecurityPayloadHeader),
            5 => Ok(SecurityProtocol::FcCtAuthentication),
            6 => Ok(SecurityProtocol::GroupIKEUpdate),
            7..=200 => Err(UnparseableParameter::Unassigned),
            201..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for the hash algorithm identifier
///
/// Values 0 are reserved, 8-1023 unassigned and 1024-65535 reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(non_camel_case_types, missing_docs)]
pub enum HashAlgorithm {
    SHA1 = 1,
    SHA2_256 = 2,
    SHA2_384 = 3,
    SHA2_512 = 4,
    Identity = 5,
    Streebog_256 = 6,
    Streebog_512 = 7,
}

impl TryFrom<u16> for HashAlgorithm {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(HashAlgorithm::SHA1),
            2 => Ok(HashAlgorithm::SHA2_256),
            3 => Ok(HashAlgorithm::SHA2_384),
            4 => Ok(HashAlgorithm::SHA2_512),
            5 => Ok(HashAlgorithm::Identity),
            6 => Ok(HashAlgorithm::Streebog_256),
            7 => Ok(HashAlgorithm::Streebog_512),
            8..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for the notify message status types
///
/// These are used to mark special notifications to the other peer(s) of
/// an IKE conversation. Notably, they do not indicate failures per-se,
/// unlike [NotifyErrorMessage].
///
/// Values 0-16383 are out of range, 16447-40959 currently unassigned and
/// 40960-65535 reserved for private use.
#[derive(Debug, Clone, Display, EnumIter, Copy, Serialize, Deserialize)] //
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum NotifyStatusMessage {
    InitialContact = 16384,
    SetWindowSize = 16385,
    AdditionalTsPossible = 16386,
    IpCompSupported = 16387,
    NatDetectionSourceIp = 16388,
    NatDetectionDestinationIp = 16389,
    Cookie = 16390,
    UseTransportMode = 16391,
    HttpCertLookupSupported = 16392,
    RekeySa = 16393,
    EspTfcPaddingNotSupported = 16394,
    NonFirstFragmentsAlso = 16395,
    MobIkeSupported = 16396,
    AdditionalIp4Address = 16397,
    AdditionalIp6Address = 16398,
    NoAdditionalAddresses = 16399,
    UpdateSaAddresses = 16400,
    Cookie2 = 16401, // see RFC 4555, section 4.2.5 - not relevant for IKEv2 only
    NoNatsAllowed = 16402,
    AuthLifetime = 16403,
    MultipleAuthSupported = 16404,
    AnotherAuthFollows = 16405,
    RedirectSupported = 16406,
    Redirect = 16407,
    RedirectedFrom = 16408,
    TicketLtOpaque = 16409,
    TicketRequest = 16410,
    TicketAck = 16411,
    TicketNack = 16412,
    TicketOpaque = 16413,
    LinkId = 16414,
    UseWespMode = 16415,
    RohcSupported = 16416,
    EapOnlyAuthentication = 16417,
    ChildlessIkev2Supported = 16418,
    QuickCrashDetection = 16419,
    Ikev2MessageIdSyncSupported = 16420,
    IpsecReplayCounterSyncSupported = 16421,
    Ikev2MessageIdSync = 16422,
    IpsecReplayCounterSync = 16423,
    SecurePasswordMethods = 16424,
    PskPersist = 16425,
    PskConfirm = 16426,
    ErxSupported = 16427,
    IfomCapability = 16428,
    GroupSender = 16429,
    Ikev2FragmentationSupported = 16430,
    SignatureHashAlgorithms = 16431,
    CloneIkeSaSupported = 16432,
    CloneIkeSa = 16433,
    Puzzle = 16434,
    UsePpk = 16435,
    PpkIdentity = 16436,
    NoPpkAuth = 16437,
    IntermediateExchangeSupported = 16438,
    Ip4Allowed = 16439,
    Ip6Allowed = 16440,
    AdditionalKeyExchange = 16441,
    UseAgfrag = 16442,
    SupportedAuthMethods = 16443,
    SaResourceInfo = 16444,
    UsePpkInt = 16445,
    PpkIdentityKey = 16446,
}

impl TryFrom<u16> for NotifyStatusMessage {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0..=16383 => Err(UnparseableParameter::OutOfRange),
            16384 => Ok(NotifyStatusMessage::InitialContact),
            16385 => Ok(NotifyStatusMessage::SetWindowSize),
            16386 => Ok(NotifyStatusMessage::AdditionalTsPossible),
            16387 => Ok(NotifyStatusMessage::IpCompSupported),
            16388 => Ok(NotifyStatusMessage::NatDetectionSourceIp),
            16389 => Ok(NotifyStatusMessage::NatDetectionDestinationIp),
            16390 => Ok(NotifyStatusMessage::Cookie),
            16391 => Ok(NotifyStatusMessage::UseTransportMode),
            16392 => Ok(NotifyStatusMessage::HttpCertLookupSupported),
            16393 => Ok(NotifyStatusMessage::RekeySa),
            16394 => Ok(NotifyStatusMessage::EspTfcPaddingNotSupported),
            16395 => Ok(NotifyStatusMessage::NonFirstFragmentsAlso),
            16396 => Ok(NotifyStatusMessage::MobIkeSupported),
            16397 => Ok(NotifyStatusMessage::AdditionalIp4Address),
            16398 => Ok(NotifyStatusMessage::AdditionalIp6Address),
            16399 => Ok(NotifyStatusMessage::NoAdditionalAddresses),
            16400 => Ok(NotifyStatusMessage::UpdateSaAddresses),
            16401 => Ok(NotifyStatusMessage::Cookie2),
            16402 => Ok(NotifyStatusMessage::NoNatsAllowed),
            16403 => Ok(NotifyStatusMessage::AuthLifetime),
            16404 => Ok(NotifyStatusMessage::MultipleAuthSupported),
            16405 => Ok(NotifyStatusMessage::AnotherAuthFollows),
            16406 => Ok(NotifyStatusMessage::RedirectSupported),
            16407 => Ok(NotifyStatusMessage::Redirect),
            16408 => Ok(NotifyStatusMessage::RedirectedFrom),
            16409 => Ok(NotifyStatusMessage::TicketLtOpaque),
            16410 => Ok(NotifyStatusMessage::TicketRequest),
            16411 => Ok(NotifyStatusMessage::TicketAck),
            16412 => Ok(NotifyStatusMessage::TicketNack),
            16413 => Ok(NotifyStatusMessage::TicketOpaque),
            16414 => Ok(NotifyStatusMessage::LinkId),
            16415 => Ok(NotifyStatusMessage::UseWespMode),
            16416 => Ok(NotifyStatusMessage::RohcSupported),
            16417 => Ok(NotifyStatusMessage::EapOnlyAuthentication),
            16418 => Ok(NotifyStatusMessage::ChildlessIkev2Supported),
            16419 => Ok(NotifyStatusMessage::QuickCrashDetection),
            16420 => Ok(NotifyStatusMessage::Ikev2MessageIdSyncSupported),
            16421 => Ok(NotifyStatusMessage::IpsecReplayCounterSyncSupported),
            16422 => Ok(NotifyStatusMessage::Ikev2MessageIdSync),
            16423 => Ok(NotifyStatusMessage::IpsecReplayCounterSync),
            16424 => Ok(NotifyStatusMessage::SecurePasswordMethods),
            16425 => Ok(NotifyStatusMessage::PskPersist),
            16426 => Ok(NotifyStatusMessage::PskConfirm),
            16427 => Ok(NotifyStatusMessage::ErxSupported),
            16428 => Ok(NotifyStatusMessage::IfomCapability),
            16429 => Ok(NotifyStatusMessage::GroupSender),
            16430 => Ok(NotifyStatusMessage::Ikev2FragmentationSupported),
            16431 => Ok(NotifyStatusMessage::SignatureHashAlgorithms),
            16432 => Ok(NotifyStatusMessage::CloneIkeSaSupported),
            16433 => Ok(NotifyStatusMessage::CloneIkeSa),
            16434 => Ok(NotifyStatusMessage::Puzzle),
            16435 => Ok(NotifyStatusMessage::UsePpk),
            16436 => Ok(NotifyStatusMessage::PpkIdentity),
            16437 => Ok(NotifyStatusMessage::NoPpkAuth),
            16438 => Ok(NotifyStatusMessage::IntermediateExchangeSupported),
            16439 => Ok(NotifyStatusMessage::Ip4Allowed),
            16440 => Ok(NotifyStatusMessage::Ip6Allowed),
            16441 => Ok(NotifyStatusMessage::AdditionalKeyExchange),
            16442 => Ok(NotifyStatusMessage::UseAgfrag),
            16443 => Ok(NotifyStatusMessage::SupportedAuthMethods),
            16444 => Ok(NotifyStatusMessage::SaResourceInfo),
            16445 => Ok(NotifyStatusMessage::UsePpkInt),
            16446 => Ok(NotifyStatusMessage::PpkIdentityKey),
            16447..=40959 => Err(UnparseableParameter::Unassigned),
            40960..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}
