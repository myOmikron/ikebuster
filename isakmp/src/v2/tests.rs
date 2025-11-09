use crate::v2::definitions::params::EncryptionAlgorithm;
use crate::v2::definitions::params::ExchangeType;
use crate::v2::definitions::params::IntegrityAlgorithm;
use crate::v2::definitions::params::KeyExchangeMethod;
use crate::v2::definitions::params::NotifyErrorMessage;
use crate::v2::definitions::params::NotifyStatusMessage;
use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::params::PseudorandomFunction;
use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::GenericPayloadHeader;
use crate::v2::definitions::IKEv2;
use crate::v2::definitions::KeyExchange;
use crate::v2::definitions::Notification;
use crate::v2::definitions::NotificationType;
use crate::v2::definitions::Payload;
use crate::v2::definitions::Proposal;
use crate::v2::definitions::SecurityAssociation;
use crate::v2::definitions::Transform;
use crate::v2::generator::GeneratorError;
use crate::v2::parser::ParserError;

#[test]
#[allow(clippy::unwrap_used)]
fn generate_sa_to_failure() {
    let mut p = Proposal::new_empty(
        SecurityProtocol::InternetKeyExchange,
        Some(vec![0x13, 0x37]),
    );
    p.add(vec![Transform::Encryption(
        EncryptionAlgorithm::BLOWFISH,
        Some(128),
    )]);
    let sa = SecurityAssociation { proposals: vec![p] };
    let result = sa.try_build(PayloadType::NoNextPayload);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        GeneratorError::MissingMandatoryTransform
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn parse_sa_to_failure() {
    let buf = vec![
        0x00, 0x00, 0x00, 0x16, 0x01, 0x01, 0x02, 0x01, // Proposal
        0x13, 0x37, // SPI
        0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x07, 0x80, 0xe, 0x00, 0x80, // transform 1
    ];
    let parsed_sa = SecurityAssociation::try_parse(&buf);
    assert!(parsed_sa.is_err());
    assert_eq!(
        parsed_sa.unwrap_err(),
        ParserError::MissingMandatoryTransform
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_and_parse_full_sa() {
    let mut p = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, Some(vec![]));
    p.add(vec![
        Transform::Integrity(IntegrityAlgorithm::HMAC_SHA2_256_128),
        Transform::Integrity(IntegrityAlgorithm::HMAC_SHA2_512_256),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_256),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_384),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_512),
        Transform::KeyExchange(KeyExchangeMethod::Curve_448),
        Transform::KeyExchange(KeyExchangeMethod::Curve_25519),
        Transform::Encryption(EncryptionAlgorithm::AES_GCM_12, Some(31337)),
    ]);
    let sa = SecurityAssociation { proposals: vec![p] };
    let sa_repr = sa.try_build(PayloadType::KeyExchange).unwrap();
    let buff = vec![
        0x22, 0x00, 0x00, 0x50, // Security Association header
        0x00, 0x00, 0x00, 0x4c, 0x01, 0x01, 0x00, 0x08, // Proposal header
        0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x13, // Transform 1, encryption
        0x80, 0x0e, 0x7a, 0x69, // Transform 1, encryption, attributes
        0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, // Transform 2, PRF 1
        0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x06, // Transform 3, PRF 2
        0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x07, // Transform 4, PRF 3
        0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, // Transform 5, integrity 1
        0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0e, // Transform 6, integrity 2
        0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x20, // Transform 7, KE 1
        0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f, // Transform 8, KE 2
    ];
    assert_eq!(sa_repr, buff);
    let parsed_sa =
        SecurityAssociation::try_parse(&buff[size_of::<GenericPayloadHeader>()..]).unwrap();
    assert_eq!(sa, parsed_sa);
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_and_parse_sa_with_many_empty_proposals() {
    let mut sa = SecurityAssociation { proposals: vec![] };
    for i in 0..100 {
        let mut p = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, Some(vec![i + 1]));
        p.add(vec![
            Transform::Encryption(EncryptionAlgorithm::AES_GCM_12, Some(256)),
            Transform::Integrity(IntegrityAlgorithm::HMAC_SHA2_256_128),
            Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_512),
            Transform::KeyExchange(KeyExchangeMethod::ECP_Random_521),
        ]);
        sa.proposals.push(p);
    }
    let generated_sa = sa.try_build(PayloadType::NoNextPayload).unwrap();
    let parsed_sa = SecurityAssociation::try_parse(
        generated_sa.as_slice()[size_of::<GenericPayloadHeader>()..]
            .iter()
            .as_slice(),
    )
    .unwrap();
    assert_eq!(sa, parsed_sa);
    assert_eq!(sa.proposals.len(), 100);
    for i in 0..100 {
        assert_eq!(sa.proposals[i].spi[0], 1 + i as u8);
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_and_parse_notify() {
    let spi = [0x00, 0x01, 0x02, 0x03];
    let notify = Notification {
        variant: NotificationType::Error(NotifyErrorMessage::InvalidSpi),
        data: vec![0x13, 0x37],
        protocol: SecurityProtocol::EncapsulatingSecurityPayload,
        spi: Some(spi.to_vec()),
    };
    let generated_notify = notify.try_build(PayloadType::NoNextPayload).unwrap();
    let expected_result = vec![
        0x00, 0x00, 0x00, 0x0e, // Generic Payload Header
        0x03, 0x04, 0x00, 0x0b, // Notification header
        0x00, 0x01, 0x02, 0x03, // SPI
        0x13, 0x37, // Data
    ];
    assert_eq!(generated_notify, expected_result);
    let parsed_notify =
        Notification::try_parse(expected_result.as_slice()[4..].iter().as_slice()).unwrap();
    assert_eq!(notify, parsed_notify);
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_and_parse_notify2() {
    let notification = Notification {
        variant: NotificationType::Status(NotifyStatusMessage::SignatureHashAlgorithms),
        // Data meaning:
        //   Supported Signature Hash Algorithm: SHA2-256 (2)
        //   Supported Signature Hash Algorithm: SHA2-384 (3)
        //   Supported Signature Hash Algorithm: SHA2-512 (4)
        data: vec![0x00, 0x02, 0x00, 0x03, 0x00, 0x04],
        protocol: SecurityProtocol::Reserved,
        spi: None,
    };
    let generated_notify = notification.try_build(PayloadType::Notify).unwrap();
    let expected_result = vec![
        0x29, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x40, 0x2f, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
    ];
    assert_eq!(generated_notify, expected_result);
    let parsed_notify =
        Notification::try_parse(expected_result.as_slice()[4..].iter().as_slice()).unwrap();
    assert_eq!(notification, parsed_notify);
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_and_parse_packet() {
    let nonce = vec![
        0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, //
        0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
    ];
    let ike = IKEv2 {
        initiator_cookie: 0x48cfb887c03b2e7f, // random data
        responder_cookie: 0x55bf4a6acd91535e, // random data
        exchange_type: ExchangeType::IkeSaInit,
        initiator: true,
        response: false,
        message_id: 0x661cf0d4, // random data
        payloads: vec![
            Payload::VendorID(vec![0x42]),
            Payload::Nonce(nonce.clone()),
            Payload::SecurityAssociation(SecurityAssociation { proposals: vec![] }),
            Payload::EncryptedAndAuthenticated(vec![0x54, 0x65, 0x73, 0x74]), // "Test"
        ],
    };
    let generated_packet = ike.try_build().unwrap();
    let parsed_ike = IKEv2::try_parse(generated_packet.as_slice()).unwrap();
    assert_eq!(ike, parsed_ike);
    assert_eq!(ike.payloads.len(), 4);
    assert_eq!(ike.payloads[0], Payload::VendorID(vec![0x42]));
    assert_eq!(ike.payloads[1], Payload::Nonce(nonce));
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_packet_with_cookie_notification() {
    let dh_group = KeyExchangeMethod::Curve_25519;
    let ike = IKEv2 {
        initiator_cookie: 0x1234567890abcdef,
        responder_cookie: 0xfedcba0987654321,
        exchange_type: ExchangeType::IkeSaInit,
        initiator: true,
        response: false,
        message_id: 0x3b20cae8, // random data
        payloads: vec![
            Payload::VendorID(vec![0x42]),
            Payload::SecurityAssociation(SecurityAssociation { proposals: vec![] }),
            Payload::Notify(Notification {
                variant: NotificationType::Status(NotifyStatusMessage::Cookie),
                data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                protocol: SecurityProtocol::Reserved,
                spi: None,
            }),
            Payload::Nonce(vec![
                0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, //
                0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
            ]),
            Payload::KeyExchange(KeyExchange {
                dh_group,
                data: vec![0xff; dh_group.get_key_handshake_length()], // 32 bytes
            }),
        ],
    };
    let serialized = ike.try_build().unwrap();
    assert_eq!(serialized.len(), 113);
    assert_eq!(serialized[16], 0x29); // next payload in IKE header
    assert_eq!(
        serialized[28..81],
        vec![
            0x2b, 0x00, 0x00, 0x10, // Generic Payload header for cookie
            0x00, // Security Protocol
            0x00, // SPI size
            0x40, 0x06, // Notify Message Type
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Cookie data
            0x21, 0x00, 0x00, 0x05, // Generic Payload header for vendor ID
            0x42, // Vendor ID data
            0x28, 0x00, 0x00, 0x04, // Generic Payload header for SA
            0x22, 0x00, 0x00, 0x14, // Generic Payload header for Nonce
            0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, // Nonce data 1
            0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, // Nonce data 2
            0x00, 0x00, 0x00, 0x28, // Generic Payload header for KE
            0x00, 0x1f, 0x00, 0x00, // KE header
        ]
    );
    assert_eq!(serialized[81..], vec![0xff; 32]); // Key Exchange payload data
}
