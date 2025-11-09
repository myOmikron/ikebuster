use isakmp::v2::definitions::params::EncryptionAlgorithm;
use isakmp::v2::definitions::params::IntegrityAlgorithm;
use isakmp::v2::definitions::params::KeyExchangeMethod;
use isakmp::v2::definitions::params::NotifyErrorMessage;
use isakmp::v2::definitions::params::PseudorandomFunction;
use isakmp::v2::definitions::params::SecurityProtocol;
use isakmp::v2::definitions::IKEv2;
use isakmp::v2::definitions::NotificationType;
use isakmp::v2::definitions::Payload;
use isakmp::v2::definitions::Proposal;
use isakmp::v2::parser::ParserError;
use tokio::net::UdpSocket;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

use crate::v2::sender::make_new_hello_packet;
use crate::v2::MAX_DATAGRAM_SIZE;
use crate::ScanError;

/// Probe towards the IKEv2 destination and send a single [IKEv2] packet with
/// two huge proposals that accept a lot of defaults to determine if the
/// destination is likely to accept our scan. It will not be a fool-proof indicator,
/// but if this returns `false` then the scan might not produce any results.
/// Note that this should be done at the start of the scan, because it can quickly
/// determine if a host is dead or does not support [IKEv2] at all.
#[allow(clippy::expect_used)]
pub(crate) async fn probe_target(socket: &UdpSocket) -> Result<bool, ScanError> {
    let (msg, _) = make_new_hello_packet(get_standard_proposals())
        .expect("failed to make new hello packet with standard ciphers");
    let serialized_msg = msg.try_build().map_err(ScanError::GeneratorFailed)?;
    let sent_bytes = socket
        .send(serialized_msg.as_slice())
        .await
        .map_err(ScanError::Send)?;
    debug!("Sent {sent_bytes} bytes with huge proposal to check availability");

    let mut recv_buffer = [0u8; MAX_DATAGRAM_SIZE];
    let recv_bytes = socket.recv(&mut recv_buffer).await.map_err(|e| {
        error!("Failed to read bytes from socket: {e}");
        ScanError::Receive(e)
    })?;
    debug!("Received {recv_bytes} bytes from responder");
    trace!(data = ?&recv_buffer[..recv_bytes], "Received data from responder");

    let packet = match IKEv2::try_parse(&recv_buffer[..recv_bytes]) {
        Ok(v) => v,
        Err(ParserError::WrongProtocol) => {
            info!("Responder replied with different IKE protocol version. Try IKEv1.");
            return Ok(false);
        }
        Err(err) => {
            error!(err = ?err, "Failed to parse IKEv2 packet: {err}");
            return Ok(false);
        }
    };
    trace!(packet = ?packet, "Correctly parsed incoming IKEv2 packet");

    for payload in packet.payloads.iter() {
        if let Payload::Notify(n) = payload {
            if let NotificationType::Error(e) = n.variant {
                match e {
                    NotifyErrorMessage::InvalidMajorVersion => {
                        info!("Destination is not capable of speaking IKEv2");
                        return Ok(false);
                    }
                    NotifyErrorMessage::NoProposalChosen => {
                        info!("Responder understood request but did not pick any proposal.");
                        return Ok(false);
                    }
                    NotifyErrorMessage::InvalidSyntax => {
                        warn!(packet = ?packet, "Responder rejected the request with invalid syntax!");
                        return Ok(false);
                    }
                    _ => {}
                }
            }
        }
    }

    info!("No negative acceptance indicators, destination likely accepts our IKEv2 scan");
    Ok(true)
}

/// Get two huge standard proposals (normal & AEAD proposal)
///
/// These two proposals list a lot of transformations that are seen often
/// and therefore are likely to be accepted by a responder that is
/// willing to negotiate using the standard ciphers.
fn get_standard_proposals() -> Vec<Proposal> {
    let p1 = Proposal {
        protocol: SecurityProtocol::InternetKeyExchange,
        spi: vec![],
        encryption_algorithms: vec![
            (EncryptionAlgorithm::AES_CBC, Some(128)),
            (EncryptionAlgorithm::AES_CBC, Some(256)),
            (EncryptionAlgorithm::AES_CTR, Some(256)),
            (EncryptionAlgorithm::TRIPLE_DES, None),
            (EncryptionAlgorithm::RC5, Some(256)),
            (EncryptionAlgorithm::CAMELLIA_CBC, Some(256)),
            (EncryptionAlgorithm::CAMELLIA_CTR, Some(256)),
        ],
        pseudo_random_functions: vec![
            PseudorandomFunction::HMAC_MD5,
            PseudorandomFunction::HMAC_SHA1,
            PseudorandomFunction::HMAC_SHA2_256,
            PseudorandomFunction::HMAC_SHA2_384,
            PseudorandomFunction::HMAC_SHA2_512,
            PseudorandomFunction::AES128_CMAC,
            PseudorandomFunction::AES128_XCBC,
        ],
        integrity_algorithms: vec![
            IntegrityAlgorithm::HMAC_MD5_96,
            IntegrityAlgorithm::HMAC_MD5_128,
            IntegrityAlgorithm::HMAC_SHA1_96,
            IntegrityAlgorithm::HMAC_SHA1_160,
            IntegrityAlgorithm::AES_128_GMAC,
            IntegrityAlgorithm::AES_256_GMAC,
            IntegrityAlgorithm::HMAC_SHA2_256_128,
            IntegrityAlgorithm::HMAC_SHA2_384_192,
            IntegrityAlgorithm::HMAC_SHA2_512_256,
        ],
        key_exchange_methods: vec![
            KeyExchangeMethod::MODP_2048,
            KeyExchangeMethod::ECP_Random_192,
            KeyExchangeMethod::ECP_Random_384,
            KeyExchangeMethod::ECP_Random_521,
            KeyExchangeMethod::MODP_1024,
            KeyExchangeMethod::MODP_3072,
            KeyExchangeMethod::MODP_4096,
            KeyExchangeMethod::Curve_448,
            KeyExchangeMethod::Curve_25519,
        ],
        sequence_numbers: vec![],
    };
    let p2 = Proposal {
        protocol: SecurityProtocol::InternetKeyExchange,
        spi: vec![],
        encryption_algorithms: vec![
            (EncryptionAlgorithm::AES_CCM_8, Some(256)),
            (EncryptionAlgorithm::AES_CCM_16, Some(256)),
            (EncryptionAlgorithm::AES_GCM_8, Some(256)),
            (EncryptionAlgorithm::AES_GCM_16, Some(256)),
            (EncryptionAlgorithm::CHACHA20_POLY1305, None),
        ],
        pseudo_random_functions: vec![
            PseudorandomFunction::HMAC_MD5,
            PseudorandomFunction::HMAC_SHA1,
            PseudorandomFunction::HMAC_SHA2_256,
            PseudorandomFunction::HMAC_SHA2_384,
            PseudorandomFunction::HMAC_SHA2_512,
            PseudorandomFunction::AES128_CMAC,
            PseudorandomFunction::AES128_XCBC,
        ],
        integrity_algorithms: vec![],
        key_exchange_methods: vec![
            KeyExchangeMethod::MODP_2048,
            KeyExchangeMethod::ECP_Random_192,
            KeyExchangeMethod::ECP_Random_384,
            KeyExchangeMethod::ECP_Random_521,
            KeyExchangeMethod::MODP_1024,
            KeyExchangeMethod::MODP_3072,
            KeyExchangeMethod::MODP_4096,
            KeyExchangeMethod::Curve_448,
            KeyExchangeMethod::Curve_25519,
        ],
        sequence_numbers: vec![],
    };
    vec![p2, p1]
}
