use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

use crate::v2::definitions::header::ProposalHeader;
use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::Proposal;
use crate::v2::definitions::Transform;
use crate::v2::generator::GeneratorError;
use crate::v2::generator::EXPECTED_TRANSFORM_LENGTH;

impl Proposal {
    /// Convert a [Proposal] into a network-level vector of bytes
    ///
    /// The argument `num` defines the number of the proposal in the list of
    /// proposals in a Security Association.
    ///
    /// The argument `last` defines if any proposal is following this proposal (false)
    /// or if this proposal is the last proposal in the Security Association payload (true).
    pub fn try_build(&self, num: u8, last: bool) -> Result<Vec<u8>, GeneratorError> {
        match self.protocol {
            // See section 3.3.3 of RFC 7296
            SecurityProtocol::InternetKeyExchange => {
                if self.encryption_algorithms.is_empty()
                    || self.pseudo_random_functions.is_empty()
                    || self.key_exchange_methods.is_empty()
                {
                    return Err(GeneratorError::MissingMandatoryTransform);
                }
                if self.integrity_algorithms.is_empty()
                    && self
                        .encryption_algorithms
                        .iter()
                        .all(|(e, _)| !e.is_aead_cipher())
                {
                    // If not a single AEAD cipher is negotiated, then integrity algorithm is mandatory, otherwise it is optional
                    return Err(GeneratorError::MissingMandatoryTransform);
                }
            }
            SecurityProtocol::AuthenticationHeader => {
                if self.encryption_algorithms.is_empty() || self.sequence_numbers.is_empty() {
                    return Err(GeneratorError::MissingMandatoryTransform);
                }
            }
            SecurityProtocol::EncapsulatingSecurityPayload => {
                if self.integrity_algorithms.is_empty() || self.sequence_numbers.is_empty() {
                    return Err(GeneratorError::MissingMandatoryTransform);
                }
            }
            _ => {}
        };

        let mut transforms = Vec::with_capacity(EXPECTED_TRANSFORM_LENGTH * self.len());
        let chain_iterator = self
            .encryption_algorithms
            .iter()
            .cloned()
            .map(|(e, o)| Transform::Encryption(e, o))
            .chain(
                self.pseudo_random_functions
                    .iter()
                    .cloned()
                    .map(Transform::PseudoRandomFunction),
            )
            .chain(
                self.integrity_algorithms
                    .iter()
                    .cloned()
                    .map(Transform::Integrity),
            )
            .chain(
                self.key_exchange_methods
                    .iter()
                    .cloned()
                    .map(Transform::KeyExchange),
            )
            .chain(
                self.sequence_numbers
                    .iter()
                    .cloned()
                    .map(Transform::SequenceNumber),
            );
        for (i, transform) in chain_iterator.enumerate() {
            transforms.extend(transform.build(i == self.len() - 1));
        }

        let packet_length = 8 + self.spi.len() as u16 + transforms.len() as u16;
        let header = ProposalHeader {
            last_substruct: if last { 0 } else { 2 },
            reserved: 0,
            proposal_length: U16::from(packet_length),
            proposal_num: num,
            protocol_id: self.protocol as u8,
            spi_size: self.spi.len() as u8,
            num_transforms: self.len() as u8,
        };

        let mut packet = Vec::with_capacity(packet_length as usize);
        packet.extend_from_slice(header.as_bytes());
        packet.extend(self.spi.clone());
        packet.extend(transforms);
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::EncryptionAlgorithm;
    use crate::v2::definitions::params::IntegrityAlgorithm;
    use crate::v2::definitions::params::KeyExchangeMethod;
    use crate::v2::definitions::params::PseudorandomFunction;
    use crate::v2::definitions::params::SecurityProtocol;
    use crate::v2::definitions::Proposal;
    use crate::v2::definitions::Transform;
    use crate::v2::generator::GeneratorError::MissingMandatoryTransform;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn empty() {
        assert_eq!(
            Proposal::new_empty(
                SecurityProtocol::InternetKeyExchange,
                Some(vec![0x13, 0x37])
            )
            .try_build(1, true)
            .unwrap_err(),
            MissingMandatoryTransform
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn single_missing_others() {
        let mut p = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, None);
        p.key_exchange_methods.push(KeyExchangeMethod::Curve_448);
        let e = p.try_build(1, true);
        assert!(e.is_err());
        assert_eq!(e.err().unwrap(), MissingMandatoryTransform);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn full() {
        let mut p = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, None);
        p.encryption_algorithms
            .push((EncryptionAlgorithm::AES_CBC, Some(256)));
        p.pseudo_random_functions
            .push(PseudorandomFunction::HMAC_SHA2_256);
        p.integrity_algorithms
            .push(IntegrityAlgorithm::HMAC_SHA2_256_128);
        p.key_exchange_methods.push(KeyExchangeMethod::Curve_25519);
        assert_eq!(
            p.try_build(4, true).unwrap(),
            vec![
                0x00, 0x00, 0x00, 0x2c, 0x04, 0x01, 0x00, 0x04, // proposal header
                0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, // encryption header
                0x80, 0x0e, 0x01, 0x00, // encryption payload
                0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, // integrity
                0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, // PRF
                0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f // KE
            ]
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn full_also_with_duplicates() {
        let mut p = Proposal::new_empty(
            SecurityProtocol::InternetKeyExchange,
            Some(vec![0x13, 0x37]),
        );
        p.add(vec![
            Transform::Integrity(IntegrityAlgorithm::AES_256_GMAC),
            Transform::Encryption(EncryptionAlgorithm::CAMELLIA_CBC, None),
            Transform::Encryption(EncryptionAlgorithm::AES_CCM_16, Some(256)),
            Transform::Encryption(EncryptionAlgorithm::AES_GCM_16, Some(128)),
            Transform::Integrity(IntegrityAlgorithm::AES_256_GMAC),
            Transform::Integrity(IntegrityAlgorithm::AES_256_GMAC),
            Transform::KeyExchange(KeyExchangeMethod::Curve_25519),
            Transform::KeyExchange(KeyExchangeMethod::Curve_448),
            Transform::KeyExchange(KeyExchangeMethod::MODP_4096),
            Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_STREEBOG_512),
            Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_512),
        ]);
        let result = p.try_build(100, true).unwrap();
        assert_eq!(result.len(), 106);
        assert_eq!(
            result[..42],
            vec![
                0x00, 0x00, 0x00, 0x6a, 0x64, 0x01, 0x02, 0x0b, // proposal header
                0x13, 0x37, // SPI
                0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x17, // encryption 1
                0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x10, // encryption 2
                0x80, 0x0e, 0x01, 0x00, // encryption 2 payload
                0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14, // encryption 3
                0x80, 0x0e, 0x00, 0x80, // encryption 3 payload
            ]
        );
        assert_eq!(
            result[42..],
            vec![
                0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x09, // PRF
                0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x07, // PRF
                0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0b, // integrity 1
                0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0b, // integrity 2
                0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0b, // integrity 3
                0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f, // KE
                0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x20, // KE
                0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x10, // KE
            ]
        );
    }
}
