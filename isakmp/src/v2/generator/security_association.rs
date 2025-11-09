use zerocopy::AsBytes;

use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::GenericPayloadHeader;
use crate::v2::definitions::SecurityAssociation;
use crate::v2::generator::GeneratorError;
use crate::v2::generator::ESTIMATED_PROPOSAL_LENGTH;

impl SecurityAssociation {
    /// Build a network-level packet from a [SecurityAssociation]#
    ///
    /// This might fail if the packet would not conform to the standard, for
    /// example if a proposal doesn't provide all details required to build it,
    /// or if too many of a certain type of structure is required
    pub fn try_build(&self, next_payload: PayloadType) -> Result<Vec<u8>, GeneratorError> {
        if self.proposals.len() >= 255 {
            return Err(GeneratorError::TooManyProposals);
        }
        let mut proposals = Vec::with_capacity(ESTIMATED_PROPOSAL_LENGTH * self.proposals.len());
        for (i, proposal) in self.proposals.iter().enumerate() {
            proposals.extend(proposal.try_build(i as u8 + 1, i == self.proposals.len() - 1)?);
        }

        let packet_length = 4 + proposals.len() as u16;
        let header = GenericPayloadHeader {
            next_payload: next_payload as u8,
            reserved: 0,
            payload_length: packet_length.into(),
        };
        let mut packet = Vec::with_capacity(packet_length.into());
        packet.extend_from_slice(header.as_bytes());
        packet.extend(proposals);
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::EncryptionAlgorithm;
    use crate::v2::definitions::params::IntegrityAlgorithm;
    use crate::v2::definitions::params::KeyExchangeMethod;
    use crate::v2::definitions::params::PayloadType;
    use crate::v2::definitions::params::PseudorandomFunction;
    use crate::v2::definitions::params::SecurityProtocol;
    use crate::v2::definitions::Proposal;
    use crate::v2::definitions::SecurityAssociation;
    use crate::v2::definitions::Transform;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn empty() {
        assert_eq!(
            SecurityAssociation { proposals: vec![] }
                .try_build(PayloadType::NoNextPayload)
                .unwrap(),
            vec![0x00, 0x00, 0x00, 0x04]
        )
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn simple_full() {
        let mut p = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, Some(vec![0x42]));
        p.add(vec![
            Transform::Encryption(EncryptionAlgorithm::AES_GCM_16, Some(256)),
            Transform::Integrity(IntegrityAlgorithm::HMAC_SHA2_256_128),
            Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_256),
            Transform::KeyExchange(KeyExchangeMethod::Curve_448),
        ]);
        assert_eq!(
            SecurityAssociation { proposals: vec![p] }
                .try_build(PayloadType::KeyExchange)
                .unwrap(),
            vec![
                0x22, 0x00, 0x00, 0x31, // Security Association header
                0x00, 0x00, 0x00, 0x2d, 0x01, 0x01, 0x01, 0x04, // Proposal header
                0x42, // SPI
                0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14, // Transform 1
                0x80, 0x0e, 0x01, 0x00, // Transform 1 attributes
                0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, // Transform 2
                0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, // Transform 3
                0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x20 // Transform 4
            ]
        )
    }
}
