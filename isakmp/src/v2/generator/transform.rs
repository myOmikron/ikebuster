use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

use crate::v2::definitions::header::TransformHeader;
use crate::v2::definitions::params::TransformType;
use crate::v2::definitions::Attribute;
use crate::v2::definitions::Transform;

impl Transform {
    /// Convert a [Transform] into a network-level vector of bytes
    ///
    /// The argument `last` defines if any transform is following this transform (false)
    /// or if this transform is the last transform in the proposal payload (true).
    pub fn build(&self, last: bool) -> Vec<u8> {
        let (t_type, t_id, attributes) = match self {
            Transform::Encryption(algorithm, key_length) => (
                TransformType::EncryptionAlgorithm,
                U16::new(*algorithm as u16),
                match key_length {
                    None => vec![],
                    Some(v) => Attribute::KeyLength(*v).build(),
                },
            ),
            Transform::PseudoRandomFunction(function) => (
                TransformType::PseudoRandomFunction,
                U16::new(*function as u16),
                vec![],
            ),
            Transform::Integrity(integrity) => (
                TransformType::IntegrityAlgorithm,
                U16::new(*integrity as u16),
                vec![],
            ),
            Transform::KeyExchange(exchange_method) => (
                TransformType::KeyExchangeMethod,
                U16::new(*exchange_method as u16),
                vec![],
            ),
            Transform::SequenceNumber(sequence_number) => (
                TransformType::SequenceNumber,
                U16::new(*sequence_number as u16),
                vec![],
            ),
        };

        let packet_length = size_of::<TransformHeader>() as u16 + attributes.len() as u16;
        let header = TransformHeader {
            last_substruct: if last { 0 } else { 3 },
            reserved: 0,
            transform_length: U16::from(packet_length),
            transform_type: t_type as u8,
            reserved2: 0,
            transform_id: t_id,
        };

        let mut packet = Vec::with_capacity(packet_length as usize);
        packet.extend_from_slice(header.as_bytes());
        packet.extend(attributes);
        packet
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::EncryptionAlgorithm;
    use crate::v2::definitions::params::KeyExchangeMethod;
    use crate::v2::definitions::Transform;

    #[test]
    fn key_exchange() {
        assert_eq!(
            Transform::KeyExchange(KeyExchangeMethod::Curve_25519).build(true),
            vec![0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f]
        );
        assert_eq!(
            Transform::KeyExchange(KeyExchangeMethod::Curve_25519).build(false),
            vec![0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f]
        );
    }

    #[test]
    fn encryption() {
        assert_eq!(
            Transform::Encryption(EncryptionAlgorithm::CAMELLIA_CTR, Some(192)).build(true),
            vec![0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x18, 0x80, 0x0e, 0x00, 0xc0]
        );
        assert_eq!(
            Transform::Encryption(EncryptionAlgorithm::AES_CBC, Some(128)).build(false),
            vec![0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, 0x80, 0x0e, 0x00, 0x80]
        )
    }
}
