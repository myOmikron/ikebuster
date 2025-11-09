use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

use crate::v1::definitions::GenericPayloadHeader;
use crate::v2::definitions::header::KeyExchangeHeader;
use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::KeyExchange;

impl KeyExchange {
    pub(crate) fn build(&self, next_payload: PayloadType) -> Vec<u8> {
        let generic_header = GenericPayloadHeader {
            next_payload: next_payload as u8,
            reserved: 0,
            payload_length: U16::from(8 + self.data.len() as u16),
        };
        let key_exchange_header = KeyExchangeHeader {
            dh_group_num: U16::from(self.dh_group as u16),
            reserved: U16::from(0),
        };
        let mut packet = Vec::with_capacity(self.data.len() + 8);
        packet.extend(generic_header.as_bytes());
        packet.extend_from_slice(key_exchange_header.as_bytes());
        packet.extend(self.data.clone());
        packet
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::KeyExchangeMethod;
    use crate::v2::definitions::params::PayloadType;
    use crate::v2::definitions::KeyExchange;

    #[test]
    fn simple() {
        assert_eq!(
            KeyExchange {
                dh_group: KeyExchangeMethod::MODP_6144,
                data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            }
            .build(PayloadType::Notify),
            vec![
                0x29, 0x00, 0x00, 0x10, // Generic payload header
                0x00, 0x11, // DH group
                0x00, 0x00, // reserved
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 // key exchange data
            ]
        )
    }
}
