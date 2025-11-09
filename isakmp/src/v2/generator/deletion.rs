use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::AsBytes;

use crate::v1::definitions::GenericPayloadHeader;
use crate::v2::definitions::header::DeleteHeader;
use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::Deletion;

impl Deletion {
    pub(crate) fn build(&self, next_payload: PayloadType) -> Vec<u8> {
        let (delete_header, spi_data) = match self {
            Deletion::InternetKeyExchange => (
                DeleteHeader {
                    protocol_id: SecurityProtocol::InternetKeyExchange as u8,
                    spi_size: 0,
                    number_of_spi: Default::default(),
                },
                vec![],
            ),
            Deletion::AuthenticationHeader(spi) => (
                DeleteHeader {
                    protocol_id: SecurityProtocol::AuthenticationHeader as u8,
                    spi_size: 4,
                    number_of_spi: U16::from(spi.len() as u16),
                },
                spi.iter().map(|v| U32::from(*v)).collect(),
            ),
            Deletion::EncapsulatingSecurityPayload(spi) => (
                DeleteHeader {
                    protocol_id: SecurityProtocol::EncapsulatingSecurityPayload as u8,
                    spi_size: 4,
                    number_of_spi: U16::from(spi.len() as u16),
                },
                spi.iter().map(|v| U32::from(*v)).collect(),
            ),
        };

        let full_len =
            size_of::<GenericPayloadHeader>() + size_of::<DeleteHeader>() + spi_data.len();
        let generic_header = GenericPayloadHeader {
            next_payload: next_payload as u8,
            reserved: 0,
            payload_length: U16::from(full_len as u16),
        };
        let mut packet = Vec::with_capacity(full_len);
        packet.extend_from_slice(generic_header.as_bytes());
        packet.extend_from_slice(delete_header.as_bytes());
        for spi in spi_data {
            packet.extend_from_slice(spi.as_bytes());
        }
        packet
    }
}
