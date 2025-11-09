use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

use crate::v1::definitions::GenericPayloadHeader;
use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::Payload;
use crate::v2::generator::GeneratorError;

impl Payload {
    pub(crate) fn try_build(&self, next_payload: PayloadType) -> Result<Vec<u8>, GeneratorError> {
        if let Payload::Nonce(v) = self {
            if v.len() < 16 || v.len() > 256 {
                return Err(GeneratorError::InvalidNonceLength);
            }
        }
        match self {
            Payload::SecurityAssociation(v) => v.try_build(next_payload),
            Payload::KeyExchange(v) => Ok(v.build(next_payload)),
            Payload::CertificateRequest(_v) => {
                todo!()
            }
            Payload::Notify(v) => v.try_build(next_payload),
            Payload::Delete(v) => Ok(v.build(next_payload)),
            Payload::Nonce(v) | Payload::VendorID(v) | Payload::EncryptedAndAuthenticated(v) => {
                Ok(self.build_generic(next_payload, v))
            }
        }
    }

    #[inline]
    fn build_generic(&self, next_payload: PayloadType, data: &[u8]) -> Vec<u8> {
        let header = GenericPayloadHeader {
            next_payload: next_payload as u8,
            reserved: 0,
            payload_length: U16::from(data.len() as u16 + 4),
        };
        let mut packet = Vec::with_capacity(data.len() + 4);
        packet.extend_from_slice(header.as_bytes());
        packet.extend(data);
        packet
    }
}
