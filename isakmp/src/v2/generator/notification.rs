use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

use crate::v2::definitions::header::NotifyHeader;
use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::GenericPayloadHeader;
use crate::v2::definitions::Notification;
use crate::v2::definitions::NotificationType;
use crate::v2::generator::GeneratorError;

impl Notification {
    pub(crate) fn try_build(&self, next_payload: PayloadType) -> Result<Vec<u8>, GeneratorError> {
        let notification_type = match self.variant {
            NotificationType::Error(e) => e as u16,
            NotificationType::Status(s) => s as u16,
        };

        let spi_len = if let Some(spi_data) = self.spi.clone() {
            u8::try_from(spi_data.len()).map_err(|_| GeneratorError::MaxSpiLengthExceeded)?
        } else {
            0
        };
        let generic_header = GenericPayloadHeader {
            next_payload: next_payload as u8,
            reserved: 0,
            payload_length: U16::from(
                size_of::<GenericPayloadHeader>() as u16
                    + size_of::<NotifyHeader>() as u16
                    + spi_len as u16
                    + self.data.len() as u16,
            ),
        };
        let notify_header = NotifyHeader {
            protocol_id: if self.spi.is_none() {
                0
            } else {
                self.protocol as u8
            },
            spi_size: spi_len,
            notify_message_type: U16::from(notification_type),
        };

        let mut packet = Vec::with_capacity(
            size_of::<GenericPayloadHeader>()
                + size_of::<NotifyHeader>()
                + spi_len as usize
                + self.data.len(),
        );
        packet.extend_from_slice(generic_header.as_bytes());
        packet.extend_from_slice(notify_header.as_bytes());
        if let Some(data) = self.spi.clone() {
            packet.extend_from_slice(data.as_slice());
        }
        packet.extend_from_slice(self.data.as_slice());
        Ok(packet)
    }
}
