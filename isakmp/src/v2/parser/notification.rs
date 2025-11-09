use log::warn;
use zerocopy::FromBytes;

use crate::v2::definitions::header::NotifyHeader;
use crate::v2::definitions::params::NotifyErrorMessage;
use crate::v2::definitions::params::NotifyStatusMessage;
use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::Notification;
use crate::v2::definitions::NotificationType;
use crate::v2::parser::ParserError;

impl Notification {
    /// Parses a buffer into a [Notification]. The buffer must not contain the
    /// generic payload header. Fails if the buffer is empty.
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        let notify_header =
            NotifyHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        let spi_size = notify_header.spi_size as usize;
        let variant = if notify_header.is_error() {
            NotificationType::Error(NotifyErrorMessage::try_from(
                notify_header.notify_message_type.get(),
            )?)
        } else {
            NotificationType::Status(NotifyStatusMessage::try_from(
                notify_header.notify_message_type.get(),
            )?)
        };
        let protocol = SecurityProtocol::try_from(notify_header.protocol_id)?;

        if spi_size > 0 && protocol == SecurityProtocol::InternetKeyExchange {
            // It is not legal to have both an SPI and use IKE
            return Err(ParserError::ProtocolViolation);
        } else if spi_size == 0 && protocol == SecurityProtocol::InternetKeyExchange {
            // If the SPI is not sent and the protocol is IKE, the responder's implementation
            // is not RFC-conform, but we will accept that anyway
            warn!("Response violates the RFC as it uses IKE protocol for zero-size SPI notification, continuing anyway")
        } else if spi_size == 0 && protocol != SecurityProtocol::Reserved {
            // If the SPI is not sent, the protocol ID must be 0 (=reserved) or IKE (as above)
            return Err(ParserError::ProtocolViolation);
        }

        let spi = if spi_size > 0 {
            Some(buf[size_of::<NotifyHeader>()..size_of::<NotifyHeader>() + spi_size].to_vec())
        } else {
            None
        };

        Ok(Self {
            variant,
            // TODO: max size of buffer? do not use too much data
            data: buf[size_of::<NotifyHeader>() + spi_size..].to_vec(),
            protocol,
            spi,
        })
    }
}
