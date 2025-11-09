use zerocopy::FromBytes;

use crate::v2::definitions::header::DeleteHeader;
use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::Deletion;
use crate::v2::parser::ParserError;

impl Deletion {
    /// Parses a buffer into a [Deletion]. The buffer must not contain the
    /// generic payload header. Fails if the buffer is empty.
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        let header = DeleteHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        let proto = SecurityProtocol::try_from(header.protocol_id)?;
        Ok(match proto {
            SecurityProtocol::InternetKeyExchange => Self::InternetKeyExchange,
            SecurityProtocol::AuthenticationHeader => todo!(),
            SecurityProtocol::EncapsulatingSecurityPayload => todo!(),
            _ => return Err(ParserError::ProtocolViolation),
        })
    }
}
