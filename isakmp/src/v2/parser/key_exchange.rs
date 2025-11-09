use zerocopy::FromBytes;

use crate::v2::definitions::header::KeyExchangeHeader;
use crate::v2::definitions::params::KeyExchangeMethod;
use crate::v2::definitions::KeyExchange;
use crate::v2::parser::ParserError;

impl KeyExchange {
    /// Parses a buffer into a [KeyExchange]. The buffer must not contain the
    /// generic payload header. Fails if the buffer is empty.
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        let header = KeyExchangeHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        Ok(Self {
            dh_group: KeyExchangeMethod::try_from(header.dh_group_num.get())?,
            data: buf[size_of::<KeyExchangeHeader>()..].to_vec(),
        })
    }
}
