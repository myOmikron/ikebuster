use log::debug;
use log::warn;
use zerocopy::FromBytes;

use crate::v1::definitions::GenericPayloadHeader;
use crate::v1::definitions::Header;
use crate::v2::definitions::constants::FLAG_INITIATOR;
use crate::v2::definitions::constants::FLAG_RESPONSE;
use crate::v2::definitions::params::ExchangeType;
use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::CertificateRequest;
use crate::v2::definitions::Deletion;
use crate::v2::definitions::IKEv2;
use crate::v2::definitions::KeyExchange;
use crate::v2::definitions::Notification;
use crate::v2::definitions::Payload;
use crate::v2::definitions::SecurityAssociation;
use crate::v2::parser::ParserError;
use crate::v2::parser::ParserResult;
use crate::v2::IKE_2_VERSION_VALUE;

impl IKEv2 {
    /// Parse a buffer into an [IKEv2] packet, if possible.
    ///
    /// The parser functionality considers the size of payloads noted in
    /// the header of the respective payload to split the buffer and feed
    /// them into sub-parser functions. These parse the structure of the
    /// payload based on "next payload" fields and do not necessarily
    /// rely on the length of the header or body. Therefore, a packet
    /// must have both correct payload header information and inner
    /// structural integrity; otherwise parsing will fail.
    pub fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        let header = Header::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        if header.version != IKE_2_VERSION_VALUE {
            return Err(ParserError::WrongProtocol);
        }
        if header.length.get() as usize != buf.len() {
            warn!("Buffer length does not match header length");
        }

        let mut offset = size_of::<Header>();
        let mut next_payload = PayloadType::try_from(header.next_payload)?;
        let mut payloads = vec![];

        loop {
            let (decoded_payload, current_size) = match next_payload {
                PayloadType::NoNextPayload => {
                    break;
                }
                PayloadType::SecurityAssociation => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    let sa = SecurityAssociation::try_parse(v.as_slice())?;
                    next_payload = n;
                    (Some(Payload::SecurityAssociation(sa)), l)
                }
                PayloadType::KeyExchange => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    let ke = KeyExchange::try_parse(v.as_slice())?;
                    next_payload = n;
                    (Some(Payload::KeyExchange(ke)), l)
                }
                PayloadType::CertificateRequest => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    let cr = CertificateRequest::try_parse(v.as_slice())?;
                    next_payload = n;
                    (Some(Payload::CertificateRequest(cr)), l)
                }
                PayloadType::Nonce => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    next_payload = n;
                    (Some(Payload::Nonce(v)), l)
                }
                PayloadType::Notify => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    let notification = Notification::try_parse(v.as_slice())?;
                    next_payload = n;
                    (Some(Payload::Notify(notification)), l)
                }
                PayloadType::Delete => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    let delete = Deletion::try_parse(v.as_slice())?;
                    next_payload = n;
                    (Some(Payload::Delete(delete)), l)
                }
                PayloadType::VendorID => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    next_payload = n;
                    (Some(Payload::VendorID(v)), l)
                }
                PayloadType::EncryptedAndAuthenticated => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    // The encrypted payload must be the last payload of a packet,
                    // everything after it is ignored
                    if n != PayloadType::NoNextPayload {
                        warn!("Found a payload after Encrypted payload, which is illegal: {n:#?}");
                    }
                    next_payload = PayloadType::NoNextPayload;
                    (Some(Payload::EncryptedAndAuthenticated(v)), l)
                }
                _ => {
                    warn!("Unknown payload type ignored: {next_payload:#?}");
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    debug!("Raw data of ignored payload: {v:#?}");
                    next_payload = n;
                    (None, l)
                }
            };
            offset += current_size;
            if let Some(p) = decoded_payload {
                payloads.push(p);
            }
        }

        Ok(Self {
            initiator_cookie: header.initiator_cookie.get(),
            responder_cookie: header.responder_cookie.get(),
            exchange_type: ExchangeType::try_from(header.exchange_type)?,
            initiator: header.flags & FLAG_INITIATOR == FLAG_INITIATOR,
            response: header.flags & FLAG_RESPONSE == FLAG_RESPONSE,
            message_id: header.message_id.get(),
            payloads,
        })
    }
}

/// Helper to parse all packets that only have a generic header
fn try_parse_generic(buf: &[u8]) -> ParserResult<Vec<u8>> {
    let header = GenericPayloadHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
    let consumed = header.payload_length.get() as usize;
    Ok((
        buf[size_of::<GenericPayloadHeader>()..consumed].to_vec(),
        consumed,
        PayloadType::try_from(header.next_payload)?,
    ))
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::ExchangeType;
    use crate::v2::definitions::IKEv2;
    use crate::v2::definitions::Payload;
    use crate::v2::definitions::SecurityAssociation;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parse_empty_packet() {
        let buff = vec![
            0x00, 0x04, 0xc0, 0x1d, 0xb4, 0x00, 0xb0, 0xc9, // initiator
            0x00, 0x00, 0x00, 0x00, 0x11, 0xf1, 0x5b, 0xa3, // responder
            0x00, // next payload
            0x20, // version
            0x25, // exchange type
            0x20, // flags, 0b00100000
            0x3b, 0x9a, 0xc9, 0xff, // message ID
            0x00, 0x00, 0x00, 0x1c, // length
        ];
        let packet = IKEv2::try_parse(buff.as_slice()).unwrap();
        assert_eq!(packet.initiator_cookie, 1337133713371337);
        assert_eq!(packet.responder_cookie, 301030307);
        assert_eq!(packet.message_id, 0x3b9ac9ff);
        assert_eq!(packet.exchange_type, ExchangeType::Informational);
        assert!(packet.response);
        assert_eq!(packet.payloads.len(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parse_empty_sa_in_packet() {
        let buff = vec![
            0x00, 0x04, 0xc0, 0x1d, 0xb4, 0x00, 0xb0, 0xc9, // initiator
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder
            0x21, // next payload, Security Association
            0x20, // version
            0x22, // exchange type
            0x08, // flags, 0b00001000
            0x1b, 0xad, 0xc9, 0xee, // message ID
            0x00, 0x00, 0x00, 0x1c, // length
            0x00, 0x00, 0x00, 0x04, // Security Association (generic payload) header
        ];
        let packet = IKEv2::try_parse(buff.as_slice()).unwrap();
        assert_eq!(packet.initiator_cookie, 1337133713371337);
        assert_eq!(packet.responder_cookie, 0);
        assert_eq!(packet.message_id, 0x1badc9ee);
        assert_eq!(packet.exchange_type, ExchangeType::IkeSaInit);
        assert!(!packet.response);
        assert!(packet.initiator);
        assert_eq!(packet.payloads.len(), 1);
        assert_eq!(
            packet.payloads[0],
            Payload::SecurityAssociation(SecurityAssociation { proposals: vec![] })
        );
    }
}
