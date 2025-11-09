use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;

use crate::v2::definitions::constants::FLAG_INITIATOR;
use crate::v2::definitions::constants::FLAG_RESPONSE;
use crate::v2::definitions::params::NotifyStatusMessage;
use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::Header;
use crate::v2::definitions::IKEv2;
use crate::v2::definitions::NotificationType;
use crate::v2::definitions::Payload;
use crate::v2::generator::GeneratorError;
use crate::v2::generator::ESTIMATED_PAYLOAD_LENGTH;
use crate::v2::IKE_2_VERSION_VALUE;

impl IKEv2 {
    /// Build a network-level packet from an [IKEv2] packet
    pub fn try_build(&self) -> Result<Vec<u8>, GeneratorError> {
        if self.payloads.len() >= 255 {
            return Err(GeneratorError::TooManyPayloads);
        }
        let mut payloads = Vec::with_capacity(ESTIMATED_PAYLOAD_LENGTH * self.payloads.len());

        // If a DoS cookie notification payload is contained in the list of payloads,
        // it MUST be the first payload and thus moves 'next payload' tracking a little around
        let mut cookie_payload_index = None;
        for (i, payload) in self.payloads.iter().enumerate() {
            if let Payload::Notify(n) = payload {
                if let NotificationType::Status(s) = n.variant {
                    if s == NotifyStatusMessage::Cookie {
                        cookie_payload_index = Some(i);
                        let next_payload = if i == 0 {
                            self.payloads.get(1).map(PayloadType::from)
                        } else {
                            self.payloads.first().map(PayloadType::from)
                        };
                        payloads.extend(
                            payload
                                .try_build(next_payload.unwrap_or(PayloadType::NoNextPayload))?,
                        );
                        break;
                    }
                }
            }
        }

        for (i, payload) in self.payloads.iter().enumerate() {
            if cookie_payload_index.is_some_and(|x| x == i) {
                continue;
            }
            let mut next_payload_index = i + 1;
            // If the 'next' payload would be the index of the cookie payload, it needs
            // to be skipped because it was already handled before
            if cookie_payload_index.is_some_and(|x| x == next_payload_index) {
                next_payload_index += 1;
            }
            payloads.extend(
                payload.try_build(match self.payloads.get(next_payload_index) {
                    None => PayloadType::NoNextPayload,
                    Some(next) => PayloadType::from(next),
                })?,
            );
        }

        let packet_length = 28 + payloads.len() as u32;
        let header = Header {
            initiator_cookie: U64::from(self.initiator_cookie),
            responder_cookie: U64::from(self.responder_cookie),
            next_payload: match cookie_payload_index {
                Some(_) => PayloadType::Notify,
                None => match self.payloads.first() {
                    None => PayloadType::NoNextPayload,
                    Some(p) => PayloadType::from(p),
                },
            } as u8,
            version: IKE_2_VERSION_VALUE,
            exchange_type: self.exchange_type as u8,
            flags: (if self.initiator { FLAG_INITIATOR } else { 0 })
                | (if self.response { FLAG_RESPONSE } else { 0 }),
            message_id: U32::from(self.message_id),
            length: U32::from(packet_length),
        };

        let mut packet = Vec::with_capacity(packet_length as usize);
        packet.extend_from_slice(header.as_bytes());
        packet.extend(payloads);
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::ExchangeType;
    use crate::v2::definitions::IKEv2;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn empty() {
        assert_eq!(
            IKEv2 {
                initiator_cookie: 1337133713371337,
                responder_cookie: 301030307,
                exchange_type: ExchangeType::IkeSaInit,
                initiator: true,
                response: false,
                message_id: 999999999,
                payloads: vec![],
            }
            .try_build()
            .unwrap(),
            vec![
                0x00, 0x04, 0xc0, 0x1d, 0xb4, 0x00, 0xb0, 0xc9, // initiator
                0x00, 0x00, 0x00, 0x00, 0x11, 0xf1, 0x5b, 0xa3, // responder
                0x00, // next payload
                0x20, // version
                0x22, // exchange type
                0x08, // flags
                0x3b, 0x9a, 0xc9, 0xff, // message ID
                0x00, 0x00, 0x00, 0x1c // length
            ]
        )
    }
}
