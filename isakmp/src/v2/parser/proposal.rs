use log::warn;
use zerocopy::FromBytes;

use crate::v2::definitions::constants::FLAG_ATTRIBUTE_FORMAT;
use crate::v2::definitions::constants::FLAG_MORE_FOLLOWING_TRANSFORMS;
use crate::v2::definitions::header::AttributeHeader;
use crate::v2::definitions::header::ProposalHeader;
use crate::v2::definitions::header::TransformHeader;
use crate::v2::definitions::params::AttributeType;
use crate::v2::definitions::params::EncryptionAlgorithm;
use crate::v2::definitions::params::IntegrityAlgorithm;
use crate::v2::definitions::params::KeyExchangeMethod;
use crate::v2::definitions::params::PseudorandomFunction;
use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::params::SequenceNumberType;
use crate::v2::definitions::params::TransformType;
use crate::v2::definitions::Proposal;
use crate::v2::parser::ParserError;

impl Proposal {
    pub(crate) fn try_parse(header: &ProposalHeader, buf: &[u8]) -> Result<Self, ParserError> {
        let header_len = size_of::<ProposalHeader>();
        let spi_len = header.spi_size as usize;
        let body_len = header.proposal_length.get() as usize - header_len - spi_len;
        let spi = Vec::from(&buf[header_len..header_len + spi_len]);
        let protocol = SecurityProtocol::try_from(header.protocol_id)?;

        let body = &buf
            .get(header_len + spi_len..header_len + spi_len + body_len)
            .ok_or(ParserError::BoundaryError)?;
        let mut encryption_algorithms = vec![];
        let mut pseudo_random_functions = vec![];
        let mut integrity_algorithms = vec![];
        let mut key_exchange_methods = vec![];
        let mut extra_key_exchange_methods = vec![];
        let mut sequence_numbers = vec![];

        if body.is_empty() {
            return Ok(Self {
                protocol,
                spi,
                encryption_algorithms,
                pseudo_random_functions,
                integrity_algorithms,
                key_exchange_methods,
                sequence_numbers,
            });
        }

        let mut offset = 0;
        let mut transform_header =
            TransformHeader::ref_from_prefix(body).ok_or(ParserError::BufferTooSmall)?;
        let mut t_type = TransformType::try_from(transform_header.transform_type)?;
        let mut t_size = usize::from(transform_header.transform_length);

        macro_rules! match_transform {
            () => {
                match t_type {
                    TransformType::EncryptionAlgorithm => {
                        let e = EncryptionAlgorithm::try_from(u16::from(
                            transform_header.transform_id,
                        ))?;
                        let attribute_data =
                            &body[offset + size_of::<TransformHeader>()..offset + t_size];
                        let attr = if attribute_data.is_empty() {
                            None
                        } else {
                            let attr_header = AttributeHeader::ref_from_prefix(attribute_data)
                                .ok_or(ParserError::BufferTooSmall)?;
                            if attr_header.is_fixed_length() {
                                let attr_type = AttributeType::try_from(
                                    u16::from(attr_header.attribute_type) - FLAG_ATTRIBUTE_FORMAT,
                                )?;
                                match attr_type {
                                    AttributeType::KeyLength => {
                                        Some(u16::from(attr_header.attribute_value))
                                    }
                                    _ => {
                                        warn!("Ignored unknown attribute type {attr_type:?}");
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        };
                        encryption_algorithms.push((e, attr));
                    }
                    TransformType::PseudoRandomFunction => {
                        pseudo_random_functions.push(PseudorandomFunction::try_from(u16::from(
                            transform_header.transform_id,
                        ))?);
                    }
                    TransformType::IntegrityAlgorithm => {
                        integrity_algorithms.push(IntegrityAlgorithm::try_from(u16::from(
                            transform_header.transform_id,
                        ))?);
                    }
                    TransformType::KeyExchangeMethod => {
                        key_exchange_methods.push(KeyExchangeMethod::try_from(u16::from(
                            transform_header.transform_id,
                        ))?);
                    }
                    TransformType::AdditionalKeyExchange1
                    | TransformType::AdditionalKeyExchange2
                    | TransformType::AdditionalKeyExchange3
                    | TransformType::AdditionalKeyExchange4
                    | TransformType::AdditionalKeyExchange5
                    | TransformType::AdditionalKeyExchange6
                    | TransformType::AdditionalKeyExchange7 => {
                        extra_key_exchange_methods.push(KeyExchangeMethod::try_from(u16::from(
                            transform_header.transform_id,
                        ))?);
                    }
                    TransformType::SequenceNumber => {
                        sequence_numbers.push(SequenceNumberType::try_from(u16::from(
                            transform_header.transform_id,
                        ))?);
                    }
                    _ => {
                        unimplemented!("transform type {:#?} not implemented", t_type);
                    }
                };
            };
        }

        // TODO: 3.3.4.  Mandatory Transform IDs

        match_transform!();
        offset += t_size;

        let mut next_transform = transform_header.last_substruct == FLAG_MORE_FOLLOWING_TRANSFORMS;
        while next_transform {
            transform_header = TransformHeader::ref_from_prefix(&body[offset..])
                .ok_or(ParserError::BufferTooSmall)?;
            t_type = TransformType::try_from(transform_header.transform_type)?;
            t_size = usize::from(transform_header.transform_length);
            match_transform!();
            offset += t_size;
            next_transform = transform_header.last_substruct == FLAG_MORE_FOLLOWING_TRANSFORMS;
        }

        match protocol {
            // See section 3.3.3 of RFC 7296
            SecurityProtocol::InternetKeyExchange => {
                if encryption_algorithms.is_empty()
                    || pseudo_random_functions.is_empty()
                    || key_exchange_methods.is_empty()
                {
                    return Err(ParserError::MissingMandatoryTransform);
                }
            }
            SecurityProtocol::AuthenticationHeader => {
                if encryption_algorithms.is_empty() || sequence_numbers.is_empty() {
                    return Err(ParserError::MissingMandatoryTransform);
                }
            }
            SecurityProtocol::EncapsulatingSecurityPayload => {
                if integrity_algorithms.is_empty() || sequence_numbers.is_empty() {
                    return Err(ParserError::MissingMandatoryTransform);
                }
            }
            _ => {}
        };

        // TODO: extra_key_exchange_methods

        Ok(Self {
            protocol,
            spi,
            encryption_algorithms,
            pseudo_random_functions,
            integrity_algorithms,
            key_exchange_methods,
            sequence_numbers,
        })
    }
}
