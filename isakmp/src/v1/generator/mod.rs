//! Message generation

use serde::Deserialize;
use serde::Serialize;
use zerocopy::network_endian::*;
use zerocopy::AsBytes;
use zerocopy::U16;
use zerocopy::U32;

use crate::v1::definitions::AuthenticationMethod;
use crate::v1::definitions::DataAttributeShort;
use crate::v1::definitions::EncryptionAlgorithm;
use crate::v1::definitions::ExchangeType;
use crate::v1::definitions::GenericPayloadHeader;
use crate::v1::definitions::GroupDescription;
use crate::v1::definitions::HashAlgorithm;
use crate::v1::definitions::Header;
use crate::v1::definitions::LifeType;
use crate::v1::definitions::PayloadType;
use crate::v1::definitions::StaticProposalPayload;
use crate::v1::definitions::StaticSecurityAssociationPayload;
use crate::v1::definitions::StaticTransformPayload;
use crate::v1::definitions::VariableProposalPayload;
use crate::v1::definitions::VariableSecurityAssociationPayload;
use crate::v1::definitions::VariableTransformPayload;

/// Representation of a Transform
///
/// A transform consists of multiple attributes that determine the encryption and authentication
/// that should be used
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Transform {
    /// Encryption algorithm
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Hash algorithm
    pub hash_algorithm: HashAlgorithm,
    /// Type of authentication to use
    pub authentication_method: AuthenticationMethod,
    /// The group description to use
    pub group_description: GroupDescription,
    /// Optional key size
    pub key_size: Option<u16>,
}

/// Helper struct to build a crate message
pub struct MessageBuilder {
    transforms: Vec<Transform>,
}

impl MessageBuilder {
    /// Create a new message builder
    pub fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    /// Add transform to the message builder
    pub fn add_transform(mut self, transform: Transform) -> Self {
        self.transforms.push(transform);
        self
    }

    /// Create a test message
    ///
    /// # Returns
    /// - the isakmp message
    /// - the initiator cookie
    pub fn build(self) -> (Vec<u8>, u64) {
        let mut msg = vec![];

        let mut overall_msg_length = size_of::<Header>();

        let mut header = Header {
            initiator_cookie: U64::new(rand::random::<u64>()),
            responder_cookie: U64::new(0),
            next_payload: PayloadType::SecurityAssociation as u8,
            version: 0b00010000,
            exchange_type: ExchangeType::IdentityProtection as u8,
            flags: 0,
            message_id: Default::default(),
            length: Default::default(),
        };
        let mut sa = StaticSecurityAssociationPayload {
            generic_payload_header: GenericPayloadHeader {
                next_payload: PayloadType::None as u8,
                reserved: 0,
                payload_length: Default::default(),
            },
            doi: U32::new(1),
        };

        let sa_var = VariableSecurityAssociationPayload {
            situation: vec![0x00, 0x00, 0x00, 0x01],
        };

        let mut proposal = StaticProposalPayload {
            generic_payload_header: GenericPayloadHeader {
                next_payload: PayloadType::None as u8,
                reserved: 0,
                payload_length: Default::default(),
            },
            proposal_no: 1,
            protocol_id: 1,
            spi_size: 0,
            no_of_transforms: self.transforms.len() as u8,
        };

        let proposal_var = VariableProposalPayload { spi: vec![] };

        let mut transforms_raw: Vec<u8> = vec![];
        for (i, transform) in self.transforms.iter().enumerate() {
            let mut transform_payload = StaticTransformPayload {
                generic_payload_header: GenericPayloadHeader {
                    next_payload: if i < self.transforms.len() - 1 {
                        PayloadType::Transform as u8
                    } else {
                        PayloadType::None as u8
                    },
                    reserved: 0,
                    payload_length: Default::default(),
                },
                transform_no: i as u8,
                transform_id: 1,
                reserved: U16::new(0),
            };

            let mut sa_attributes = vec![];
            sa_attributes.extend_from_slice(
                DataAttributeShort {
                    attribute_type: U16::new(0b1000_0000_0000_0001),
                    attribute_value: U16::new(transform.encryption_algorithm as u16),
                }
                .as_bytes(),
            );
            sa_attributes.extend_from_slice(
                DataAttributeShort {
                    attribute_type: U16::new(0b1000_0000_0000_0010),
                    attribute_value: U16::new(transform.hash_algorithm as u16),
                }
                .as_bytes(),
            );
            sa_attributes.extend_from_slice(
                DataAttributeShort {
                    attribute_type: U16::new(0b1000_0000_0000_0011),
                    attribute_value: U16::new(transform.authentication_method as u16),
                }
                .as_bytes(),
            );
            sa_attributes.extend_from_slice(
                DataAttributeShort {
                    attribute_type: U16::new(0b1000_0000_0000_0100),
                    attribute_value: U16::new(transform.group_description as u16),
                }
                .as_bytes(),
            );
            sa_attributes.extend_from_slice(
                DataAttributeShort {
                    attribute_type: U16::new(0b1000_0000_0000_1011),
                    attribute_value: U16::new(LifeType::Seconds as u16),
                }
                .as_bytes(),
            );
            sa_attributes.extend_from_slice(
                DataAttributeShort {
                    attribute_type: U16::new(0b1000_0000_0000_1100),
                    attribute_value: U16::new(7080),
                }
                .as_bytes(),
            );
            if let Some(key_size) = transform.key_size {
                sa_attributes.extend_from_slice(
                    DataAttributeShort {
                        attribute_type: U16::new(0b1000_0000_0000_1110),
                        attribute_value: U16::new(key_size),
                    }
                    .as_bytes(),
                );
            }
            let transform_var = VariableTransformPayload { sa_attributes };

            transform_payload.generic_payload_header.payload_length = U16::new(
                (size_of::<StaticTransformPayload>() + transform_var.sa_attributes.len()) as u16,
            );

            transforms_raw.extend_from_slice(transform_payload.as_bytes());
            transforms_raw.extend_from_slice(&transform_var.sa_attributes);
        }

        // Set sa length
        let mut sa_size = 0;
        let mut proposal_size = 0;
        let static_sa_size = size_of::<StaticSecurityAssociationPayload>();
        let static_proposal_size = size_of::<StaticProposalPayload>();

        sa_size += static_sa_size;
        sa_size += sa_var.situation.len();

        proposal_size += static_proposal_size;
        proposal_size += proposal_var.spi.len();

        // Add transform size to proposal size
        proposal_size += transforms_raw.len();

        // Add proposal size to sa size
        sa_size += proposal_size;

        // Add sa size to overall msg length
        overall_msg_length += sa_size;
        let remaining = overall_msg_length % 4;
        if remaining != 0 {
            overall_msg_length += remaining;
        }

        // Set SA payload size to message and payload header
        proposal.generic_payload_header.payload_length = U16::new(proposal_size as u16);
        sa.generic_payload_header.payload_length = U16::new(sa_size as u16);

        // Set overall message length
        header.length = U32::new(overall_msg_length as u32);

        // Add data to message
        msg.extend_from_slice(header.as_bytes());
        msg.extend_from_slice(sa.as_bytes());
        msg.extend_from_slice(&sa_var.situation);
        msg.extend_from_slice(proposal.as_bytes());
        msg.extend_from_slice(&proposal_var.spi);
        msg.extend_from_slice(&transforms_raw);

        // padding with 0
        msg.resize(overall_msg_length, 0);

        (msg, header.initiator_cookie.get())
    }
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}
