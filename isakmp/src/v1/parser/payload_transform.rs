//! Parser of the transform payload

use zerocopy::FromBytes;

use crate::v1::definitions::PayloadType;
use crate::v1::parser::data_attribute::parse_data_attribute;
use crate::v1::parser::definitions::TransformPayload;
use crate::v1::parser::errors::IsakmpParseError;

/// Parse a transform payload
pub fn parse_transform(buf: &[u8]) -> Result<TransformPayload, IsakmpParseError> {
    let static_part = crate::v1::definitions::StaticTransformPayload::ref_from_prefix(buf)
        .ok_or(IsakmpParseError::BufferTooSmall)?;

    if static_part.generic_payload_header.reserved != 0 || static_part.reserved.get() != 0 {
        return Err(IsakmpParseError::UnexpectedPayload);
    }

    let mut transform = TransformPayload {
        next_payload: PayloadType::try_from(static_part.generic_payload_header.next_payload)?,
        length: static_part.generic_payload_header.payload_length.get(),
        transform_no: static_part.transform_no,
        transform_id: static_part.transform_id,
        sa_attributes: vec![],
    };

    let static_size = size_of::<crate::v1::definitions::StaticTransformPayload>();

    let remaining = &buf[static_size..transform.length as usize];

    let mut start = 0;

    while start < remaining.len() {
        let (attribute, len) = parse_data_attribute(&remaining[start..])?;
        transform.sa_attributes.push(attribute);
        start += len;
    }

    Ok(transform)
}
