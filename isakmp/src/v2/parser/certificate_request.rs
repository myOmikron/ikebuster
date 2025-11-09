use zerocopy::FromBytes;

use crate::v2::definitions::header::CertificateHeader;
use crate::v2::definitions::params::CertificateEncoding;
use crate::v2::definitions::CertificateRequest;
use crate::v2::parser::ParserError;

impl CertificateRequest {
    /// Parses a buffer into a [CertificateRequest]. The buffer must not contain the
    /// generic payload header. Fails if the buffer is empty.
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        let cr_header =
            CertificateHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        Ok(Self {
            encoding: CertificateEncoding::try_from(cr_header.encoding)?,
            certification_authority: buf[size_of::<CertificateHeader>()..].to_vec(),
        })
    }
}
