use zerocopy::FromBytes;

use crate::v2::definitions::constants::FLAG_MORE_FOLLOWING_PROPOSALS;
use crate::v2::definitions::header::ProposalHeader;
use crate::v2::definitions::Proposal;
use crate::v2::definitions::SecurityAssociation;
use crate::v2::parser::ParserError;

impl SecurityAssociation {
    /// Parses a buffer into a [SecurityAssociation]. The buffer must not contain the
    /// generic payload header, it should only contain the list of proposals. The buffer
    /// length is not checked, but will yield an error if too small. Larger buffers
    /// than necessary are ignored. If the buffer is not empty, it must contain at least
    /// one proposal. Otherwise, an empty buffer produces an SA that has no proposals.
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        if buf.is_empty() {
            return Ok(SecurityAssociation { proposals: vec![] });
        }
        let mut offset = 0;
        let mut proposals = vec![];
        let mut proposal_header =
            ProposalHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        let proposal = Proposal::try_parse(proposal_header, &buf[offset..])?;
        proposals.push(proposal);
        offset += proposal_header.proposal_length.get() as usize;

        let mut more_proposals = proposal_header.last_substruct == FLAG_MORE_FOLLOWING_PROPOSALS;
        while more_proposals {
            let next_proposal_header = ProposalHeader::ref_from_prefix(&buf[offset..])
                .ok_or(ParserError::BufferTooSmall)?;
            if next_proposal_header.proposal_num != 1 + proposal_header.proposal_num {
                return Err(ParserError::InvalidProposalNumbering);
            }
            proposal_header = next_proposal_header;
            more_proposals = proposal_header.last_substruct == FLAG_MORE_FOLLOWING_PROPOSALS;
            let proposal = Proposal::try_parse(proposal_header, &buf[offset..])?;
            proposals.push(proposal);
            offset += proposal_header.proposal_length.get() as usize;
        }
        Ok(Self { proposals })
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::PseudorandomFunction;
    use crate::v2::definitions::SecurityAssociation;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parse_sa_with_extra_attrs() {
        let buf = vec![
            //0x22, 0x00, 0x00, 0x50, // Security Association header
            0x00, 0x00, 0x00, 0x60, 0x01, 0x01, 0x00, 0x08, // Proposal header
            0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x13, // Transform 1, encryption
            0x80, 0x0e, 0x7a, 0x69, // Transform 1, encryption, attributes
            0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, // Transform 2, PRF 1
            0x03, 0x00, 0x00, 0x0c, 0x02, 0x00, 0x00, 0x06, // Transform 3, PRF 2
            0x00, 0x00, 0x00, 0x00, // random data for transform 3 should be ignored
            0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x07, // Transform 4, PRF 3
            0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, // Transform 5, integrity 1
            0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0e, // Transform 6, integrity 2
            0x03, 0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x20, // Transform 7, KE 1
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // random data for transform 7
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // random data for transform 7
            0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f, // Transform 8, KE 2
        ];

        let sa = SecurityAssociation::try_parse(&buf).unwrap();
        assert_eq!(sa.proposals.len(), 1);
        let p = &sa.proposals[0];
        assert_eq!(p.spi.len(), 0);
        assert_eq!(p.sequence_numbers.len(), 0);
        assert_eq!(p.key_exchange_methods.len(), 2);
        assert_eq!(
            p.pseudo_random_functions,
            vec![
                PseudorandomFunction::HMAC_SHA2_256,
                PseudorandomFunction::HMAC_SHA2_384,
                PseudorandomFunction::HMAC_SHA2_512
            ]
        );
    }
}
