//! Implementation of the new IKEv2 scanner, and related utilities

use std::net::IpAddr;
use std::time::Duration;
use std::time::Instant;

use isakmp::v2::definitions::IKEv2;
use isakmp::v2::definitions::Proposal;
use itertools::Itertools;
use serde::Serialize;

use crate::v2::finding::Finding;
use crate::v2::finding::FindingResult;

pub mod finding;
pub mod gen_proposals;
pub(crate) mod probing;
pub(crate) mod receiver;
pub mod scanner;
pub(crate) mod sender;
pub mod serialization;

/// Timeout for receiving any data from the remote side
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout when a host that was alive before stopped sending over 10 minutes ago
pub const HOST_DEAD_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes

/// Max size of a single UDP packet that we can support
pub const MAX_DATAGRAM_SIZE: usize = 65_507;

/// Options to "configure" the scanner v2
#[derive(Debug, Clone)]
pub struct ScanOptionsV2 {
    /// Target IP
    pub ip: IpAddr,
    /// Target port
    pub port: u16,
    /// Local listen port
    pub listen_port: u16,
    /// Interval between each sent message
    pub interval: u64,
    /// Number of transforms to send in a single proposal
    pub transform_no: usize,
    /// Optional save file to store scanner state in JSON
    pub json_state: Option<String>,
    /// Enable probing with a single packet before the actual scan
    pub enable_probing: bool,
}

/// Statistics tracked while executing an IKEv2 scan on a target
#[derive(Clone, Debug, Default, Serialize)]
pub struct Statistics {
    /// Number of non-critical errors that occurred during the scan, see logs for details
    pub errors: u64,
    /// Number of sent bytes during the scan (excludes pre-scan exchanges)
    pub sent_bytes: u64,
    /// Number of sent packets during the scan (excludes pre-scan exchanges)
    pub sent_packets: u64,
    /// Number of received bytes during the scan (excludes pre-scan exchanges)
    pub recv_bytes: u64,
    /// Number of received packets during the scan (excludes pre-scan exchanges)
    pub recv_packets: u64,
    /// Total number of proposals as combinations of transformations that were checked in the scan
    pub total_checks: usize,
}

/// Tracker of results for a running scan. After the scan is completed, this can be
/// used to identify which proposals were accepted or rejected by the target.
/// `invalid_syntax` should be treated as rejected. The list of vendor IDs may
/// be used for fingerprinting, but it is not a very reliable indicator.
/// See also the [Results::to_findings] method to create a list of [Finding]s.
#[derive(Debug, Default)]
pub struct Results {
    /// List of proposals accepted by the target
    pub accepted: Vec<Proposal>,
    /// List of proposals rejected by the target
    pub rejected: Vec<Proposal>,
    /// List of proposals that were not understood by the target;
    /// should be treated as rejected but may allow fingerprinting
    pub invalid_syntax: Vec<Proposal>,
    /// List of Vendor IDs that were sent by the target
    pub vendor_ids: Vec<Vec<u8>>,
}

/// Connection tracker for a running scan
#[derive(Debug, Default)]
pub(crate) struct Open {
    /// List of sent [IKEv2] packets and the timestamp when they were sent; the ordering
    /// is not important and may be arbitrary due to retry and timeout logic.
    sent: Vec<(IKEv2, Instant)>,
    /// List of packets that need to be retried to send; they may be modified (e.g. for Cookie
    /// payloads), and they also include other payloads (e.g. the Delete packet).
    retry: Vec<IKEv2>,
    /// List of vectors of [Proposal]s that should be sent again in a new packet soon to
    /// verify them; the ordering is not important. Note that [Proposal]s in this list may
    /// have been sent to the responder already in a larger bulk but needed to be split up again.
    verify: Vec<Vec<Proposal>>,
}

impl Results {
    /// Create a list of findings from the results
    pub fn to_findings(&self) -> Vec<Finding> {
        let mut findings = vec![];

        for i in self.accepted.iter() {
            if let Some(f) = Finding::from_proposal(i, FindingResult::Accepted) {
                findings.push(f);
            }
        }
        for i in self.rejected.iter() {
            if let Some(f) = Finding::from_proposal(i, FindingResult::Rejected) {
                findings.push(f);
            }
        }
        for i in self.invalid_syntax.iter() {
            if let Some(f) = Finding::from_proposal(i, FindingResult::InvalidSyntax) {
                findings.push(f);
            }
        }

        findings.into_iter().unique().collect_vec()
    }
}
