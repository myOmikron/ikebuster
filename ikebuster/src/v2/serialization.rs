//! Serialization formats for IKEv2

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;

use isakmp::v2::definitions::Proposal;
use serde::Serialize;

use crate::v2::finding::Finding;
use crate::v2::Statistics;

/// Scan state serialization for IKEv2 scans when written to JSON files
#[derive(Debug, Serialize)]
pub struct ScannerSerialization {
    /// The target IP address (maybe IPv4 or IPv6) that was scanned
    pub target: IpAddr,
    /// The target port that was scanned
    pub target_port: u16,
    /// Length of the retry buffer
    pub retry_len: usize,
    /// Statistics tracked during the scan (likely not completed yet)
    pub statistics: Statistics,
    /// UNIX timestamp when the scan was started
    pub scan_started: u64,
    /// Elapsed scan time in milliseconds
    pub elapsed_ms: u64,
    /// UNIX timestamp when this file was created
    pub save_created: u64,
    /// Map of open (in-flight) proposals, see [Open](crate::v2::Open)
    pub open: HashMap<u64, Vec<Proposal>>,
    /// List of proposals accepted by the target
    pub accepted: Vec<Proposal>,
    /// Number of rejected proposals of the receiver side
    pub rejected: Vec<Proposal>,
    /// Number of rejected proposals that the target did not understand
    pub invalid_syntax: Vec<Proposal>,
    /// List of remaining proposals not yet sent to the target
    pub todo: VecDeque<Proposal>,
    /// List of unique vendor IDs sent by the target
    pub vendor_ids: Vec<Vec<u8>>,
}

/// Scan output format for IKEv2 scans when written to JSON files
#[derive(Clone, Debug, Serialize)]
pub struct ScanResultOutputFormat {
    /// The target IP address (maybe IPv4 or IPv6) that was scanned
    pub target: IpAddr,
    /// The target port that was scanned
    pub target_port: u16,
    /// Indicator whether the scan was completed
    pub completed: bool,
    /// Statistics tracked during the scan
    pub statistics: Statistics,
    /// Number of rejected proposals of the receiver side;
    /// look into [Statistics] for the total number of attempted proposals
    pub rejected: usize,
    /// Number of rejected proposals that the target did not understand
    pub invalid_syntax: usize,
    /// List of individually accepted proposals as list of [Finding]s
    pub accepted: Vec<Finding>,
    /// List of unique vendor IDs sent by the target
    pub vendor_ids: Vec<Vec<u8>>,
}
