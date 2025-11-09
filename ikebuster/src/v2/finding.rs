//! Module for [Finding]s and related utils

use std::fmt::Write;

use isakmp::strum::Display;
use isakmp::v2::definitions::params::EncryptionAlgorithm;
use isakmp::v2::definitions::params::IntegrityAlgorithm;
use isakmp::v2::definitions::params::KeyExchangeMethod;
use isakmp::v2::definitions::params::PseudorandomFunction;
use isakmp::v2::definitions::Proposal;
use serde::Deserialize;
use serde::Serialize;

/// State of a finding, i.e. whether the proposal was accepted by the target or not
#[derive(Debug, Clone, Display, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingResult {
    /// The proposal was accepted
    Accepted,
    /// The proposal was not understood
    InvalidSyntax,
    /// The proposal was rejected
    Rejected,
}

/// Fully populated test result for a single proposal made up of encryption algorithm,
/// PRF algorithm, key exchange method and optional key size and integrity function
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Finding {
    /// Symmetric encryption algorithm
    pub encryption: EncryptionAlgorithm,
    /// Optional accepted key length for the symmetric encryption algorithm
    pub key_size: Option<u16>,
    /// Indicator whether the encryption algorithm is an AEAD,
    /// i.e. does not require an explicit integrity algorithm
    pub is_aead: bool,
    /// Pseudo-random function (aka hash function)
    pub prf: PseudorandomFunction,
    /// Optional integrity function of the proposal
    pub integrity: Option<IntegrityAlgorithm>,
    /// Key exchange method for the Diffie-Hellman key exchange
    pub kex: KeyExchangeMethod,
    /// Result of the check of the proposal
    pub result: FindingResult,
}

/// Convert a list of [Finding]s into a CSV-like format with its own heading line (columns name row)
pub fn format_to_csv(findings: &[Finding]) -> Result<String, std::fmt::Error> {
    let mut result =
        "\"number\";\"encryption\";\"key_size\";\"is_aead\";\"prf\";\"integrity\";\"key_exchange\";\"result\"\n"
            .to_string();

    for (i, f) in findings.iter().enumerate() {
        result.write_fmt(format_args!(
            "\"{number}\";\"{encryption}\";\"{key_size}\";\"{is_aead}\";\"{prf}\";\"{integrity}\";\"{key_exchange}\";\"{result}\"\n",
            number = i + 1,
            encryption = f.encryption,
            key_size = if let Some(s) = f.key_size {
                s.to_string()
            } else {
                "".to_string()
            },
            is_aead = f.is_aead,
            prf = f.prf,
            integrity = if let Some(integrity) = f.integrity {
                integrity.to_string()
            } else {
                "".to_string()
            },
            key_exchange = f.kex,
            result = f.result
        ))?
    }
    Ok(result)
}

impl Finding {
    /// Create a [Finding] from a [Proposal] and the result of the proposal scan
    ///
    /// Note that this finding only uses the very first of each of the proposal's
    /// values. If the proposal contains multiple transforms for a single
    /// transform type, only the first will be used. If a mandatory transform
    /// is omitted, `None` will be returned.
    pub fn from_proposal(proposal: &Proposal, result: FindingResult) -> Option<Self> {
        if let Some((encryption, key_size)) = proposal.encryption_algorithms.first() {
            if let Some(kex) = proposal.key_exchange_methods.first() {
                if let Some(prf) = proposal.pseudo_random_functions.first() {
                    return Some(Finding {
                        encryption: *encryption,
                        key_size: *key_size,
                        is_aead: encryption.is_aead_cipher(),
                        prf: *prf,
                        integrity: proposal.integrity_algorithms.first().copied(),
                        kex: *kex,
                        result,
                    });
                }
            }
        }
        None
    }
}
