//! Generator for proposal lists for IKEv2

use std::collections::VecDeque;

use isakmp::strum::IntoEnumIterator;
use isakmp::v2::definitions::params::EncryptionAlgorithm;
use isakmp::v2::definitions::params::IntegrityAlgorithm;
use isakmp::v2::definitions::params::KeyExchangeMethod;
use isakmp::v2::definitions::params::PseudorandomFunction;
use isakmp::v2::definitions::params::SecurityProtocol;
use isakmp::v2::definitions::Proposal;
use isakmp::v2::definitions::Transform::Encryption;
use isakmp::v2::definitions::Transform::Integrity;
use isakmp::v2::definitions::Transform::KeyExchange;
use isakmp::v2::definitions::Transform::PseudoRandomFunction;
use itertools::Itertools;
use tracing::debug;

/// Generate a list of all possible valid proposals that should be checked
pub fn list_all_proposals() -> VecDeque<Proposal> {
    let now = std::time::Instant::now();
    let product = itertools::iproduct!(
        EncryptionAlgorithm::iter(),
        PseudorandomFunction::iter(),
        IntegrityAlgorithm::iter(),
        KeyExchangeMethod::iter(),
    )
    .map(|(encr, prf, integrity, kex)| {
        let valid_lengths = encr.get_key_lengths();
        if valid_lengths.is_empty() {
            if encr.is_aead_cipher() {
                vec![Proposal::new_full(
                    SecurityProtocol::InternetKeyExchange,
                    vec![
                        Encryption(encr, None),
                        PseudoRandomFunction(prf),
                        KeyExchange(kex),
                    ],
                )]
            } else {
                vec![Proposal::new_full(
                    SecurityProtocol::InternetKeyExchange,
                    vec![
                        Encryption(encr, None),
                        PseudoRandomFunction(prf),
                        Integrity(integrity),
                        KeyExchange(kex),
                    ],
                )]
            }
        } else {
            valid_lengths
                .iter()
                .map(|l| {
                    if encr.is_aead_cipher() {
                        Proposal::new_full(
                            SecurityProtocol::InternetKeyExchange,
                            vec![
                                Encryption(encr, Some(*l)),
                                PseudoRandomFunction(prf),
                                KeyExchange(kex),
                            ],
                        )
                    } else {
                        Proposal::new_full(
                            SecurityProtocol::InternetKeyExchange,
                            vec![
                                Encryption(encr, Some(*l)),
                                PseudoRandomFunction(prf),
                                Integrity(integrity),
                                KeyExchange(kex),
                            ],
                        )
                    }
                })
                .collect::<Vec<_>>()
        }
    })
    .flatten()
    .unique()
    .collect::<VecDeque<_>>();
    debug!(
        "Produced {} proposals in {:#?}",
        product.len(),
        now.elapsed()
    );
    product
}
