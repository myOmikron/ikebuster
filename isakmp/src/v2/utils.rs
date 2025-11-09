//! Various utilities for IKEv2

use crate::v2::definitions::Proposal;

/// Format a list of [Proposal]s into a serialized CSV interpretation
pub fn format_to_csv(proposals: Vec<Proposal>) -> Result<String, std::fmt::Error> {
    let mut counter = 0;
    let mut result =
        "\"number\";\"proposal\";\"encryption\";\"prf\";\"integrity\";\"key_exchange\"\n"
            .to_string();

    for (i, p) in proposals.iter().enumerate() {
        use std::fmt::Write;
        for (e, key_len) in p.encryption_algorithms.iter() {
            let encryption = if let Some(key_len) = key_len {
                format!("{e}_{key_len}")
            } else {
                e.to_string()
            };
            for prf in p.pseudo_random_functions.iter() {
                for kex in p.key_exchange_methods.iter() {
                    if p.integrity_algorithms.is_empty() {
                        counter += 1;
                        result.write_fmt(format_args!(
                            "\"{counter}\";\"{proposal_no}\";\"{encryption}\";\"{prf}\";\"{integrity}\";\"{kex}\"\n",
                            proposal_no = i + 1,
                            integrity = ""
                        ))?
                    }
                    for integrity in p.integrity_algorithms.iter() {
                        counter += 1;
                        result.write_fmt(format_args!(
                            "\"{counter}\";\"{proposal_no}\";\"{encryption}\";\"{prf}\";\"{integrity}\";\"{kex}\"\n",
                            proposal_no = i + 1
                        ))?
                    }
                }
            }
        }
    }
    Ok(result)
}
