use isakmp::v2::definitions::constants::MAX_COOKIE_DATA_SIZE;
use isakmp::v2::definitions::constants::WIN32_ERROR_INVALID_PARAMETER;
use isakmp::v2::definitions::params::ExchangeType;
use isakmp::v2::definitions::params::NotifyErrorMessage;
use isakmp::v2::definitions::params::NotifyStatusMessage;
use isakmp::v2::definitions::params::SecurityProtocol;
use isakmp::v2::definitions::IKEv2;
use isakmp::v2::definitions::Notification;
use isakmp::v2::definitions::NotificationType;
use isakmp::v2::definitions::Payload;
use isakmp::v2::definitions::Proposal;
use itertools::Itertools;
use tracing::debug;
use tracing::error;
use tracing::instrument;
use tracing::trace;
use tracing::warn;

use crate::v2::Open;
use crate::v2::Results;
use crate::v2::Statistics;
use crate::ScanError;

/// Max number of proposals in a `NO_PROPOSAL_CHOSEN` reply that are confirmed
/// to be rejected by the responder; if more than this number of proposals was sent
/// and got rejected, it should be split up and retried instead of counted as rejected
pub const MAX_NO_PROPOSALS_CONFIRMED_LENGTH: usize = 10;

#[instrument(skip_all)]
pub(crate) fn handle_receiving(
    stats: &mut Statistics,
    open: &mut Open,
    results: &mut Results,
    raw_rx: &[u8],
) -> Result<(), ScanError> {
    match IKEv2::try_parse(raw_rx) {
        Ok(packet) => {
            handle_packet(packet, stats, open, results)?;
            stats.recv_packets += 1;
        }
        Err(err) => {
            error!(err = ?err, "Failed to parse IKEv2 packet: {}", err);
            debug!(buff = ?raw_rx, "Invalid IKEv2 packet: {:02x?}", raw_rx);
            stats.errors += 1;
        }
    }
    Ok(())
}

/// Handle an [IKEv2] packet including updates to the statistics
fn handle_packet(
    packet: IKEv2,
    stats: &mut Statistics,
    open: &mut Open,
    results: &mut Results,
) -> Result<(), ScanError> {
    if packet.initiator {
        warn!(
            packet = ?packet,
            "Received IKEv2 packet with initiator flag set, refused to parse"
        );
        stats.errors += 1;
        return Ok(());
    }
    if !packet.response {
        match packet.exchange_type {
            ExchangeType::Informational => {}
            _ => {
                debug!(packet = ?packet, "Ignored IKEv2 request with non-informational payload");
            }
        }
        return Ok(());
    }

    let tracked_packet_index = match open
        .sent
        .iter()
        .position(|(p, _)| p.initiator_cookie == packet.initiator_cookie)
    {
        Some(index) => index,
        None => {
            error!(
                packet = ?packet,
                "Received IKEv2 packet with unknown initiator SPI not tracked in `open` connections!"
            );
            stats.errors += 1;
            return Ok(());
        }
    };

    // Handle notifications (e.g. DoS cookies and invalid proposals) before handling successful cases
    for payload in packet.payloads.iter() {
        if let Payload::Notify(n) = payload {
            match n.variant {
                NotificationType::Error(e) => match e {
                    NotifyErrorMessage::InvalidMajorVersion => {
                        error!("Destination is not capable of speaking IKEv2: {}", e);
                        return Err(ScanError::IKEv2NotSupported(e.to_string()));
                    }
                    NotifyErrorMessage::NoProposalChosen
                    | NotifyErrorMessage::InvalidSyntax
                    | NotifyErrorMessage::InvalidKeyExchangePayload => {
                        let (open_packet, _) = open.sent.swap_remove(tracked_packet_index);
                        handle_unsuccessful_responses(open_packet, open, stats, results, e);
                        return Ok(());
                    }
                    NotifyErrorMessage::MicrosoftWindowsStatusNotify => {
                        let win_status_notify_data = n.data.iter().copied().collect_array();
                        debug!("Found a Microsoft Windows status notification with data: {win_status_notify_data:#?}");
                        trace!("Raw notification data: {:#?}", n.data);
                        if let Some(win_status_data) = win_status_notify_data {
                            let error_code = u32::from_be_bytes(win_status_data);
                            if error_code == WIN32_ERROR_INVALID_PARAMETER {
                                let (open_packet, _) = open.sent.swap_remove(tracked_packet_index);
                                handle_unsuccessful_responses(open_packet, open, stats, results, e);
                                return Ok(());
                            }
                        } else {
                            warn!(packet = ?packet, "Unexpected Windows error Notify data format: {:?}", n);
                        }
                    }
                    _ => {
                        warn!(packet = ?packet, "Unexpected error notification: {:?}", n);
                    }
                },
                NotificationType::Status(s) => {
                    match s {
                        NotifyStatusMessage::Cookie => {
                            let (open_packet, _) = open.sent.swap_remove(tracked_packet_index);
                            if handle_dos_cookie(open_packet, open, n) {
                                return Ok(());
                            };
                        }
                        // Simply ignore various status messages we are not interested in
                        NotifyStatusMessage::MultipleAuthSupported
                        | NotifyStatusMessage::NatDetectionSourceIp
                        | NotifyStatusMessage::NatDetectionDestinationIp
                        | NotifyStatusMessage::Ikev2FragmentationSupported
                        | NotifyStatusMessage::ChildlessIkev2Supported => {}
                        _ => {
                            warn!("Unexpected status notification: {:?}", n)
                        }
                    }
                }
            }
        }
    }

    // Successful handshakes produce SecurityAssociation payloads as response, but the
    // Proposal inside may be ordered differently and is identified by the Proposal number
    // that is not accessible here anymore, thus we need to iterate over all Proposals
    for payload in packet.payloads {
        match payload {
            Payload::SecurityAssociation(sa) => {
                let (open_packet, _) = open.sent.swap_remove(tracked_packet_index);
                if let Some(received_proposal) = sa.proposals.first() {
                    let mut todo = vec![];
                    let open_proposals = open_packet
                        .payloads
                        .into_iter()
                        .filter_map(|p| match p {
                            Payload::SecurityAssociation(sa) => Some::<Vec<Proposal>>(sa.proposals),
                            _ => None,
                        })
                        .flatten()
                        .collect::<Vec<_>>();
                    for p in open_proposals.iter() {
                        if *p == *received_proposal {
                            results.accepted.push(p.clone());
                        } else {
                            todo.push(p.clone());
                        }
                    }

                    // If the length of the open proposals matches the list of to-do items,
                    // which was filled above, then none of the open proposals was accepted.
                    // This may happen if the proposal is slightly different, for example if it has
                    // a key size attribute while no such attribute was sent to the responder first.
                    // Then the above filtering loop needs to be repeated with a fix for it.
                    if todo.len() == open_proposals.len() {
                        todo.clear();
                        let mut modified_proposal = received_proposal.clone();
                        for e in modified_proposal.encryption_algorithms.iter_mut() {
                            e.1 = None
                        }
                        for mut p in open_proposals {
                            for e in p.encryption_algorithms.iter_mut() {
                                e.1 = None
                            }
                            if p == modified_proposal {
                                results.accepted.push(p.clone());
                            } else {
                                todo.push(p);
                            }
                        }
                    }

                    // Only the single accepted proposal is treated as finished, all others
                    // need to be retried to verify that they also work correctly
                    if !todo.is_empty() {
                        open.verify.push(todo);
                    }
                }
            }
            Payload::KeyExchange(_) => {}        // TODO: verify KE
            Payload::CertificateRequest(_) => {} // TODO: verify CR
            Payload::VendorID(v) => {
                if !results.vendor_ids.contains(&v) {
                    results.vendor_ids.push(v);
                }
            }
            // Ignore all other payloads
            Payload::Nonce(_)
            | Payload::Notify(_)
            | Payload::Delete(_)
            | Payload::EncryptedAndAuthenticated(_) => {}
        }
    }
    Ok(())
}

/// Handle responses that are neither DoS cookies nor successfully established SAs
///
/// If the variant is a [NotifyErrorMessage::MicrosoftWindowsStatusNotify],
/// it is assumed to be invalid syntax, which counts as rejected anyway.
#[instrument(skip_all, fields(variant))]
fn handle_unsuccessful_responses(
    open_packet: IKEv2,
    open: &mut Open,
    stats: &mut Statistics,
    results: &mut Results,
    variant: NotifyErrorMessage,
) {
    if let Some(sa) = open_packet
        .payloads
        .iter()
        .filter_map(|p| match p {
            Payload::SecurityAssociation(sa) => Some(sa),
            _ => None,
        })
        .next()
    {
        match &sa.proposals {
            v if v.is_empty() => {
                error!(
                    packet = ?open_packet,
                    "Sent IKEv2 packet seems to have no proposals, found a bug."
                );
                stats.errors += 1;
            }
            v if v.len() == 1 => {
                if let Some(proposal) = v.first() {
                    match variant {
                        NotifyErrorMessage::NoProposalChosen => {
                            results.rejected.push(proposal.clone())
                        }
                        NotifyErrorMessage::InvalidSyntax
                        | NotifyErrorMessage::MicrosoftWindowsStatusNotify => {
                            results.invalid_syntax.push(proposal.clone())
                        }
                        NotifyErrorMessage::InvalidKeyExchangePayload => {
                            warn!(
                                packet = ?open_packet,
                                "Received invalid key exchange payload for a single proposal"
                            );
                            results.rejected.push(proposal.clone())
                        }
                        _ => {}
                    }
                }
            }
            v => {
                if variant == NotifyErrorMessage::NoProposalChosen
                    && v.len() <= MAX_NO_PROPOSALS_CONFIRMED_LENGTH
                {
                    for p in v {
                        results.rejected.push(p.clone())
                    }
                } else {
                    // For more than one proposal, it is not known which proposal might have caused
                    // problems; thus we simply split them in half to perform a binary search
                    let mut v = v.clone();
                    let second_half = v.split_off(v.len() / 2);
                    open.verify.push(v);
                    open.verify.push(second_half);
                }
            }
        }
    }
}

/// Handle DoS cookies, returns `true` when the packet should be discarded
#[instrument(skip_all, fields(?notification))]
fn handle_dos_cookie(mut open_packet: IKEv2, open: &mut Open, notification: &Notification) -> bool {
    if notification.protocol == SecurityProtocol::InternetKeyExchange
        || notification.protocol == SecurityProtocol::Reserved
    {
        if notification.protocol == SecurityProtocol::Reserved {
            debug!(notification = ?notification, "Received cookie for Reserved, but using anyway");
        }
        if notification.data.len() > MAX_COOKIE_DATA_SIZE {
            warn!(
                notification = ?notification,
                "Received cookie with more than {MAX_COOKIE_DATA_SIZE} bytes payload, violating the protocol! Proceeding anyway..."
            );
        } else if notification.data.is_empty() {
            warn!(
                notification = ?notification,
                "Received empty cookie payload, violating the protocol! Proceeding anyway..."
            );
        }
        let data = notification.data.clone();
        open_packet.payloads.push(Payload::Notify(Notification {
            variant: NotificationType::Status(NotifyStatusMessage::Cookie),
            data,
            protocol: notification.protocol,
            spi: None,
        }));
        open.retry.push(open_packet);
        true
    } else {
        error!(
            "Received unexpected cookie for non-IKE protocol: {:#?}",
            notification
        );
        false
    }
}
