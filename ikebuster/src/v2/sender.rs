use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use isakmp::v2::definitions::constants::MIN_SUPPORTED_MSG_SIZE;
use isakmp::v2::definitions::IKEv2;
use isakmp::v2::definitions::KeyExchange;
use isakmp::v2::definitions::Payload;
use isakmp::v2::definitions::Proposal;
use isakmp::v2::definitions::SecurityAssociation;
use tokio::net::UdpSocket;
use tracing::debug;
use tracing::error;
use tracing::instrument;
use tracing::trace;
use tracing::warn;

use crate::v2::Open;
use crate::v2::ScanOptionsV2;
use crate::v2::Statistics;
use crate::v2::HOST_DEAD_TIMEOUT;
use crate::v2::RECEIVE_TIMEOUT;
use crate::ScanError;

/// Maximum number of packets that should be kept in `open` state simultaneously
const SENT_THRESHOLD: usize = 5;

/// Handle sending any packet to the destination. This can be a new `SA_IKE_INIT` packet,
/// but it could be also retrying an already sent packet or deleting a half-open connection.
pub(crate) async fn handle_sending(
    stats: &mut Statistics,
    open: &mut Open,
    todo: &mut VecDeque<Proposal>,
    socket: &Arc<UdpSocket>,
    options: &ScanOptionsV2,
    last_received_packet: &Option<Instant>,
) -> Result<(), ScanError> {
    trace!(
        sent = open.sent.len(),
        retry = open.retry.len(),
        verify = open.verify.len(),
        todo = todo.len(),
        "Sending packet"
    );
    if !handle_sending_hello(stats, open, todo, socket, options).await? {
        debug!("Reached threshold for open connections, did not send new packets");
        let now = Instant::now();
        if open.sent.iter().all(|(_, i)| (now - *i) > RECEIVE_TIMEOUT) {
            // If no packets were received and all sent packets timed out, the
            // host is either dead or went into DoS protection and drops packets.
            // DoS protection is likely not active at the very beginning of the
            // program, thus it is likely that any response is received if there is
            // an IKE responder on the other side.
            if stats.recv_bytes == 0 {
                error!("Timeout reached while waiting for incoming packets, does the host accept IKE connections?");
                return Err(ScanError::Timeout(RECEIVE_TIMEOUT));
            } else if last_received_packet.is_some_and(|i| Instant::now() - i > HOST_DEAD_TIMEOUT) {
                error!("Timeout reached while waiting for incoming packets, the host likely died or disconnected.");
                return Err(ScanError::Timeout(HOST_DEAD_TIMEOUT));
            }
            // Otherwise, if packets were received already and the last packet was
            // received less than 10 minutes ago, we just keep retrying with some
            // packet, while the retry list is already empty at this point.
            if let Some((packet, _)) = open.sent.pop() {
                send_packet(packet, socket, open, stats).await?;
            }
        };
    } else {
        // If a packet was lost but the sender threshold not reached, we need to detect the packet
        // timeout. Detecting a single lost packet is sufficient, since this part will be called
        // in a loop, and it will add at most one packet per iteration of that loop anyway.
        let now = Instant::now();
        if let Some(last_lost_index) = open
            .sent
            .iter()
            .enumerate()
            .filter_map(|(i, (_, instant))| {
                if (now - *instant) > RECEIVE_TIMEOUT {
                    Some(i)
                } else {
                    None
                }
            })
            .next_back()
        {
            let (packet, _) = open.sent.swap_remove(last_lost_index);
            send_packet(packet, socket, open, stats).await?;
        };
    };
    Ok(())
}

/// Send IKEv2 `IKE_SA_INIT` messages, returning whether any packet was sent;
/// it will first retry any packet that has already been sent at least once,
/// and then check for proposal lists that need to be verified before
/// trying new proposals that have not been attempted yet
async fn handle_sending_hello(
    stats: &mut Statistics,
    open: &mut Open,
    todo: &mut VecDeque<Proposal>,
    socket: &Arc<UdpSocket>,
    options: &ScanOptionsV2,
) -> Result<bool, ScanError> {
    if let Some(packet) = open.retry.pop() {
        send_packet(packet, socket, open, stats).await?;
        return Ok(true);
    }

    if open.sent.len() >= SENT_THRESHOLD {
        return Ok(false);
    }
    if let Some(proposals) = open.verify.pop() {
        if let Some((packet, unused_proposals)) = make_new_hello_packet(proposals) {
            if !unused_proposals.is_empty() {
                open.verify.push(unused_proposals);
            }
            send_packet(packet, socket, open, stats).await?;
        }
        return Ok(true);
    }

    let mut proposals = vec![];
    for _ in 0..options.transform_no {
        if let Some(proposal) = todo.pop_front() {
            proposals.push(proposal);
        }
    }
    if let Some((packet, unused_proposals)) = make_new_hello_packet(proposals) {
        for p in unused_proposals {
            todo.push_front(p)
        }
        send_packet(packet, socket, open, stats).await?;
    }
    Ok(true)
}

/// Send a single [IKEv2] packet and keep track of stats and open connections
#[instrument(skip_all, fields(payloads = packet.payloads.len(), proposals = count_proposals(&packet)))]
pub(crate) async fn send_packet(
    packet: IKEv2,
    socket: &Arc<UdpSocket>,
    open: &mut Open,
    stats: &mut Statistics,
) -> Result<(), ScanError> {
    let serialized_msg = packet.try_build().map_err(ScanError::GeneratorFailed)?;
    let ts = Instant::now();
    let sent_bytes = match socket.send(serialized_msg.as_slice()).await {
        Ok(v) => v,
        Err(err) => {
            warn!(
                ?packet,
                "Sending failed for IKE packet: {}: {:#?}",
                err.kind(),
                err
            );
            // For ErrorKind::Uncategorized errors with error number 90, the MTU
            // along the path was lower than expected. If Path MTU Discovery is enabled,
            // this error signals that the sender should reduce the packet size.
            // However, since the kernel performs Path MTU Discovery as well,
            // simply retrying to send the packet once will already solve the problem,
            // as the kernel will fragment the outgoing UDP packet correctly.
            if let Some(e) = err.raw_os_error() {
                if e == 90 {
                    debug!(
                        "Detected raw OS error value 90. This is likely due to Path
                        MTU Discovery. Retrying to send the packet once..."
                    );
                    let sent_bytes = socket.send(serialized_msg.as_slice()).await.map_err(|e| {
                        stats.errors += 1;
                        error!("Failed to resend the packet after MTU discovery: {}", e);
                        ScanError::Send(e)
                    })?;
                    open.sent.push((packet, ts));
                    stats.sent_bytes += sent_bytes as u64;
                    stats.sent_packets += 1;
                    return Ok(());
                }
            }
            stats.errors += 1;
            return Err(ScanError::Send(err));
        }
    };
    open.sent.push((packet, ts));
    stats.sent_bytes += sent_bytes as u64;
    stats.sent_packets += 1;
    Ok(())
}

/// Construct a new "hello packet" from a list of proposals that should be used in the
/// SA of that packet, returning the packet and all unused proposals on success.
/// Proposals may not all be used if the packet would grow too large if they were added.
/// The "hello" packet is the first packet of the `IKE_SA_INIT` exchange that negotiates an SA.
pub(crate) fn make_new_hello_packet(
    mut proposals: Vec<Proposal>,
) -> Option<(IKEv2, Vec<Proposal>)> {
    let first_proposal = proposals.pop();
    let mut packet = if let Some(dh_group) = match &first_proposal {
        Some(first) => first.key_exchange_methods.first().cloned(),
        None => None,
    } {
        IKEv2::hello(vec![
            Payload::SecurityAssociation(SecurityAssociation {
                proposals: vec![first_proposal.expect("first proposal must exist to get here")],
            }),
            Payload::KeyExchange(KeyExchange {
                dh_group,
                data: get_random_vec(dh_group.get_key_handshake_length()),
            }),
            Payload::Nonce(get_random_vec(64)),
        ])
    } else {
        return None;
    };

    let mut current_len = packet
        .try_build()
        .map_err(ScanError::GeneratorFailed)
        .ok()?
        .len();

    while let Some(next) = proposals.last() {
        let serialized_proposal_len = next
            .try_build(1, true)
            .map_err(ScanError::GeneratorFailed)
            .ok()?
            .len();
        if current_len + serialized_proposal_len <= MIN_SUPPORTED_MSG_SIZE {
            current_len += serialized_proposal_len;
            for payload in packet.payloads.iter_mut() {
                if let Payload::SecurityAssociation(sa) = payload {
                    sa.proposals.push(proposals.pop()?);
                    break;
                }
            }
        } else {
            break;
        }
    }
    Some((packet, proposals))
}

fn count_proposals(packet: &IKEv2) -> usize {
    packet
        .payloads
        .iter()
        .filter_map(|p| match p {
            Payload::SecurityAssociation(sa) => Some(sa.proposals.len()),
            _ => None,
        })
        .sum()
}

/// Create a `Vec<u8>` filled with random bytes
///
/// These bytes are not guaranteed to be cryptographically safe.
fn get_random_vec(len: usize) -> Vec<u8> {
    rand::random_iter().take(len).collect()
}
