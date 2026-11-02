//! Packet relay between the associated 802.11 station and macOS `utun`.
//!
//! The same shape as the BetterTether relay, one layer up: `utun → Wi-Fi` (a
//! packet from macOS is encapsulated in an 802.11 data frame and sent to the
//! AP) and `Wi-Fi → utun` (an inbound IP packet is framed with the 4-byte
//! `utun` header and handed to macOS). `utun` is layer 3, so no Ethernet header
//! is involved — the 802.11 data frame carries IP directly via LLC/SNAP.

use std::io::Read;
use std::time::Duration;

use crate::net::IpLink;

use super::{parse_frame, Utun, AF_INET_HEADER};

/// Read buffer for one `utun` read.
const TUN_BUFFER_LEN: usize = 2048;

/// Upper bound on the packets one direction may move in a single iteration, so
/// a saturating flow cannot starve the other direction or delay shutdown.
pub const MAX_BATCH: usize = 256;

/// A layer-3 endpoint the relay reads and writes raw IP packets on.
pub trait PacketTun {
    /// Read the next IP packet, or `None` if `timeout` elapses.
    fn read_packet(&mut self, timeout: Duration) -> Option<Vec<u8>>;
    /// Write one IP packet.
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), String>;

    /// Push out anything the transport still holds internally.
    ///
    /// `write_packet` may accept a packet without finishing it — the helper
    /// client queues what a full socket would not take. The relay calls this
    /// every iteration so such a queue keeps draining even while no new
    /// packet arrives; a queue that only drains on the next write can fill
    /// and then stay full forever. Transports without an internal queue do
    /// nothing.
    fn flush(&mut self) {}

    /// Read up to `max` IP packets, blocking up to `timeout` for the first.
    ///
    /// The default reads one packet and then drains whatever is already queued
    /// with a short timeout. A transport that can hand back a whole burst at
    /// once (a socket, the raw `utun` fd) overrides this so a busy link is not
    /// limited to one packet per call.
    fn read_batch(&mut self, timeout: Duration, max: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if let Some(packet) = self.read_packet(timeout) {
            out.push(packet);
        }
        while out.len() < max {
            match self.read_packet(Duration::from_millis(1)) {
                Some(packet) => out.push(packet),
                None => break,
            }
        }
        out
    }
}

/// Running counters for the relay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Packets forwarded from macOS into the Wi-Fi link.
    pub to_link_packets: u64,
    /// Bytes forwarded from macOS into the Wi-Fi link.
    pub to_link_bytes: u64,
    /// Packets forwarded from the Wi-Fi link into macOS.
    pub to_tun_packets: u64,
    /// Bytes forwarded from the Wi-Fi link into macOS.
    pub to_tun_bytes: u64,
    /// Packets dropped because a transfer failed.
    pub dropped: u64,
    /// TX status FIFO entries drained (one per retired outbound frame).
    pub tx_status_drained: u64,
    /// Drained entries whose frame was never acknowledged.
    pub tx_status_failed: u64,
}

/// Alternate between the two directions until `keep_going` returns false.
///
/// Each `recv`/`read` is bounded by `poll`, so the loop notices a shutdown
/// request within one poll interval without a second thread. Whole batches are
/// moved per iteration: a single packet per round trip — with a fixed sleep
/// between rounds — is what capped the tunnel at a few tens of packets per
/// second.
pub fn run(
    link: &dyn IpLink,
    tun: &mut dyn PacketTun,
    poll: Duration,
    mut keep_going: impl FnMut() -> bool,
) -> Stats {
    let mut stats = Stats::default();
    while keep_going() {
        for packet in tun.read_batch(poll, MAX_BATCH) {
            match link.send_ipv4(&packet) {
                Ok(()) => {
                    stats.to_link_packets += 1;
                    stats.to_link_bytes += packet.len() as u64;
                }
                Err(_) => stats.dropped += 1,
            }
        }

        for packet in link.recv_batch(poll, MAX_BATCH) {
            match tun.write_packet(&packet) {
                Ok(()) => {
                    stats.to_tun_packets += 1;
                    stats.to_tun_bytes += packet.len() as u64;
                }
                Err(_) => stats.dropped += 1,
            }
        }
    }
    stats
}

impl PacketTun for Utun {
    fn read_packet(&mut self, _timeout: Duration) -> Option<Vec<u8>> {
        // The caller sets `SO_RCVTIMEO` on the interface; `read` honours it.
        let mut buffer = vec![0u8; TUN_BUFFER_LEN];
        let len = self.read(&mut buffer).ok()?;
        let (family, payload) = parse_frame(&buffer[..len])?;
        (family == AF_INET_HEADER).then(|| payload.to_vec())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        self.try_write_packet(packet)
            .map_err(|error| error.to_string())
    }

    fn read_batch(&mut self, _timeout: Duration, max: usize) -> Vec<Vec<u8>> {
        // `SO_RCVTIMEO` (set by the tunnel setup) already bounds each read, so
        // this drains everything the kernel has queued and only blocks on the
        // final, empty read.
        let mut out = Vec::new();
        let mut buffer = [0u8; TUN_BUFFER_LEN];
        while out.len() < max {
            match self.read(&mut buffer) {
                Ok(len) if len > 0 => {
                    if let Some((family, payload)) = parse_frame(&buffer[..len]) {
                        if family == AF_INET_HEADER {
                            out.push(payload.to_vec());
                        }
                    }
                }
                _ => break,
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// An in-memory link that records sends and replays queued receives.
    struct FakeLink {
        sent: RefCell<Vec<Vec<u8>>>,
        received: RefCell<VecDeque<Vec<u8>>>,
    }

    impl IpLink for FakeLink {
        fn send_ipv4(&self, packet: &[u8]) -> Result<(), String> {
            self.sent.borrow_mut().push(packet.to_vec());
            Ok(())
        }
        fn recv_ipv4(&self, _timeout: Duration) -> Option<Vec<u8>> {
            self.received.borrow_mut().pop_front()
        }
    }

    /// An in-memory tun that records writes and replays queued reads.
    struct FakeTun {
        written: RefCell<Vec<Vec<u8>>>,
        to_read: RefCell<VecDeque<Vec<u8>>>,
    }

    impl PacketTun for FakeTun {
        fn read_packet(&mut self, _timeout: Duration) -> Option<Vec<u8>> {
            self.to_read.borrow_mut().pop_front()
        }
        fn write_packet(&mut self, packet: &[u8]) -> Result<(), String> {
            self.written.borrow_mut().push(packet.to_vec());
            Ok(())
        }
    }

    #[test]
    fn relays_both_directions() {
        let link = FakeLink {
            sent: RefCell::new(Vec::new()),
            received: RefCell::new(vec![vec![9, 9, 9]].into()),
        };
        let mut tun = FakeTun {
            written: RefCell::new(Vec::new()),
            to_read: RefCell::new(vec![vec![1, 2, 3]].into()),
        };

        // Stop after two iterations.
        let mut iterations = 0;
        let stats = run(&link, &mut tun, Duration::from_millis(1), || {
            iterations += 1;
            iterations <= 2
        });

        assert_eq!(stats.to_link_packets, 1);
        assert_eq!(stats.to_tun_packets, 1);
        assert_eq!(stats.to_link_bytes, 3);
        assert_eq!(stats.to_tun_bytes, 3);
        assert_eq!(link.sent.borrow().as_slice(), &[vec![1, 2, 3]]);
        assert_eq!(tun.written.borrow().as_slice(), &[vec![9, 9, 9]]);
    }

    #[test]
    fn counts_drops_when_a_transfer_fails() {
        struct FailingLink;
        impl IpLink for FailingLink {
            fn send_ipv4(&self, _packet: &[u8]) -> Result<(), String> {
                Err("nope".into())
            }
            fn recv_ipv4(&self, _timeout: Duration) -> Option<Vec<u8>> {
                None
            }
        }
        let mut tun = FakeTun {
            written: RefCell::new(Vec::new()),
            to_read: RefCell::new(vec![vec![0u8; 8]].into()),
        };
        let mut iterations = 0;
        let stats = run(&FailingLink, &mut tun, Duration::from_millis(1), || {
            iterations += 1;
            iterations <= 1
        });
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.to_link_packets, 0);
    }

    #[test]
    fn read_batch_drains_a_queued_burst() {
        let mut tun = FakeTun {
            written: RefCell::new(Vec::new()),
            to_read: RefCell::new(vec![vec![1], vec![2], vec![3]].into()),
        };
        assert_eq!(
            tun.read_batch(Duration::from_millis(1), MAX_BATCH),
            vec![vec![1], vec![2], vec![3]]
        );
    }

    #[test]
    fn stops_immediately_when_asked() {
        let link = FakeLink {
            sent: RefCell::new(Vec::new()),
            received: RefCell::new(VecDeque::new()),
        };
        let mut tun = FakeTun {
            written: RefCell::new(Vec::new()),
            to_read: RefCell::new(VecDeque::new()),
        };
        let stats = run(&link, &mut tun, Duration::from_millis(1), || false);
        assert_eq!(stats, Stats::default());
    }
}
