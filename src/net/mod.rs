//! User-space network helpers for the Wi-Fi tunnel.
//!
//! The station ([`crate::mt7601u::data`]) implements [`IpLink`]; [`ipv4`] and
//! [`dhcp`] bring that link up with an address from the AP. The relay that
//! moves packets between the link and macOS `utun` lives in
//! [`crate::tunnel::relay`].

pub mod arp;
pub mod dhcp;
pub mod ipv4;

use std::time::Duration;

/// A link that carries raw IPv4 packets — here, the associated 802.11 station.
pub trait IpLink {
    /// Send one IPv4 packet towards the AP.
    fn send_ipv4(&self, packet: &[u8]) -> Result<(), String>;
    /// Receive the next inbound IPv4 packet, or `None` if `timeout` elapses.
    fn recv_ipv4(&self, timeout: Duration) -> Option<Vec<u8>>;

    /// Receive up to `max` inbound IPv4 packets, blocking up to `timeout` for
    /// the first.
    ///
    /// The default reads a single packet; a link whose transport delivers
    /// several frames per transfer (the MT7601U does) overrides it to drain a
    /// whole batch at once instead of one packet per call.
    fn recv_batch(&self, timeout: Duration, _max: usize) -> Vec<Vec<u8>> {
        self.recv_ipv4(timeout).into_iter().collect()
    }
}
