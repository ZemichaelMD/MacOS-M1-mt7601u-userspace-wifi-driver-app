//! Minimal ARP (RFC 826) for the tunnel.
//!
//! The relay is layer 3 — it moves IP packets — but the Wi-Fi link is not: an
//! outbound frame has to name a next-hop MAC, and the gateway has to be able to
//! resolve *our* IP before it will deliver anything. Addressing every frame to
//! the AP's own MAC makes the AP consume it (it is not addressed to the next
//! hop), and never answering an ARP request for our address means the gateway
//! has nowhere to send the replies. Both show up as a tunnel that reports
//! "relaying" with packets sent and none received.
//!
//! This module is the packet codec; the resolution state lives in the relay.

use std::net::Ipv4Addr;

/// EtherType for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// `htype`: Ethernet.
const HTYPE_ETHERNET: u16 = 1;
/// `ptype`: IPv4.
const PTYPE_IPV4: u16 = 0x0800;
/// Hardware address length.
const HLEN: u8 = 6;
/// Protocol address length.
const PLEN: u8 = 4;
/// ARP request.
pub const OP_REQUEST: u16 = 1;
/// ARP reply.
pub const OP_REPLY: u16 = 2;
/// Size of an Ethernet/IPv4 ARP packet.
pub const PACKET_LEN: usize = 28;

/// A decoded Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

/// Parse an ARP packet, or `None` for anything that is not Ethernet/IPv4 ARP.
pub fn parse(packet: &[u8]) -> Option<ArpPacket> {
    if packet.len() < PACKET_LEN {
        return None;
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != HTYPE_ETHERNET {
        return None;
    }
    if u16::from_be_bytes([packet[2], packet[3]]) != PTYPE_IPV4 {
        return None;
    }
    if packet[4] != HLEN || packet[5] != PLEN {
        return None;
    }

    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&packet[8..14]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&packet[18..24]);

    Some(ArpPacket {
        operation: u16::from_be_bytes([packet[6], packet[7]]),
        sender_mac,
        sender_ip: Ipv4Addr::new(packet[14], packet[15], packet[16], packet[17]),
        target_mac,
        target_ip: Ipv4Addr::new(packet[24], packet[25], packet[26], packet[27]),
    })
}

fn build(
    operation: u16,
    sender_mac: &[u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: &[u8; 6],
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(PACKET_LEN);
    packet.extend_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    packet.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
    packet.push(HLEN);
    packet.push(PLEN);
    packet.extend_from_slice(&operation.to_be_bytes());
    packet.extend_from_slice(sender_mac);
    packet.extend_from_slice(&sender_ip.octets());
    packet.extend_from_slice(target_mac);
    packet.extend_from_slice(&target_ip.octets());
    packet
}

/// Build an ARP request: "who has `target_ip`? tell `sender_ip`".
///
/// The sender fields carry our own address so the reply (and the gateway's own
/// ARP cache) learns where to send traffic for us.
pub fn request(sender_mac: &[u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    build(OP_REQUEST, sender_mac, sender_ip, &[0u8; 6], target_ip)
}

/// Build an ARP reply answering a request for our address.
pub fn reply(
    sender_mac: &[u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: &[u8; 6],
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    build(OP_REPLY, sender_mac, sender_ip, target_mac, target_ip)
}

/// The address whose MAC a frame to `destination` has to be sent to.
///
/// An on-link destination is resolved itself; anything else goes to the
/// gateway, exactly like a default route.
pub fn next_hop(
    destination: Ipv4Addr,
    our: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> Ipv4Addr {
    if super::ipv4::same_subnet(our, destination, mask) {
        destination
    } else {
        gateway
    }
}

/// The addresses the relay has resolved to MAC addresses.
///
/// Small and linearly searched: a station only ever talks to its gateway and a
/// handful of on-link peers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ArpCache {
    entries: Vec<(Ipv4Addr, [u8; 6])>,
}

impl ArpCache {
    /// Record that `ip` is reachable at `mac`.
    pub fn learn(&mut self, ip: Ipv4Addr, mac: [u8; 6]) {
        if let Some(entry) = self.entries.iter_mut().find(|(known, _)| *known == ip) {
            entry.1 = mac;
        } else {
            self.entries.push((ip, mac));
        }
    }

    /// The MAC resolved for `ip`, if any.
    pub fn mac(&self, ip: Ipv4Addr) -> Option<[u8; 6]> {
        self.entries
            .iter()
            .find(|(known, _)| *known == ip)
            .map(|(_, mac)| *mac)
    }

    /// Forget everything (a new link invalidates every entry).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of resolved addresses.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is resolved yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x88, 0x82, 0x79, 0x24, 0x0e, 0xc0];

    #[test]
    fn request_round_trips_and_carries_our_address() {
        let packet = request(
            &MAC,
            Ipv4Addr::new(192, 168, 0, 123),
            Ipv4Addr::new(192, 168, 0, 1),
        );
        assert_eq!(packet.len(), PACKET_LEN);

        let parsed = parse(&packet).unwrap();
        assert_eq!(parsed.operation, OP_REQUEST);
        assert_eq!(parsed.sender_mac, MAC);
        assert_eq!(parsed.sender_ip, Ipv4Addr::new(192, 168, 0, 123));
        assert_eq!(parsed.target_mac, [0u8; 6]);
        assert_eq!(parsed.target_ip, Ipv4Addr::new(192, 168, 0, 1));
    }

    #[test]
    fn reply_carries_both_addresses() {
        let gateway = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let packet = reply(
            &MAC,
            Ipv4Addr::new(192, 168, 0, 123),
            &gateway,
            Ipv4Addr::new(192, 168, 0, 1),
        );
        let parsed = parse(&packet).unwrap();
        assert_eq!(parsed.operation, OP_REPLY);
        assert_eq!(parsed.sender_mac, MAC);
        assert_eq!(parsed.target_mac, gateway);
        assert_eq!(parsed.target_ip, Ipv4Addr::new(192, 168, 0, 1));
    }

    #[test]
    fn rejects_non_ethernet_ipv4_and_truncated_packets() {
        assert!(parse(&[0u8; 10]).is_none());
        let mut packet = request(&MAC, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        packet[1] = 0; // not Ethernet
        assert!(parse(&packet).is_none());
        let mut packet = request(&MAC, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        packet[3] = 0xdd; // not IPv4
        assert!(parse(&packet).is_none());
        let mut packet = request(&MAC, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        packet[5] = 16; // not a 4-byte protocol address
        assert!(parse(&packet).is_none());
    }

    #[test]
    fn next_hop_uses_the_gateway_off_link() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let us = Ipv4Addr::new(192, 168, 0, 123);
        let gateway = Ipv4Addr::new(192, 168, 0, 1);
        // The internet goes through the gateway…
        assert_eq!(
            next_hop(Ipv4Addr::new(8, 8, 8, 8), us, mask, gateway),
            gateway
        );
        // …and an on-link peer is resolved directly.
        assert_eq!(
            next_hop(Ipv4Addr::new(192, 168, 0, 50), us, mask, gateway),
            Ipv4Addr::new(192, 168, 0, 50)
        );
    }

    #[test]
    fn arp_cache_learns_updates_and_clears() {
        let mut cache = ArpCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.mac(Ipv4Addr::new(192, 168, 0, 1)), None);

        cache.learn(Ipv4Addr::new(192, 168, 0, 1), [1; 6]);
        assert_eq!(cache.mac(Ipv4Addr::new(192, 168, 0, 1)), Some([1; 6]));
        assert_eq!(cache.mac(Ipv4Addr::new(192, 168, 0, 2)), None);

        // Re-learning the same address replaces the entry rather than growing.
        cache.learn(Ipv4Addr::new(192, 168, 0, 1), [2; 6]);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.mac(Ipv4Addr::new(192, 168, 0, 1)), Some([2; 6]));

        cache.clear();
        assert!(cache.is_empty());
    }
}
