//! IPv4 + UDP framing (RFC 791 / RFC 768) for the DHCP client.
//!
//! The data-path relay itself does not interpret IP packets — it passes them
//! between `utun` and the Wi-Fi data frames untouched. This module exists only
//! so the station can originate and receive the DHCP `DISCOVER`/`REQUEST`
//! exchange that assigns the link an address.

use std::net::Ipv4Addr;

/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;
/// IPv4 header length for a packet with no options.
pub const IPV4_HEADER_LEN: usize = 20;
/// UDP header length.
pub const UDP_HEADER_LEN: usize = 8;

/// RFC 1071 Internet checksum over `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = remainder {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 packet with a 20-byte header and no options.
pub fn build(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u16,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + payload.len();
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x45); // version 4, IHL 5
    packet.push(0x00); // DSCP / ECN
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&identification.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    packet.push(64); // TTL
    packet.push(protocol);
    packet.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// Build a UDP datagram, computing the checksum against the IPv4 pseudo-header.
pub fn build_udp(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let length = UDP_HEADER_LEN + payload.len();
    let mut datagram = Vec::with_capacity(length);
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&(length as u16).to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    datagram.extend_from_slice(payload);

    let sum = udp_checksum(source, destination, &datagram);
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    datagram
}

/// UDP checksum over the IPv4 pseudo-header (RFC 768).
pub fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, datagram: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + datagram.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(PROTO_UDP);
    pseudo.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(datagram);
    match checksum(&pseudo) {
        0 => 0xffff,
        sum => sum,
    }
}

/// A parsed IPv4 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub payload: &'a [u8],
}

/// The validated total length (header + payload) of an IPv4 packet.
///
/// Useful for trimming the 4-byte padding that follows a receive segment.
pub fn total_length(packet: &[u8]) -> Option<usize> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    (total >= IPV4_HEADER_LEN && total <= packet.len()).then_some(total)
}

/// Parse an IPv4 packet, honouring the IHL and total-length fields.
pub fn parse(packet: &[u8]) -> Option<Ipv4<'_>> {
    let total_len = total_length(packet)?;
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < IPV4_HEADER_LEN || ihl > total_len {
        return None;
    }
    Some(Ipv4 {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol: packet[9],
        payload: &packet[ihl..total_len],
    })
}

/// Parse a UDP datagram into `(source_port, destination_port, payload)`.
pub fn parse_udp(datagram: &[u8]) -> Option<(u16, u16, &[u8])> {
    if datagram.len() < UDP_HEADER_LEN {
        return None;
    }
    let source_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let destination_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    let length = usize::from(u16::from_be_bytes([datagram[4], datagram[5]])).min(datagram.len());
    if length < UDP_HEADER_LEN {
        return None;
    }
    Some((
        source_port,
        destination_port,
        &datagram[UDP_HEADER_LEN..length],
    ))
}

/// Whether two addresses are on the same subnet, given a netmask.
///
/// Used to pick the next hop: an on-link destination is resolved directly,
/// anything else goes to the gateway.
pub fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let a = u32::from(a);
    let b = u32::from(b);
    let mask = u32::from(mask);
    a & mask == b & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_known_header() {
        // A standard example header: 45 00 00 73 ... -> checksum 0xb861.
        let header = [
            0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&header), 0xb861);
    }

    #[test]
    fn ipv4_build_parse_round_trip() {
        let source = Ipv4Addr::new(0, 0, 0, 0);
        let dest = Ipv4Addr::new(255, 255, 255, 255);
        let packet = build(source, dest, 0x1234, PROTO_UDP, &[1, 2, 3, 4]);

        let parsed = parse(&packet).unwrap();
        assert_eq!(parsed.source, source);
        assert_eq!(parsed.destination, dest);
        assert_eq!(parsed.protocol, PROTO_UDP);
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);

        // Header checksum verifies over the header with the checksum field zeroed.
        let mut header = packet[..20].to_vec();
        header[10] = 0;
        header[11] = 0;
        assert_eq!(
            checksum(&header),
            u16::from_be_bytes([packet[10], packet[11]])
        );
    }

    #[test]
    fn udp_round_trip_and_checksum() {
        let source = Ipv4Addr::new(0, 0, 0, 0);
        let dest = Ipv4Addr::new(255, 255, 255, 255);
        let datagram = build_udp(source, 68, dest, 67, &[9, 8, 7]);
        let (sport, dport, payload) = parse_udp(&datagram).unwrap();
        assert_eq!((sport, dport), (68, 67));
        assert_eq!(payload, &[9, 8, 7]);
        // The stored checksum matches a recomputation.
        let mut copy = datagram.clone();
        copy[6] = 0;
        copy[7] = 0;
        assert_eq!(
            udp_checksum(source, dest, &copy),
            u16::from_be_bytes([datagram[6], datagram[7]])
        );
    }

    #[test]
    fn rejects_short_and_non_ipv4() {
        assert!(parse(&[0u8; 10]).is_none());
        let mut packet = build(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            0,
            PROTO_UDP,
            &[],
        );
        packet[0] = 0x65; // version 6
        assert!(parse(&packet).is_none());
        assert!(parse_udp(&[0u8; 4]).is_none());
    }

    #[test]
    fn same_subnet_picks_the_next_hop() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let us = Ipv4Addr::new(192, 168, 0, 123);
        // On-link peers are resolved directly.
        assert!(same_subnet(us, Ipv4Addr::new(192, 168, 0, 1), mask));
        assert!(same_subnet(us, Ipv4Addr::new(192, 168, 0, 200), mask));
        // Anything off-link goes to the gateway.
        assert!(!same_subnet(us, Ipv4Addr::new(8, 8, 8, 8), mask));
        assert!(!same_subnet(us, Ipv4Addr::new(192, 168, 1, 1), mask));
        // A /25 mask splits 192.168.0.x.
        let mask25 = Ipv4Addr::new(255, 255, 255, 128);
        assert!(!same_subnet(us, Ipv4Addr::new(192, 168, 0, 200), mask25));
    }
}
