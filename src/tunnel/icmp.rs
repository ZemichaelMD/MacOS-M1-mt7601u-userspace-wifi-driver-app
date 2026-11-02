//! Minimal IPv4 / ICMPv4 helpers used by the tunnel self-test.
//!
//! These are pure functions (no I/O) so they are unit-testable.

/// Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build the ICMP echo **reply** for an IPv4 echo request.
///
/// Returns the complete IPv4 packet (header + ICMP), ready to be written to the
/// tunnel. Returns `None` if the input is not a well-formed IPv4 echo request.
pub fn echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 20 {
        return None;
    }
    if request[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(request[0] & 0x0f) * 4;
    if ihl < 20 || request.len() < ihl + 8 {
        return None;
    }
    if request[9] != 1 {
        return None; // not ICMP
    }

    let total_len = usize::from(u16::from_be_bytes([request[2], request[3]]));
    let total_len = total_len.clamp(ihl + 8, request.len());
    if total_len < ihl + 8 {
        return None;
    }

    let mut reply = request[..total_len].to_vec();

    // ICMP: type 8 (request) -> 0 (reply).
    if reply[ihl] != 8 {
        return None;
    }
    reply[ihl] = 0;
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let icmp_sum = checksum(&reply[ihl..]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_sum.to_be_bytes());

    // Swap source/destination addresses.
    for offset in 0..4 {
        reply.swap(12 + offset, 16 + offset);
    }

    // IPv4 header: clear checksum, recompute, refresh TTL.
    reply[8] = 64;
    reply[10] = 0;
    reply[11] = 0;
    let ip_sum = checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal IPv4 ICMP echo request from 10.9.9.2 to 10.9.9.1.
    fn echo_request() -> Vec<u8> {
        let mut packet = vec![0u8; 20 + 8 + 4];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(32u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1; // ICMP
        packet[12..16].copy_from_slice(&[10, 9, 9, 2]);
        packet[16..20].copy_from_slice(&[10, 9, 9, 1]);
        packet[20] = 8; // echo request
        packet[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
        packet
    }

    #[test]
    fn checksum_of_known_data() {
        // Checksum of an all-zero 20-byte header is 0xffff.
        assert_eq!(checksum(&[0u8; 20]), 0xffff);
    }

    #[test]
    fn builds_a_valid_echo_reply() {
        let reply = echo_reply(&echo_request()).expect("reply");

        assert_eq!(reply[20], 0, "type should be echo reply");
        // src/dst swapped
        assert_eq!(&reply[12..16], &[10, 9, 9, 1]);
        assert_eq!(&reply[16..20], &[10, 9, 9, 2]);

        // Recomputing the IP checksum over the header must yield 0.
        let ip_sum = checksum(&reply[..20]);
        assert_eq!(ip_sum, 0);
        // Recomputing the ICMP checksum over the ICMP block must yield 0.
        let icmp_sum = checksum(&reply[20..]);
        assert_eq!(icmp_sum, 0);
    }

    #[test]
    fn rejects_non_echo_frames() {
        let mut packet = echo_request();
        packet[20] = 3; // unreachable
        assert!(echo_reply(&packet).is_none());
    }

    #[test]
    fn rejects_short_or_non_ipv4() {
        assert!(echo_reply(&[0u8; 10]).is_none());
        let mut packet = echo_request();
        packet[0] = 0x65; // IPv6
        assert!(echo_reply(&packet).is_none());
    }
}
