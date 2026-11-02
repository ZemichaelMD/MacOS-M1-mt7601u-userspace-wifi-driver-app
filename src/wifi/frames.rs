//! 802.11 management frame construction.
//!
//! Hand-built frames (no mac80211 on macOS). All multi-byte fields are
//! little-endian per the standard.

/// Broadcast address.
pub const BROADCAST: [u8; 6] = [0xff; 6];

/// Management frame control word for a given subtype (type 0).
fn frame_control(subtype: u8) -> u16 {
    u16::from(subtype) << 4
}

/// Write the 24-byte management MAC header.
fn header(frame: &mut Vec<u8>, subtype: u8, destination: [u8; 6], source: [u8; 6], bssid: [u8; 6]) {
    frame.extend_from_slice(&frame_control(subtype).to_le_bytes());
    frame.extend_from_slice(&0u16.to_le_bytes()); // duration
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&0u16.to_le_bytes()); // sequence control
}

/// Append an information element.
fn ie(frame: &mut Vec<u8>, id: u8, body: &[u8]) {
    frame.push(id);
    frame.push(body.len() as u8);
    frame.extend_from_slice(body);
}

/// Basic rates 1, 2, 5.5, 11 Mbit/s (`0x80 | value*2` encoding).
const SUPPORTED_RATES: [u8; 4] = [0x82, 0x84, 0x8b, 0x96];
/// OFDM rates 6..54 Mbit/s as an extended-supported-rates IE.
const EXTENDED_RATES: [u8; 8] = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c];

/// Probe request (subtype 4). An empty `ssid` becomes a wildcard scan.
pub fn probe_request(source: [u8; 6], ssid: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + 2 + ssid.len() + 6 + 10);
    header(&mut frame, 4, BROADCAST, source, BROADCAST);
    ie(&mut frame, 0, ssid);
    ie(&mut frame, 1, &SUPPORTED_RATES);
    ie(&mut frame, 50, &EXTENDED_RATES);
    frame
}

/// Open-system authentication request (subtype 11, algorithm 0, seq 1).
pub fn auth_open(source: [u8; 6], bssid: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(30);
    header(&mut frame, 11, bssid, source, bssid);
    frame.extend_from_slice(&0u16.to_le_bytes()); // auth algorithm: open system
    frame.extend_from_slice(&1u16.to_le_bytes()); // auth transaction sequence
    frame.extend_from_slice(&0u16.to_le_bytes()); // status code
    frame
}

/// SAE authentication frame (subtype 11, algorithm 3).
///
/// The body carries the commit, the commit replayed with an anti-clogging
/// token, or the confirm, depending on `sequence`.
pub fn auth_sae(
    source: [u8; 6],
    bssid: [u8; 6],
    sequence: u16,
    status: u16,
    body: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(30 + body.len());
    header(&mut frame, 11, bssid, source, bssid);
    frame.extend_from_slice(&3u16.to_le_bytes()); // auth algorithm: SAE
    frame.extend_from_slice(&sequence.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

/// Association request (subtype 0) for an open network.
///
/// `capability` should set the ESS bit (0x0001).
pub fn assoc_request(
    source: [u8; 6],
    bssid: [u8; 6],
    ssid: &[u8],
    capability: u16,
    listen_interval: u16,
) -> Vec<u8> {
    assoc_request_with_ies(source, bssid, ssid, capability, listen_interval, &[])
}

/// Association request with extra information elements appended (for example
/// the RSN IE that a WPA2-only AP requires).
pub fn assoc_request_with_ies(
    source: [u8; 6],
    bssid: [u8; 6],
    ssid: &[u8],
    capability: u16,
    listen_interval: u16,
    extra_ies: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + 4 + 2 + ssid.len() + 10 + extra_ies.len());
    header(&mut frame, 0, bssid, source, bssid);
    frame.extend_from_slice(&capability.to_le_bytes());
    frame.extend_from_slice(&listen_interval.to_le_bytes());
    ie(&mut frame, 0, ssid);
    ie(&mut frame, 1, &SUPPORTED_RATES);
    ie(&mut frame, 50, &EXTENDED_RATES);
    frame.extend_from_slice(extra_ies);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const AP: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    #[test]
    fn probe_request_structure() {
        let frame = probe_request(SRC, &[]);

        // Management, subtype 4.
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        assert_eq!(fc >> 2 & 0x3, 0);
        assert_eq!(fc >> 4 & 0xf, 4);
        // DA broadcast, SA ours, BSSID broadcast.
        assert_eq!(&frame[4..10], &BROADCAST);
        assert_eq!(&frame[10..16], &SRC);
        assert_eq!(&frame[16..22], &BROADCAST);
        // Wildcard SSID IE + supported rates + extended rates.
        assert_eq!(&frame[24..26], &[0, 0]);
        assert_eq!(&frame[26..28], &[1, 4]);
        assert_eq!(&frame[32..34], &[50, 8]);
        assert_eq!(frame.len(), 24 + 2 + 6 + 10);
    }

    #[test]
    fn auth_open_is_open_system_seq_one() {
        let frame = auth_open(SRC, AP);
        assert_eq!(&frame[4..10], &AP);
        assert_eq!(&frame[10..16], &SRC);
        assert_eq!(&frame[24..30], &[0, 0, 1, 0, 0, 0]);
        assert_eq!(frame.len(), 30);
    }

    #[test]
    fn auth_sae_carries_the_commit() {
        let frame = auth_sae(SRC, AP, 1, 0, &[0xab; 98]);
        assert_eq!(&frame[4..10], &AP);
        assert_eq!(&frame[10..16], &SRC);
        assert_eq!(&frame[24..30], &[3, 0, 1, 0, 0, 0]);
        assert_eq!(frame.len(), 30 + 98);
        assert_eq!(&frame[30..], &[0xab; 98]);
    }

    #[test]
    fn assoc_request_carries_ssid_and_capability() {
        let frame = assoc_request(SRC, AP, b"test", 0x0001, 10);
        assert_eq!(&frame[24..26], &[0x01, 0x00]); // ESS
        assert_eq!(&frame[26..28], &[10, 0]); // listen interval
        assert_eq!(&frame[28..30], &[0, 4]); // SSID IE
        assert_eq!(&frame[30..34], b"test");
    }
}
