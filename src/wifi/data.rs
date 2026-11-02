//! 802.11 data-frame construction/parsing and LLC/SNAP encapsulation
//! (RFC 1042).
//!
//! This is the payload half of the station data path: IP packets travel inside
//! `[LLC/SNAP][IP]` inside an 802.11 data frame (which in turn is wrapped by
//! the TXWI/DMA framing in [`crate::mt7601u::tx`]). Only unencrypted
//! (open-network) data frames are handled — a frame with the Protected bit set
//! is rejected, because WPA2/CCMP is not implemented.

/// LLC/SNAP header prefix: DSAP/SSAP `0xaa`, control `0x03`.
const LLC_SNAP_PREFIX: [u8; 3] = [0xaa, 0xaa, 0x03];
/// LLC/SNAP organisation code for EtherType-tagged frames.
const SNAP_ORG: [u8; 3] = [0x00, 0x00, 0x00];

/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// 802.11 frame type value for data frames.
const TYPE_DATA: u16 = 2;
/// Data subtype (no QoS).
const SUBTYPE_DATA: u16 = 0;
/// QoS data subtype.
const SUBTYPE_QOS_DATA: u16 = 8;

/// Length of the 802.11 data MAC header (no QoS, no address 4).
pub const DATA_HEADER_LEN: usize = 24;
/// Length of the QoS control field.
pub const QOS_CTRL_LEN: usize = 2;
/// Length of an LLC/SNAP header.
pub const LLC_SNAP_LEN: usize = 8;

// Frame-control bits (`IEEE80211_FCTL_*`).
const FC_TO_DS: u16 = 0x0100;
const FC_FROM_DS: u16 = 0x0200;
const FC_PROTECTED: u16 = 0x4000;
/// `IEEE80211_FCTL_ORDER`: an HT control field follows the QoS control field.
const FC_ORDER: u16 = 0x8000;

/// A parsed inbound data frame (AP → station).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame<'a> {
    pub to_ds: bool,
    pub from_ds: bool,
    pub qos: bool,
    /// True when an HT control field follows the QoS control field.
    pub ht_control: bool,
    /// `Address 1` (receiver).
    pub receiver: [u8; 6],
    /// `Address 2` (transmitter).
    pub transmitter: [u8; 6],
    /// `Address 3` (source/destination depending on the DS bits).
    pub address3: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// Build a data frame a station sends **to** its AP (`ToDS = 1`).
///
/// Per the ToDS address mapping: `Address 1 = BSSID (RA)`,
/// `Address 2 = source`, `Address 3 = destination`. A minimal station sends
/// every outbound frame to the AP's BSSID, so `destination` is normally the
/// BSSID too.
///
/// `protected` must be set when the hardware will encrypt the frame: mac80211
/// sets `IEEE80211_FCTL_PROTECTED` on every keyed frame before handing it to the
/// driver (`ieee80211_tx_set_protected`), and the AP discards a frame whose
/// Protected bit is clear even though its payload is CCMP ciphertext.
pub fn build_tx(
    bssid: &[u8; 6],
    source: &[u8; 6],
    destination: &[u8; 6],
    ethertype: u16,
    payload: &[u8],
    qos: bool,
    protected: bool,
) -> Vec<u8> {
    let subtype = if qos { SUBTYPE_QOS_DATA } else { SUBTYPE_DATA };
    let mut frame_control = (TYPE_DATA << 2) | (subtype << 4) | FC_TO_DS;
    if protected {
        frame_control |= FC_PROTECTED;
    }

    let mut frame = Vec::with_capacity(
        DATA_HEADER_LEN + if qos { QOS_CTRL_LEN } else { 0 } + LLC_SNAP_LEN + payload.len(),
    );
    frame.extend_from_slice(&frame_control.to_le_bytes());
    frame.extend_from_slice(&0u16.to_le_bytes()); // duration
    frame.extend_from_slice(bssid); // Address 1 (RA)
    frame.extend_from_slice(source); // Address 2 (TA)
    frame.extend_from_slice(destination); // Address 3 (DA)
    frame.extend_from_slice(&0u16.to_le_bytes()); // sequence control (HW assigns)
    if qos {
        frame.extend_from_slice(&0u16.to_le_bytes()); // QoS control, TID 0
    }
    frame.extend_from_slice(&LLC_SNAP_PREFIX);
    frame.extend_from_slice(&SNAP_ORG);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Parse an inbound 802.11 data frame, stripping the LLC/SNAP header.
///
/// Returns `None` for non-data frames, encrypted frames, or a missing
/// LLC/SNAP header.
pub fn parse(frame: &[u8]) -> Option<DataFrame<'_>> {
    parse_with(frame, false, false, false)
}

/// Parse a frame the hardware has already decrypted.
///
/// The Protected bit remains set in the header, but the payload is plaintext
/// with the IV/ICV stripped (`MT_RXINFO_DECRYPT`).
pub fn parse_decrypted(frame: &[u8]) -> Option<DataFrame<'_>> {
    parse_with(frame, true, false, false)
}

/// Length of the CCMP header (the IV) that precedes the L2 payload of a
/// protected frame.
pub const CCMP_HEADER_LEN: usize = 8;

/// Parse a frame from the RX path, given the RXWI flags.
///
/// `l2_pad` is `MT_RXINFO_L2PAD`: the hardware inserted two bytes after the
/// 802.11 header to align the L2 payload, so they must be skipped before the
/// LLC/SNAP header (`mt7601u_rx_skb_from_seg`: `data += hdr_len + 2`).
///
/// `crypto_header` is the hardware saying it left the CCMP IV in the frame
/// (`MT_RXINFO_PN_LEN` non-zero); it sits between the header (and any L2 pad)
/// and the LLC/SNAP header, so the parser must skip it too.
pub fn parse_rx(
    frame: &[u8],
    decrypted: bool,
    l2_pad: bool,
    crypto_header: bool,
) -> Option<DataFrame<'_>> {
    parse_with(frame, decrypted, l2_pad, crypto_header)
}

fn parse_with(
    frame: &[u8],
    decrypted: bool,
    l2_pad: bool,
    crypto_header: bool,
) -> Option<DataFrame<'_>> {
    if frame.len() < DATA_HEADER_LEN + LLC_SNAP_LEN {
        return None;
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    if (frame_control >> 2) & 0x3 != TYPE_DATA {
        return None;
    }
    let subtype = (frame_control >> 4) & 0xf;
    if subtype != SUBTYPE_DATA && subtype != SUBTYPE_QOS_DATA {
        return None;
    }
    if frame_control & FC_PROTECTED != 0 && !decrypted {
        // Encrypted and not decrypted in hardware.
        return None;
    }

    let qos = subtype == SUBTYPE_QOS_DATA;
    let ht_control = qos && frame_control & FC_ORDER != 0;
    let mut base = DATA_HEADER_LEN;
    if qos {
        base += QOS_CTRL_LEN;
        if ht_control {
            base += 4; // HT control field
        }
    }
    let mut offset = base;
    if l2_pad {
        offset += 2;
    }
    // A protected frame the hardware decrypted but did not strip still carries
    // its 8-byte CCMP header before the LLC/SNAP header.
    if crypto_header && frame_control & FC_PROTECTED != 0 {
        offset += CCMP_HEADER_LEN;
    }

    // Two things can sit between the 802.11 header and the LLC/SNAP header: two
    // bytes of L2 alignment padding (`MT_RXINFO_L2PAD`) and the 8-byte CCMP IV
    // (`MT_RXINFO_PN_LEN`). Neither can begin with the LLC/SNAP prefix, and the
    // hardware does not always report them, so for a protected frame that did
    // not land on the prefix, find it at the offsets it could be at.
    if frame_control & FC_PROTECTED != 0 && frame.get(offset..offset + 3) != Some(&LLC_SNAP_PREFIX)
    {
        offset = [
            base,
            base + 2,
            base + CCMP_HEADER_LEN,
            base + 2 + CCMP_HEADER_LEN,
        ]
        .into_iter()
        .find(|at| frame.get(*at..*at + 3) == Some(&LLC_SNAP_PREFIX))?;
    }
    if offset + LLC_SNAP_LEN > frame.len() {
        return None;
    }
    if frame[offset..offset + 3] != LLC_SNAP_PREFIX {
        return None;
    }

    let ethertype = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
    let payload = &frame[offset + LLC_SNAP_LEN..];

    let mut receiver = [0u8; 6];
    let mut transmitter = [0u8; 6];
    let mut address3 = [0u8; 6];
    receiver.copy_from_slice(&frame[4..10]);
    transmitter.copy_from_slice(&frame[10..16]);
    address3.copy_from_slice(&frame[16..22]);

    Some(DataFrame {
        to_ds: frame_control & FC_TO_DS != 0,
        from_ds: frame_control & FC_FROM_DS != 0,
        qos,
        ht_control,
        receiver,
        transmitter,
        address3,
        ethertype,
        payload,
    })
}

/// True when a data frame has the Protected bit set (encrypted).
pub fn is_encrypted(frame: &[u8]) -> bool {
    if frame.len() < 2 {
        return false;
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    (frame_control >> 2) & 0x3 == TYPE_DATA && frame_control & FC_PROTECTED != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR: [u8; 6] = [0x88, 0x82, 0x79, 0x24, 0x0e, 0xc0];
    const AP: [u8; 6] = [0x14, 0xcb, 0x49, 0x0d, 0x94, 0xec];
    const GW: [u8; 6] = [0x14, 0xcb, 0x49, 0x0d, 0x94, 0xed];

    #[test]
    fn build_tx_sets_tods_and_addresses() {
        let frame = build_tx(&AP, &OUR, &GW, ETHERTYPE_IPV4, &[0x45, 0x00], false, false);
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        assert_eq!((fc >> 2) & 0x3, TYPE_DATA);
        assert_eq!((fc >> 4) & 0xf, SUBTYPE_DATA);
        assert_ne!(fc & FC_TO_DS, 0);
        assert_eq!(&frame[4..10], &AP); // Address 1 = BSSID
        assert_eq!(&frame[10..16], &OUR); // Address 2 = source
        assert_eq!(&frame[16..22], &GW); // Address 3 = destination
        assert_eq!(&frame[24..27], &[0xaa, 0xaa, 0x03]);
        assert_eq!(&frame[28..30], &[0x00, 0x00]);
        assert_eq!(&frame[30..32], &[0x08, 0x00]); // EtherType IPv4
        assert_eq!(&frame[32..], &[0x45, 0x00]);
        assert_eq!(frame.len(), 24 + 8 + 2);
    }

    #[test]
    fn qos_build_adds_control_field() {
        let frame = build_tx(&AP, &OUR, &AP, ETHERTYPE_IPV4, &[1, 2, 3, 4], true, false);
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        assert_eq!((fc >> 4) & 0xf, SUBTYPE_QOS_DATA);
        assert_eq!(&frame[24..26], &[0, 0]); // QoS control
        assert_eq!(&frame[26..29], &[0xaa, 0xaa, 0x03]);
        assert_eq!(frame.len(), 24 + 2 + 8 + 4);
    }

    #[test]
    fn tx_then_parse_round_trips_the_payload() {
        let payload = [0x45, 0x00, 0x00, 0x28];
        let frame = build_tx(&AP, &OUR, &GW, ETHERTYPE_IPV4, &payload, false, false);
        let parsed = parse(&frame).expect("data frame");
        assert!(parsed.to_ds);
        assert!(!parsed.from_ds);
        assert_eq!(parsed.ethertype, ETHERTYPE_IPV4);
        assert_eq!(parsed.payload, &payload);
    }

    #[test]
    fn parses_a_from_ds_ipv6_frame() {
        let mut frame = build_tx(&AP, &OUR, &GW, ETHERTYPE_IPV6, &[0x60], true, false);
        // Flip it into an AP→STA frame.
        let mut fc = u16::from_le_bytes([frame[0], frame[1]]);
        fc = (fc & !FC_TO_DS) | FC_FROM_DS;
        frame[0..2].copy_from_slice(&fc.to_le_bytes());
        let parsed = parse(&frame).unwrap();
        assert!(parsed.from_ds);
        assert!(parsed.qos);
        assert_eq!(parsed.ethertype, ETHERTYPE_IPV6);
        assert_eq!(parsed.payload, &[0x60]);
    }

    #[test]
    fn rejects_encrypted_frames() {
        let mut frame = build_tx(&AP, &OUR, &GW, ETHERTYPE_IPV4, &[0; 4], false, false);
        let fc = u16::from_le_bytes([frame[0], frame[1]]) | FC_PROTECTED;
        frame[0..2].copy_from_slice(&fc.to_le_bytes());
        assert!(parse(&frame).is_none());
        assert!(is_encrypted(&frame));
    }

    #[test]
    fn rejects_non_data_and_truncated_frames() {
        let beacon = [0x80u8, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse(&beacon).is_none());
        assert!(parse(&[0u8; 12]).is_none());
        // A data frame missing the LLC/SNAP header.
        let mut frame = build_tx(&AP, &OUR, &GW, ETHERTYPE_IPV4, &[], false, false);
        frame.truncate(24);
        assert!(parse(&frame).is_none());
    }

    #[test]
    fn ht_control_field_shifts_the_payload() {
        let mut frame = build_tx(&AP, &OUR, &GW, ETHERTYPE_IPV4, &[9, 9], true, false);
        let fc = u16::from_le_bytes([frame[0], frame[1]]) | FC_ORDER;
        frame[0..2].copy_from_slice(&fc.to_le_bytes());
        frame.splice(26..26, [0u8; 4]); // insert HT control after QoS control
        let parsed = parse(&frame).unwrap();
        assert_eq!(parsed.payload, &[9, 9]);
        assert!(parsed.ht_control);
    }

    #[test]
    fn build_tx_flags_keyed_frames_as_protected() {
        // The hardware encrypts the payload, so the frame control must say so;
        // the AP discards a frame whose Protected bit is clear but whose
        // payload is ciphertext (this broke the DHCP DISCOVER).
        let plain = build_tx(&AP, &OUR, &GW, ETHERTYPE_IPV4, &[1], false, false);
        assert_eq!(u16::from_le_bytes([plain[0], plain[1]]) & FC_PROTECTED, 0);

        let protected = build_tx(&AP, &OUR, &GW, ETHERTYPE_IPV4, &[1], false, true);
        assert_ne!(
            u16::from_le_bytes([protected[0], protected[1]]) & FC_PROTECTED,
            0
        );
        assert!(is_encrypted(&protected));
    }
}
