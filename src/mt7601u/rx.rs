//! RX path parsing: DMA segments, RXWI and 802.11 management frames.
//!
//! Transcribed from `dma.c` (`mt7601u_rx_process_seg`,
//! `mt7601u_rx_next_seg_len`) and the `struct mt7601u_rxwi` layout in `mac.h`.

use super::dma;

/// `sizeof(struct mt7601u_rxwi)`.
pub const RXWI_LEN: usize = 28;
/// Minimum DMA segment length accepted by `mt7601u_rx_next_seg_len`.
pub const MIN_SEG_LEN: usize =
    dma::MT_DMA_HDR_LEN + dma::MT_RX_INFO_LEN + RXWI_LEN + dma::MT_FCE_INFO_LEN;

/// `struct mt7601u_rxwi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rxwi {
    pub rxinfo: u32,
    pub ctl: u32,
    pub frag_sn: u16,
    pub rate: u16,
    pub snr: u8,
    pub ant: u8,
    pub gain: u8,
    pub freq_off: u8,
}

// `MT_RXINFO_*` (mac.h).
const RXINFO_DATA: u32 = 1 << 1;
const RXINFO_CRCERR: u32 = 1 << 8;
const RXINFO_L2PAD: u32 = 1 << 14;
const RXINFO_DECRYPT: u32 = 1 << 16;
/// `MT_RXINFO_PN_LEN` (`GENMASK(21, 19)`).
const RXINFO_PN_LEN: u32 = 0x7 << 19;

// `MT_RXWI_CTL_*` (mac.h).
const CTL_WCID: u32 = 0xff;
const CTL_KEY_IDX: u32 = 0x3 << 8;
const CTL_KEY_IDX_SHIFT: u32 = 8;
const CTL_MPDU_LEN: u32 = 0xfff << 16;
const CTL_MPDU_LEN_SHIFT: u32 = 16;

impl Rxwi {
    /// Parse the RXWI from the start of a segment payload region.
    pub fn parse(data: &[u8]) -> Option<Rxwi> {
        if data.len() < RXWI_LEN {
            return None;
        }
        Some(Rxwi {
            rxinfo: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            ctl: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            frag_sn: u16::from_le_bytes([data[8], data[9]]),
            rate: u16::from_le_bytes([data[10], data[11]]),
            snr: data[16],
            ant: data[17],
            gain: data[18],
            freq_off: data[19],
        })
    }

    /// True for a data frame (`MT_RXINFO_DATA`).
    pub fn is_data(&self) -> bool {
        self.rxinfo & RXINFO_DATA != 0
    }

    /// True when the hardware flagged a CRC error (`MT_RXINFO_CRCERR`).
    pub fn is_crc_error(&self) -> bool {
        self.rxinfo & RXINFO_CRCERR != 0
    }

    /// True when the hardware decrypted the frame (`MT_RXINFO_DECRYPT`), so the
    /// payload is plaintext with the IV/ICV already stripped.
    pub fn is_decrypted(&self) -> bool {
        self.rxinfo & RXINFO_DECRYPT != 0
    }

    /// True when the hardware inserted two bytes of padding after the 802.11
    /// header (`MT_RXINFO_L2PAD`) to 4-byte-align the L2 payload. This happens
    /// for QoS data frames, whose header is 26 bytes; the parser must skip the
    /// two bytes (`mt7601u_rx_skb_from_seg` does `data += hdr_len + 2`).
    pub fn is_l2_padded(&self) -> bool {
        self.rxinfo & RXINFO_L2PAD != 0
    }

    /// True when the hardware left the crypto header (the 8-byte CCMP IV) in
    /// the frame, so the payload starts 8 bytes later.
    ///
    /// A decrypted frame only has its IV stripped when `MT_RXINFO_PN_LEN` is
    /// zero. `mt7601u` mirrors this: it sets `RX_FLAG_IV_STRIPPED` when it
    /// decrypts, then clears it again for a non-zero `MT_RXINFO_PN_LEN`, which
    /// leaves the CCMP header for mac80211 to strip.
    pub fn has_crypto_header(&self) -> bool {
        self.rxinfo & RXINFO_PN_LEN != 0
    }

    /// `MT_RXWI_CTL_WCID`: the WCID the hardware attributed this frame to. This
    /// is what selects the key used to decrypt it.
    pub fn wcid(&self) -> u8 {
        (self.ctl & CTL_WCID) as u8
    }

    /// `MT_RXWI_CTL_KEY_IDX`: the key index the hardware used for this frame.
    pub fn key_index(&self) -> u8 {
        ((self.ctl & CTL_KEY_IDX) >> CTL_KEY_IDX_SHIFT) as u8
    }

    /// `MT_RXWI_CTL_MPDU_LEN`: the on-air MPDU length the hardware measured.
    pub fn mpdu_len(&self) -> usize {
        ((self.ctl & CTL_MPDU_LEN) >> CTL_MPDU_LEN_SHIFT) as usize
    }
}

/// One DMA segment: an RXWI plus the 802.11 payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxSegment<'a> {
    pub fce_info: u32,
    pub rxwi: Rxwi,
    pub payload: &'a [u8],
}

/// Split a bulk-IN buffer into DMA segments (`mt7601u_rx_process_entry`).
///
/// The first two bytes of each segment hold the little-endian segment length;
/// the FCE descriptor is the last 4 bytes; the RXWI follows the 4-byte DMA
/// header.
pub fn parse_segments(data: &[u8]) -> Vec<RxSegment<'_>> {
    let mut segments = Vec::new();
    let mut offset = 0usize;

    while offset + 2 <= data.len() {
        let dma_len = usize::from(u16::from_le_bytes([data[offset], data[offset + 1]]));
        let remaining = data.len() - offset;
        if dma_len == 0
            || dma_len + dma::MT_DMA_HDRS > remaining
            || dma_len & 0x3 != 0
            || dma_len < MIN_SEG_LEN
        {
            break;
        }

        let seg_len = dma::MT_DMA_HDRS + dma_len;
        let segment = &data[offset..offset + seg_len];

        let fce_info = u32::from_le_bytes([
            segment[seg_len - 4],
            segment[seg_len - 3],
            segment[seg_len - 2],
            segment[seg_len - 1],
        ]);

        let rxwi_start = dma::MT_DMA_HDR_LEN;
        let payload_start = rxwi_start + RXWI_LEN;
        let payload_end = seg_len - dma::MT_FCE_INFO_LEN;

        if let Some(rxwi) = Rxwi::parse(&segment[rxwi_start..payload_start]) {
            segments.push(RxSegment {
                fce_info,
                rxwi,
                payload: &segment[payload_start..payload_end],
            });
        }

        offset += seg_len;
    }

    segments
}

/// A decoded beacon / probe-response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BssInfo {
    pub bssid: [u8; 6],
    pub ssid: String,
    pub channel: Option<u8>,
    pub capability: u16,
    /// Beacon interval in time units (TU), from the beacon's fixed fields.
    pub beacon_interval: u16,
    pub has_rsn: bool,
    pub has_wpa: bool,
    /// The raw RSN information element (id 48 including the tag and length),
    /// so the caller can tell WPA3 (SAE) from WPA2-PSK networks.
    pub rsn_ie: Option<Vec<u8>>,
}

impl BssInfo {
    /// BSSID formatted `aa:bb:cc:dd:ee:ff`.
    pub fn bssid_string(&self) -> String {
        self.bssid
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Parse an 802.11 beacon (subtype 8) or probe response (subtype 5).
pub fn parse_beacon(payload: &[u8]) -> Option<BssInfo> {
    if payload.len() < 24 + 12 {
        return None;
    }

    let frame_control = u16::from_le_bytes([payload[0], payload[1]]);
    let frame_type = (frame_control >> 2) & 0x3;
    let subtype = (frame_control >> 4) & 0xf;
    if frame_type != 0 || (subtype != 8 && subtype != 5) {
        return None;
    }

    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(&payload[16..22]);

    // Fixed parameters: timestamp(8) + beacon interval(2) + capability(2).
    let beacon_interval = u16::from_le_bytes([payload[32], payload[33]]);
    let capability = u16::from_le_bytes([payload[34], payload[35]]);
    let mut channel = None;
    let mut has_rsn = false;
    let mut has_wpa = false;
    let mut rsn_ie = None;
    // The RX payload is zero-padded to a 4-byte boundary. Keep the first
    // SSID/channel IE so trailing padding is not read as an empty tag.
    let mut ssid: Option<String> = None;

    let mut cursor = 36usize;
    while cursor + 2 <= payload.len() {
        let id = payload[cursor];
        let len = usize::from(payload[cursor + 1]);
        let start = cursor + 2;
        let end = start + len;
        if end > payload.len() {
            break;
        }
        let body = &payload[start..end];

        match id {
            0 if ssid.is_none() => ssid = Some(String::from_utf8_lossy(body).into_owned()),
            3 if channel.is_none() => channel = body.first().copied(),
            48 if rsn_ie.is_none() => {
                has_rsn = true;
                rsn_ie = Some(payload[cursor..end].to_vec());
            }
            221 if len >= 4 && body[..4] == [0x00, 0x50, 0xf2, 0x01] => has_wpa = true,
            _ => {}
        }

        cursor = end;
    }

    Some(BssInfo {
        bssid,
        ssid: ssid.unwrap_or_default(),
        channel,
        capability,
        beacon_interval,
        has_rsn,
        has_wpa,
        rsn_ie,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(payload: &[u8]) -> Vec<u8> {
        let dma_len = (MIN_SEG_LEN + payload.len()).next_multiple_of(4);
        let mut seg = vec![0u8; dma::MT_DMA_HDRS + dma_len];
        seg[..2].copy_from_slice(&(dma_len as u16).to_le_bytes());
        seg[4 + RXWI_LEN..4 + RXWI_LEN + payload.len()].copy_from_slice(payload);
        seg
    }

    fn beacon_frame(ssid: &str, channel: u8) -> Vec<u8> {
        let mut frame = vec![0u8; 36];
        frame[0] = 0x80; // beacon
        frame[16..22].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame[32..34].copy_from_slice(&100u16.to_le_bytes()); // beacon interval
        frame.extend_from_slice(&[0x00, ssid.len() as u8]);
        frame.extend_from_slice(ssid.as_bytes());
        frame.extend_from_slice(&[0x03, 0x01, channel]);
        frame
    }

    #[test]
    fn parses_a_beacon_segment() {
        let frame = beacon_frame("test-net", 6);
        let buffer = segment(&frame);
        let segments = parse_segments(&buffer);
        assert_eq!(segments.len(), 1);

        let bss = parse_beacon(segments[0].payload).expect("beacon parsed");
        assert_eq!(bss.ssid, "test-net");
        assert_eq!(bss.channel, Some(6));
        assert_eq!(bss.beacon_interval, 100);
        assert_eq!(bss.bssid, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!bss.has_rsn);
    }

    #[test]
    fn detects_rsn_security() {
        let mut frame = beacon_frame("secure", 1);
        // RSN information element (id 48).
        frame.extend_from_slice(&[48, 2, 0x01, 0x00]);
        let bss = parse_beacon(&frame).unwrap();
        assert!(bss.has_rsn);
    }

    #[test]
    fn rejects_non_beacon_frames() {
        let mut frame = beacon_frame("x", 1);
        frame[0] = 0x08; // data frame
        assert!(parse_beacon(&frame).is_none());
    }

    #[test]
    fn stops_on_malformed_segment() {
        let buffer = [0u8; 4];
        assert!(parse_segments(&buffer).is_empty());
    }

    #[test]
    fn parses_two_concatenated_segments() {
        let mut buffer = segment(&beacon_frame("a", 1));
        buffer.extend_from_slice(&segment(&beacon_frame("b", 2)));
        let segments = parse_segments(&buffer);
        assert_eq!(segments.len(), 2);
        assert_eq!(parse_beacon(segments[1].payload).unwrap().ssid, "b");
    }

    #[test]
    fn rxwi_flags() {
        let mut data = [0u8; RXWI_LEN];
        data[0] = 0x02; // MT_RXINFO_DATA
        let rxwi = Rxwi::parse(&data).unwrap();
        assert!(rxwi.is_data());
        assert!(!rxwi.is_crc_error());
    }
}
