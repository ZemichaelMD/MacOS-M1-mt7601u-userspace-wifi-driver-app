//! Station data path: payloads ⇄ 802.11 data frames over the USB transport.
//!
//! Wraps [`crate::wifi::data`] framing with the TXWI/DMA submission in
//! [`super::tx`] and the receive-segment parsing in [`super::rx`]. Frames the
//! hardware decrypted are accepted; frames that are still encrypted are dropped.

use std::time::{Duration, Instant};

use crate::net::{ipv4, IpLink};
use crate::usb::{Transport, UsbError};
use crate::wifi::{data, eapol};

use super::device::Mt7601u;
use super::mac::{GROUP_WCID_0, STA_WCID};
use super::{dma, rx, tx};

/// Read buffer for one bulk-IN transfer (`MT_RX_URB_SIZE`, `PAGE_SIZE <<
/// MT_RX_ORDER` = 16 KiB in `mt7601u.h`). Kept at the value the link is known to
/// run stably with: a short buffer can make the device's RX aggregation
/// overflow the transfer, but enlarging it perturbs the hardware and has not
/// been shown to help.
pub(crate) const RX_BUFFER_LEN: usize = 16384;

/// The addressing a data-path link needs: our MAC, the AP's BSSID and the two
/// WCID entries the hardware selects for unicast and group traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaLinkInfo {
    pub local_mac: [u8; 6],
    pub bssid: [u8; 6],
    /// WCID entry for the AP; unicast traffic uses its pairwise key.
    pub wcid: u8,
    /// Group WCID entry holding the GTK for broadcast/multicast traffic.
    pub group_wcid: u8,
    /// Send QoS data frames (set when the AP advertises WMM).
    pub qos: bool,
    /// Encrypt data frames in hardware (set once the WPA2 keys are installed).
    pub encrypted: bool,
}

impl StaLinkInfo {
    /// The common case: the AP is programmed at the station WCID (unicast) and
    /// the group WCID (broadcast/multicast), unencrypted.
    pub fn new(local_mac: [u8; 6], bssid: [u8; 6], qos: bool) -> Self {
        Self {
            local_mac,
            bssid,
            wcid: STA_WCID,
            group_wcid: GROUP_WCID_0,
            qos,
            encrypted: false,
        }
    }

    /// The same link, but with hardware encryption enabled.
    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }
}

/// A payload received from the AP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxPayload {
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

/// One received 802.11 data frame, recorded while a DHCP exchange is waiting.
///
/// The point of recording inside the receive loop (rather than reading the
/// adapter again after the timeout) is that the DHCP client consumes the frames
/// it rejects: a diagnostic pass that starts once `obtain` has given up can no
/// longer see an OFFER/ACK that arrived but was not parsed. This captures every
/// frame as it is seen, with the RXWI fields that say which key the hardware
/// used, so "the AP sent nothing" can be told apart from "we dropped the reply".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameTrace {
    pub type_: u8,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub protected: bool,
    pub receiver: [u8; 6],
    pub transmitter: [u8; 6],
    pub bssid: [u8; 6],
    /// `MT_RXWI_CTL_WCID`: the entry the hardware attributed the frame to.
    pub wcid: u8,
    /// `MT_RXWI_CTL_KEY_IDX`: the key index the hardware used.
    pub key_index: u8,
    pub decrypted: bool,
    pub l2_padded: bool,
    pub crc_error: bool,
    pub rxinfo: u32,
    pub mpdu_len: usize,
    pub len: usize,
    /// The EtherType, when the frame parsed as a data payload.
    pub ethertype: Option<u16>,
    /// Why the parser rejected the frame, when it did.
    pub rejection: Option<&'static str>,
    /// Offset of the first `aa aa 03` LLC/SNAP prefix anywhere in the frame, so
    /// a rejection can show where the header actually is.
    pub llc_at: Option<usize>,
    /// The first bytes of the frame, for diagnosing a rejection.
    pub head: Vec<u8>,
}

impl FrameTrace {
    /// One log line describing the frame.
    pub fn line(&self) -> String {
        format!(
            "type {} subtype {}, {} bytes (mpdu {}), rxinfo {:#010x} (decrypt {}, l2pad {}, crc {}), \
             protected {}, toDS {}, fromDS {}, rx {}, tx {}, bssid {}, wcid {}, key {}, \
             addr1 {}, addr2 {}, addr3 {}, {}",
            self.type_,
            self.subtype,
            self.len,
            self.mpdu_len,
            self.rxinfo,
            self.decrypted,
            self.l2_padded,
            self.crc_error,
            self.protected,
            self.to_ds,
            self.from_ds,
            mac(&self.receiver),
            mac(&self.transmitter),
            mac(&self.bssid),
            self.wcid,
            self.key_index,
            mac(&self.receiver),
            mac(&self.transmitter),
            mac(&self.bssid),
            match self.rejection {
                Some(reason) => format!(
                    "rejected: {reason}; llc_at {:?}; head {}",
                    self.llc_at,
                    hex(&self.head)
                ),
                None => format!(
                    "accepted, ethertype {:#06x}",
                    self.ethertype.unwrap_or(0)
                ),
            },
        )
    }
}

/// Hex dump of a short byte slice, for the frame trace.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn mac(address: &[u8; 6]) -> String {
    address
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl<T: Transport> Mt7601u<T> {
    /// Transmit `payload` to the AP (Address 3 = BSSID). Sent at the lowest
    /// OFDM rate.
    pub fn tx_payload(
        &self,
        info: &StaLinkInfo,
        ethertype: u16,
        payload: &[u8],
    ) -> Result<(), UsbError> {
        self.tx_payload_to(info, &info.bssid, ethertype, payload)
    }

    /// Transmit `payload` to an explicit destination MAC (Address 3).
    pub fn tx_payload_to(
        &self,
        info: &StaLinkInfo,
        destination: &[u8; 6],
        ethertype: u16,
        payload: &[u8],
    ) -> Result<(), UsbError> {
        let frame = data::build_tx(
            &info.bssid,
            &info.local_mac,
            destination,
            ethertype,
            payload,
            info.qos,
            // The hardware encrypts the payload, so the frame must be flagged
            // Protected; otherwise the AP reads the CCMP header as plaintext.
            info.encrypted,
        );
        // mac80211 supplies no station for a broadcast/multicast destination,
        // so the MT7601U reference driver selects the VIF's group WCID for it.
        // The AP station WCID continues to carry all unicast data.
        let wcid = if is_group_address(destination) {
            info.group_wcid
        } else {
            info.wcid
        };
        // The AP used for data is 802.11g/n-capable; use its lowest OFDM rate
        // until AP rate negotiation is implemented. The lowest rate is the most
        // robust but caps the link at 6 Mbps, so it can be raised with
        // `MT7601U_TX_MCS` (0–7) — the hardware's fallback tables step back down
        // when a frame is not acknowledged, which makes a higher rate a safe
        // experiment on a clean channel.
        let rate = tx::rate_val(tx::PHY_TYPE_OFDM, data_rate_mcs(), false, false);
        // mac80211 sets IEEE80211_TX_CTL_NO_ACK for multicast/broadcast, so the
        // driver must not ask the hardware for an ACK on a group-addressed
        // frame: there is no one to ACK it.
        let ack_req = !is_group_address(destination);
        let txwi = tx::build_txwi(frame.len(), wcid, rate, ack_req, true, false, 0);
        let endpoint = self.ac_endpoint(tx::AC_BE)?;
        // `no_encryption` sets the WIV flag (the frame carries its own IV); it
        // applies only when we are *not* using hardware encryption.
        self.tx_frame(&txwi, &frame, endpoint, dma::QSEL_EDCA, !info.encrypted)?;
        Ok(())
    }

    /// Transmit an IPv4 packet.
    ///
    /// Everything is addressed to the AP, including broadcast and multicast:
    /// the AP is the next hop, and it floods or consumes the frame. Addressing
    /// a broadcast IP packet to the *broadcast* MAC instead selects the group
    /// WCID (the GTK), and on this hardware/AP pair a group-key frame is not
    /// delivered — verified on the air: a broadcast ARP for the gateway is never
    /// answered, while the same ARP sent to the AP's MAC is answered at once.
    /// A unicast frame goes out on the station WCID (the pairwise TK), which the
    /// AP decrypts, and the AP's bridge/router takes it from there. This is also
    /// how a DHCP client works behind a relay: the L2 destination is the next
    /// hop, the IP destination stays a broadcast.
    pub fn tx_ipv4(&self, info: &StaLinkInfo, packet: &[u8]) -> Result<(), UsbError> {
        self.tx_payload_to(info, &info.bssid, data::ETHERTYPE_IPV4, packet)
    }

    /// Read inbound frames for up to `timeout`, returning the first payload of
    /// the requested EtherType sent by the AP to us.
    pub fn recv_payload(
        &self,
        info: &StaLinkInfo,
        timeout: Duration,
        want: u16,
    ) -> Option<RxPayload> {
        self.recv_matching(info, timeout, &|ethertype| ethertype == want)
    }

    /// Read the next inbound payload of *any* EtherType sent by the AP to us.
    ///
    /// The relay needs ARP as well as IPv4, so it cannot use the
    /// EtherType-filtered [`Self::recv_payload`] — that would discard the ARP
    /// replies the next hop is resolved from.
    pub fn recv_frame(&self, info: &StaLinkInfo, timeout: Duration) -> Option<RxPayload> {
        self.recv_matching(info, timeout, &|_| true)
    }

    /// The shared receive loop: read bulk-IN segments until a payload the
    /// predicate accepts arrives or `timeout` elapses.
    fn recv_matching(
        &self,
        info: &StaLinkInfo,
        timeout: Duration,
        accept: &dyn Fn(u16) -> bool,
    ) -> Option<RxPayload> {
        let endpoint = self.rx_endpoint().ok()?;
        let mut buffer = vec![0u8; RX_BUFFER_LEN];
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            let Ok(len) =
                self.transport()
                    .bulk_in(endpoint, &mut buffer, Duration::from_millis(50))
            else {
                continue;
            };
            if len < 2 {
                continue;
            }
            for segment in rx::parse_segments(&buffer[..len]) {
                if segment.rxwi.is_crc_error() {
                    continue;
                }
                // Record before deciding: this is the client's own receive loop,
                // and a reply it rejects would otherwise be lost before any
                // diagnostic pass could see it. Only data frames are recorded —
                // beacons alone would fill the trace — but everything the AP
                // sends *as data* (including EAPOL and its handshake messages) is
                // kept.
                if self.is_frame_trace_enabled() {
                    let entry = trace_segment(&segment, info);
                    if entry.type_ == 2 {
                        self.record_frame_trace(entry);
                    }
                }
                if let Some(payload) = payload_from_frame(
                    segment.payload,
                    info,
                    segment.rxwi.is_decrypted(),
                    segment.rxwi.is_l2_padded(),
                    segment.rxwi.has_crypto_header(),
                ) {
                    if accept(payload.ethertype) {
                        return Some(payload);
                    }
                }
            }
        }
        None
    }

    /// Read inbound IPv4 packets for up to `timeout`.
    pub fn recv_ipv4(&self, info: &StaLinkInfo, timeout: Duration) -> Option<Vec<u8>> {
        self.recv_payload(info, timeout, data::ETHERTYPE_IPV4)
            .map(|payload| payload.payload)
    }

    /// Read up to `max` inbound payloads, blocking up to `timeout` for the
    /// first.
    ///
    /// The device packs several RX frames into a single bulk transfer, so a
    /// reader that returns on the first frame throws away the rest of the
    /// window — which, under a TCP download, is most of what the link just
    /// received. This keeps *every* frame from each transfer.
    ///
    /// It deliberately reads **once** and only continues while the transfer
    /// filled the buffer (which means more is queued). A drain loop with a short
    /// timeout cancels the device's in-flight USB transfer many times a second;
    /// on this hardware that starves the receive path and eventually wedges the
    /// radio, so the timeout here should stay generous.
    pub fn recv_batch(&self, info: &StaLinkInfo, timeout: Duration, max: usize) -> Vec<RxPayload> {
        let Ok(endpoint) = self.rx_endpoint() else {
            return Vec::new();
        };
        let mut buffer = vec![0u8; RX_BUFFER_LEN];
        let mut out: Vec<RxPayload> = Vec::new();

        // The device delivers the buffer as one transfer; read again only while
        // it filled the buffer, which means more is queued. `while let` keeps
        // the "no more data" (error/timeout) path as the loop exit.
        while let Ok(len) = self.transport().bulk_in(endpoint, &mut buffer, timeout) {
            if len < 2 {
                break;
            }
            let filled = len >= buffer.len();

            for payload in self.parse_rx_buffer(&buffer[..len], info) {
                out.push(payload);
                if out.len() >= max {
                    return out;
                }
            }

            // A transfer that did not fill the buffer means the device had
            // nothing more queued, so stop rather than time out on another read.
            if !filled {
                break;
            }
        }
        out
    }

    /// Parse one raw receive buffer into the payloads it carries.
    ///
    /// This is the decode half of [`Self::recv_batch`], shared with the
    /// receive reader ([`crate::usb::RxPump`]) that keeps the bulk IN endpoint
    /// armed while the relay is up.
    pub(crate) fn parse_rx_buffer(&self, buffer: &[u8], info: &StaLinkInfo) -> Vec<RxPayload> {
        let mut out = Vec::new();
        for segment in rx::parse_segments(buffer) {
            if segment.rxwi.is_crc_error() {
                continue;
            }
            if self.is_frame_trace_enabled() {
                let entry = trace_segment(&segment, info);
                if entry.type_ == 2 {
                    self.record_frame_trace(entry);
                }
            }
            if let Some(payload) = payload_from_frame(
                segment.payload,
                info,
                segment.rxwi.is_decrypted(),
                segment.rxwi.is_l2_padded(),
                segment.rxwi.has_crypto_header(),
            ) {
                out.push(payload);
            }
        }
        out
    }
}

/// Cap on the frames a trace reports, so a long exchange cannot grow unbounded.
pub const MAX_TRACED_FRAMES: usize = 64;

/// True for a group (broadcast/multicast) MAC address — the I/G bit is set.
pub fn is_group_address(address: &[u8; 6]) -> bool {
    address[0] & 0x01 != 0
}

/// The OFDM MCS index data frames are sent at.
///
/// Defaults to 0 (6 Mbps, the most robust). `MT7601U_TX_MCS` (0–7) overrides it;
/// values outside that range are ignored. Read once and cached, since it is on
/// the per-packet transmit path.
pub fn data_rate_mcs() -> u8 {
    static MCS: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    *MCS.get_or_init(|| {
        std::env::var("MT7601U_TX_MCS")
            .ok()
            .and_then(|value| value.trim().parse::<u8>().ok())
            .filter(|mcs| *mcs <= 7)
            .unwrap_or(0)
    })
}

/// Extract a payload from a received 802.11 frame, if it is a data frame sent by
/// the AP to us. `decrypted` says whether the hardware already decrypted it;
/// `l2_pad` whether the hardware inserted two alignment bytes after the header;
/// `crypto_header` whether the CCMP IV is still in the frame.
pub fn payload_from_frame(
    frame: &[u8],
    info: &StaLinkInfo,
    decrypted: bool,
    l2_pad: bool,
    crypto_header: bool,
) -> Option<RxPayload> {
    analyse(frame, info, decrypted, l2_pad, crypto_header).ok()
}

/// Like [`payload_from_frame`], but says *why* a frame was rejected. Used by the
/// DHCP trace so a dropped reply is distinguishable from a missing one.
pub fn analyse(
    frame: &[u8],
    info: &StaLinkInfo,
    decrypted: bool,
    l2_pad: bool,
    crypto_header: bool,
) -> Result<RxPayload, &'static str> {
    if frame.len() < 2 {
        return Err("truncated frame");
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    if (frame_control >> 2) & 0x3 != 2 {
        return Err("not a data frame");
    }
    let subtype = (frame_control >> 4) & 0xf;
    if subtype != 0 && subtype != 8 {
        return Err("not a data frame");
    }
    // IEEE80211_FCTL_PROTECTED.
    if frame_control & 0x4000 != 0 && !decrypted {
        return Err("protected frame the hardware did not decrypt");
    }

    let parsed = data::parse_rx(frame, decrypted, l2_pad, crypto_header)
        .ok_or("no LLC/SNAP header at the expected offset")?;
    if !parsed.from_ds || parsed.to_ds {
        return Err("not a FromDS frame");
    }
    if parsed.transmitter != info.bssid {
        return Err("transmitter is not our AP");
    }
    // Accept frames addressed to us, plus group-addressed (broadcast/multicast)
    // frames such as a DHCP reply or an ARP request.
    if parsed.receiver != info.local_mac && !is_group_address(&parsed.receiver) {
        return Err("receiver is not us and not a group address");
    }

    let payload = match parsed.ethertype {
        data::ETHERTYPE_IPV4 => {
            // Trim the 4-byte segment padding using the IP total length.
            let total = ipv4::total_length(parsed.payload).ok_or("truncated IPv4 header")?;
            parsed.payload[..total].to_vec()
        }
        eapol::ETHERTYPE_EAPOL => {
            // Trim using the EAPOL length field: the MIC covers the PDU exactly.
            let length = u16::from_be_bytes([
                *parsed.payload.get(2).ok_or("truncated EAPOL header")?,
                *parsed.payload.get(3).ok_or("truncated EAPOL header")?,
            ]);
            let total = usize::from(length) + 4;
            if total > parsed.payload.len() {
                return Err("truncated EAPOL payload");
            }
            parsed.payload[..total].to_vec()
        }
        _ => parsed.payload.to_vec(),
    };

    Ok(RxPayload {
        ethertype: parsed.ethertype,
        payload,
    })
}

/// Describe one received segment for the DHCP trace.
pub fn trace_segment(segment: &rx::RxSegment<'_>, info: &StaLinkInfo) -> FrameTrace {
    let frame = segment.payload;
    let rxwi = segment.rxwi;
    let frame_control = if frame.len() >= 2 {
        u16::from_le_bytes([frame[0], frame[1]])
    } else {
        0
    };
    let address = |at: usize| -> [u8; 6] {
        let mut out = [0u8; 6];
        if frame.len() >= at + 6 {
            out.copy_from_slice(&frame[at..at + 6]);
        }
        out
    };
    let analysed = analyse(
        frame,
        info,
        rxwi.is_decrypted(),
        rxwi.is_l2_padded(),
        rxwi.has_crypto_header(),
    );

    FrameTrace {
        type_: ((frame_control >> 2) & 0x3) as u8,
        subtype: ((frame_control >> 4) & 0xf) as u8,
        to_ds: frame_control & 0x0100 != 0,
        from_ds: frame_control & 0x0200 != 0,
        protected: frame_control & 0x4000 != 0,
        receiver: address(4),
        transmitter: address(10),
        bssid: address(16),
        wcid: rxwi.wcid(),
        key_index: rxwi.key_index(),
        decrypted: rxwi.is_decrypted(),
        l2_padded: rxwi.is_l2_padded(),
        crc_error: rxwi.is_crc_error(),
        rxinfo: rxwi.rxinfo,
        mpdu_len: rxwi.mpdu_len(),
        len: frame.len(),
        ethertype: analysed.as_ref().ok().map(|payload| payload.ethertype),
        rejection: analysed.err(),
        // Where the LLC/SNAP prefix actually is, and the raw bytes, so a
        // rejection shows the real layout instead of just failing silently.
        llc_at: frame
            .windows(3)
            .position(|window| window == [0xaa, 0xaa, 0x03]),
        head: frame[..frame.len().min(64)].to_vec(),
    }
}

/// An [`IpLink`] backed by the MT7601U station.
pub struct StaLink<'a, T: Transport> {
    pub chip: &'a Mt7601u<T>,
    pub info: StaLinkInfo,
}

impl<'a, T: Transport> StaLink<'a, T> {
    pub fn new(chip: &'a Mt7601u<T>, info: StaLinkInfo) -> Self {
        Self { chip, info }
    }
}

impl<T: Transport> IpLink for StaLink<'_, T> {
    fn send_ipv4(&self, packet: &[u8]) -> Result<(), String> {
        self.chip
            .tx_ipv4(&self.info, packet)
            .map_err(|e| e.to_string())
    }

    fn recv_ipv4(&self, timeout: Duration) -> Option<Vec<u8>> {
        self.chip.recv_ipv4(&self.info, timeout)
    }

    fn recv_batch(&self, timeout: Duration, max: usize) -> Vec<Vec<u8>> {
        self.chip
            .recv_batch(&self.info, timeout, max)
            .into_iter()
            .filter(|payload| payload.ethertype == data::ETHERTYPE_IPV4)
            .map(|payload| payload.payload)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{device_info, MockTransport};

    const OUR: [u8; 6] = [0x88, 0x82, 0x79, 0x24, 0x0e, 0xc0];
    const AP: [u8; 6] = [0x14, 0xcb, 0x49, 0x0d, 0x94, 0xec];

    fn info() -> StaLinkInfo {
        StaLinkInfo::new(OUR, AP, false)
    }

    fn segment(payload: &[u8]) -> Vec<u8> {
        let dma_len = (rx::MIN_SEG_LEN + payload.len()).next_multiple_of(4);
        let mut seg = vec![0u8; dma::MT_DMA_HDRS + dma_len];
        seg[..2].copy_from_slice(&(dma_len as u16).to_le_bytes());
        seg[4 + rx::RXWI_LEN..4 + rx::RXWI_LEN + payload.len()].copy_from_slice(payload);
        seg
    }

    /// A data frame as the AP would send it (`FromDS = 1`): Address 1 is the
    /// receiver (us), Address 2 the transmitter (the AP).
    fn ap_data_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let frame_control: u16 = (2 << 2) | 0x0200; // type data, FromDS
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_control.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes()); // duration
        frame.extend_from_slice(&OUR); // Address 1 (receiver)
        frame.extend_from_slice(&AP); // Address 2 (transmitter)
        frame.extend_from_slice(&AP); // Address 3 (source)
        frame.extend_from_slice(&0u16.to_le_bytes()); // sequence
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Wrap a frame in a segment, optionally marking it hardware-decrypted.
    fn rx_segment(frame: &[u8], decrypted: bool) -> Vec<u8> {
        rx_segment_with(frame, decrypted, false)
    }

    /// Wrap a frame in a segment with explicit RXWI flags.
    fn rx_segment_with(frame: &[u8], decrypted: bool, l2_pad: bool) -> Vec<u8> {
        let mut rxinfo = 0u32;
        if decrypted {
            rxinfo |= 1 << 16; // MT_RXINFO_DECRYPT
        }
        if l2_pad {
            rxinfo |= 1 << 14; // MT_RXINFO_L2PAD
        }
        rx_segment_raw(frame, rxinfo)
    }

    /// Wrap a frame as the hardware reports a decrypted protected frame whose
    /// CCMP header it did *not* strip (`MT_RXINFO_DECRYPT | MT_RXINFO_PN_LEN`).
    /// The real MT7601U uses this for every CCMP reply from `HaLePo`.
    fn rx_segment_crypto(frame: &[u8]) -> Vec<u8> {
        rx_segment_raw(frame, (1 << 16) | (2 << 19))
    }

    fn rx_segment_raw(frame: &[u8], rxinfo: u32) -> Vec<u8> {
        let dma_len = (rx::MIN_SEG_LEN + frame.len()).next_multiple_of(4);
        let mut seg = vec![0u8; dma::MT_DMA_HDRS + dma_len];
        seg[..2].copy_from_slice(&(dma_len as u16).to_le_bytes());
        seg[4..8].copy_from_slice(&rxinfo.to_le_bytes());
        seg[4 + rx::RXWI_LEN..4 + rx::RXWI_LEN + frame.len()].copy_from_slice(frame);
        seg
    }

    /// A QoS data frame as the AP sends it: a 26-byte header means the hardware
    /// inserts two bytes of L2 padding before the LLC/SNAP header and sets
    /// `MT_RXINFO_L2PAD`.
    fn ap_qos_data_frame(ethertype: u16, payload: &[u8], padded: bool) -> Vec<u8> {
        let frame_control: u16 = (2 << 2) | (8 << 4) | 0x0200; // data, QoS, FromDS
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_control.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes()); // duration
        frame.extend_from_slice(&OUR); // Address 1 (receiver)
        frame.extend_from_slice(&AP); // Address 2 (transmitter)
        frame.extend_from_slice(&AP); // Address 3 (source)
        frame.extend_from_slice(&0u16.to_le_bytes()); // sequence
        frame.extend_from_slice(&0u16.to_le_bytes()); // QoS control
        if padded {
            frame.extend_from_slice(&[0x00, 0x00]);
        }
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// A protected FromDS frame whose 8-byte CCMP header is still present ahead
    /// of the LLC/SNAP header, as the hardware delivers it when it did not strip
    /// the IV (`MT_RXINFO_PN_LEN`): `[hdr][CCMP 8][LLC/SNAP][payload]`.
    fn ap_data_frame_with_ccmp(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let frame_control: u16 = (2 << 2) | 0x0200 | 0x4000; // data, FromDS, Protected
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_control.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes()); // duration
        frame.extend_from_slice(&OUR); // Address 1 (receiver)
        frame.extend_from_slice(&AP); // Address 2 (transmitter)
        frame.extend_from_slice(&AP); // Address 3 (source)
        frame.extend_from_slice(&0u16.to_le_bytes()); // sequence
        frame.extend_from_slice(&[0x01, 0x00, 0x00, 0x20, 0, 0, 0, 0]); // CCMP header
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn recv_accepts_a_l2_padded_qos_frame() {
        // The shape of a real DHCP OFFER: a decrypted QoS data frame with two
        // alignment bytes after the header. Ignoring MT_RXINFO_L2PAD used to
        // drop these, which is why DHCP never completed.
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::BROADCAST,
            0,
            ipv4::PROTO_UDP,
            &[7, 7, 7],
        );
        let mock = MockTransport::default();
        mock.push_rx_frame(rx_segment_with(
            &ap_qos_data_frame(data::ETHERTYPE_IPV4, &packet, true),
            true,
            true,
        ));
        let chip = Mt7601u::new(mock, device_info());

        assert_eq!(
            chip.recv_ipv4(&info(), Duration::from_millis(200)),
            Some(packet)
        );
    }

    #[test]
    fn recv_skips_the_ccmp_header_the_hardware_left_in_place() {
        // The hardware decrypts but, when MT_RXINFO_PN_LEN is set, does not strip
        // the 8-byte CCMP IV. Every CCMP reply from "HaLePo" looks like this; a
        // parser that expects the LLC/SNAP header at offset 24 rejects all of
        // them, which is what kept DHCP from ever completing.
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::BROADCAST,
            0,
            ipv4::PROTO_UDP,
            &[7, 7, 7],
        );
        let mock = MockTransport::default();
        mock.push_rx_frame(rx_segment_crypto(&ap_data_frame_with_ccmp(
            data::ETHERTYPE_IPV4,
            &packet,
        )));
        let chip = Mt7601u::new(mock, device_info());

        assert_eq!(
            chip.recv_ipv4(&info(), Duration::from_millis(200)),
            Some(packet)
        );
    }

    #[test]
    fn recv_rejects_a_padded_frame_without_the_flag() {
        // The padding is only there because the flag says so; without it the
        // same bytes must not be skipped (guards against over-skipping).
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            0,
            ipv4::PROTO_UDP,
            &[1],
        );
        let mock = MockTransport::default();
        mock.push_rx_frame(rx_segment_with(
            &ap_qos_data_frame(data::ETHERTYPE_IPV4, &packet, true),
            true,
            false,
        ));
        let chip = Mt7601u::new(mock, device_info());

        assert!(chip
            .recv_ipv4(&info(), Duration::from_millis(150))
            .is_none());
    }

    #[test]
    fn tx_ipv4_submits_a_data_frame_on_the_bulk_out_endpoint() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        chip.tx_ipv4(&info(), &[0x45, 0x00, 0x00, 0x14]).unwrap();

        let writes = chip.transport().bulk_writes.borrow();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, 0x05); // AC_BE
        let buffer = &writes[0].1;
        assert_eq!(buffer.len(), 4 + 20 + 36 + 4);
        let frame = &buffer[4 + 20..];
        assert_eq!(&frame[24..27], &[0xaa, 0xaa, 0x03]);
        assert_eq!(&frame[32..36], &[0x45, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn tx_with_encryption_clears_the_wiv_flag() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        chip.tx_ipv4(&info().encrypted(), &[0x45, 0x00, 0x00, 0x14])
            .unwrap();
        let writes = chip.transport().bulk_writes.borrow();
        let info_word = u32::from_le_bytes([
            writes[0].1[0],
            writes[0].1[1],
            writes[0].1[2],
            writes[0].1[3],
        ]);
        assert_eq!(info_word & dma::PKT_INFO_WIV, 0);
    }

    #[test]
    fn tx_with_encryption_sets_the_protected_bit() {
        // The hardware encrypts the payload, so the 802.11 header must flag the
        // frame Protected; the AP drops a keyed frame that is not flagged.
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        chip.tx_ipv4(&info().encrypted(), &[0x45, 0x00, 0x00, 0x14])
            .unwrap();
        let writes = chip.transport().bulk_writes.borrow();
        let frame = &writes[0].1[4 + 20..];
        assert!(data::is_encrypted(frame));
    }

    #[test]
    fn recv_batch_keeps_every_frame_in_an_aggregated_transfer() {
        // The device packs several RX frames into one bulk transfer. A reader
        // that returns on the first frame throws the rest of the window away,
        // which is what capped the tunnel's download rate.
        let first = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::new(192, 168, 1, 50),
            0,
            ipv4::PROTO_UDP,
            &[1, 1, 1],
        );
        let second = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::new(192, 168, 1, 51),
            0,
            ipv4::PROTO_UDP,
            &[2, 2, 2],
        );
        let mut buffer = segment(&ap_data_frame(data::ETHERTYPE_IPV4, &first));
        buffer.extend_from_slice(&segment(&ap_data_frame(data::ETHERTYPE_IPV4, &second)));

        let mock = MockTransport::default();
        mock.push_rx_frame(buffer);
        let chip = Mt7601u::new(mock, device_info());

        let batch = chip.recv_batch(&info(), Duration::from_millis(50), 16);
        assert_eq!(batch.len(), 2, "both frames in the transfer must survive");
        assert_eq!(batch[0].payload, first);
        assert_eq!(batch[1].payload, second);
    }

    #[test]
    fn recv_ipv4_returns_the_payload_of_an_ap_data_frame() {
        // A 25-byte packet: the segment padding must be trimmed back off.
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::new(192, 168, 1, 50),
            0,
            ipv4::PROTO_UDP,
            &[1, 2, 3, 4, 5],
        );
        assert_eq!(packet.len(), 25);

        let mock = MockTransport::default();
        mock.push_rx_frame(segment(&ap_data_frame(data::ETHERTYPE_IPV4, &packet)));
        let chip = Mt7601u::new(mock, device_info());

        let received = chip
            .recv_ipv4(&info(), Duration::from_millis(200))
            .expect("packet");
        assert_eq!(received, packet);
    }

    #[test]
    fn recv_ipv4_ignores_frames_from_other_stations() {
        let mock = MockTransport::default();
        let mut frame = ap_data_frame(data::ETHERTYPE_IPV4, &[0x45]);
        frame[4..10].copy_from_slice(&[0xaa; 6]);
        mock.push_rx_frame(segment(&frame));
        let chip = Mt7601u::new(mock, device_info());

        assert!(chip
            .recv_ipv4(&info(), Duration::from_millis(100))
            .is_none());
    }

    #[test]
    fn recv_accepts_a_hardware_decrypted_frame() {
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            0,
            ipv4::PROTO_UDP,
            &[7, 7],
        );
        let mut frame = ap_data_frame(data::ETHERTYPE_IPV4, &packet);
        // Mark it Protected, but have the RXWI say the hardware decrypted it.
        let fc = u16::from_le_bytes([frame[0], frame[1]]) | 0x4000;
        frame[0..2].copy_from_slice(&fc.to_le_bytes());

        let mock = MockTransport::default();
        mock.push_rx_frame(rx_segment(&frame, true));
        let chip = Mt7601u::new(mock, device_info());
        assert_eq!(
            chip.recv_ipv4(&info(), Duration::from_millis(200)),
            Some(packet)
        );
    }

    #[test]
    fn recv_accepts_an_eapol_frame_trimmed_to_its_length() {
        // EAPOL: version 2, type 3, length 8, then 8 bytes of body.
        let mut eapol = vec![2u8, 3, 0, 8];
        eapol.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let mock = MockTransport::default();
        mock.push_rx_frame(segment(&ap_data_frame(eapol::ETHERTYPE_EAPOL, &eapol)));
        let chip = Mt7601u::new(mock, device_info());

        let payload = chip
            .recv_payload(&info(), Duration::from_millis(200), eapol::ETHERTYPE_EAPOL)
            .expect("eapol");
        assert_eq!(payload.payload, eapol);
    }

    #[test]
    fn recv_accepts_a_broadcast_addressed_frame() {
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::BROADCAST,
            0,
            ipv4::PROTO_UDP,
            &[4, 4, 4],
        );
        let mut frame = ap_data_frame(data::ETHERTYPE_IPV4, &packet);
        frame[4..10].copy_from_slice(&[0xff; 6]); // Address 1 = broadcast

        let mock = MockTransport::default();
        mock.push_rx_frame(segment(&frame));
        let chip = Mt7601u::new(mock, device_info());
        assert_eq!(
            chip.recv_ipv4(&info(), Duration::from_millis(200)),
            Some(packet)
        );
    }

    #[test]
    fn tx_ipv4_addresses_broadcast_traffic_to_the_ap() {
        // A broadcast IP packet is carried to the AP, not to the broadcast MAC:
        // the AP is the next hop, and framing it on the group WCID (the GTK) is
        // what made every DHCPDISCOVER and ARP silently die on real hardware.
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        let packet = ipv4::build(
            std::net::Ipv4Addr::UNSPECIFIED,
            std::net::Ipv4Addr::BROADCAST,
            0,
            ipv4::PROTO_UDP,
            &[1, 2, 3],
        );
        chip.tx_ipv4(&info(), &packet).unwrap();

        let writes = chip.transport().bulk_writes.borrow();
        let frame = &writes[0].1[4 + 20..];
        assert_eq!(&frame[4..10], &AP); // Address 1 (RA) = BSSID
        assert_eq!(&frame[16..22], &AP); // Address 3 (DA) = the AP, the next hop
                                         // Unicast framing: the AP's station WCID (pairwise key) and an ACK.
        assert_eq!(writes[0].1[4 + 5], STA_WCID);
        assert_ne!(
            writes[0].1[4 + 4] & 0x1,
            0,
            "a unicast frame asks for an ACK"
        );
        assert_eq!(
            writes[0].1[4 + 4] & 0x2,
            0x2,
            "the hardware assigns the sequence"
        );
    }

    #[test]
    fn tx_ipv4_addresses_unicast_to_the_bssid() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 50),
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            0,
            ipv4::PROTO_UDP,
            &[1, 2, 3],
        );
        chip.tx_ipv4(&info(), &packet).unwrap();

        let writes = chip.transport().bulk_writes.borrow();
        let frame = &writes[0].1[4 + 20..];
        assert_eq!(&frame[16..22], &AP);
        // Unicast traffic is framed on the AP's station WCID (pairwise key).
        assert_eq!(writes[0].1[4 + 5], STA_WCID);
    }

    #[test]
    fn payload_from_frame_rejects_encrypted_without_a_decrypt_flag() {
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            0,
            ipv4::PROTO_UDP,
            &[1, 2],
        );
        let frame = ap_data_frame(data::ETHERTYPE_IPV4, &packet);
        assert!(payload_from_frame(&frame, &info(), false, false, false).is_some());

        let mut protected = frame.clone();
        let fc = u16::from_le_bytes([protected[0], protected[1]]) | 0x4000;
        protected[0..2].copy_from_slice(&fc.to_le_bytes());
        assert!(payload_from_frame(&protected, &info(), false, false, false).is_none());
        assert!(payload_from_frame(&protected, &info(), true, false, false).is_some());
    }

    #[test]
    fn analyse_explains_every_rejection() {
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            0,
            ipv4::PROTO_UDP,
            &[1, 2],
        );
        assert!(analyse(&packet[..12], &info(), true, false, false).is_err());
        // A beacon is not a data frame.
        let beacon = [0x80u8, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            analyse(&beacon, &info(), true, false, false),
            Err("not a data frame")
        );
        // Protected frames the hardware did not decrypt are the DHCP-reply case.
        let mut protected = ap_data_frame(data::ETHERTYPE_IPV4, &packet);
        let fc = u16::from_le_bytes([protected[0], protected[1]]) | 0x4000;
        protected[0..2].copy_from_slice(&fc.to_le_bytes());
        assert_eq!(
            analyse(&protected, &info(), false, false, false),
            Err("protected frame the hardware did not decrypt")
        );
        // A frame from another transmitter.
        let mut other = ap_data_frame(data::ETHERTYPE_IPV4, &packet);
        other[10..16].copy_from_slice(&[0xaa; 6]);
        assert_eq!(
            analyse(&other, &info(), true, false, false),
            Err("transmitter is not our AP")
        );
    }

    #[test]
    fn the_dhcp_trace_records_frames_the_client_rejects() {
        // A protected reply the hardware did not decrypt: the client drops it,
        // but the trace must still show it, with the RXWI WCID/key that the
        // hardware used. This is the frame a "no DHCP response" report needs.
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::BROADCAST,
            0,
            ipv4::PROTO_UDP,
            &[1, 2, 3],
        );
        let mut frame = ap_data_frame(data::ETHERTYPE_IPV4, &packet);
        let fc = u16::from_le_bytes([frame[0], frame[1]]) | 0x4000;
        frame[0..2].copy_from_slice(&fc.to_le_bytes());

        let mock = MockTransport::default();
        mock.push_rx_frame(rx_segment(&frame, false));
        let chip = Mt7601u::new(mock, device_info());

        chip.start_frame_trace();
        assert!(chip
            .recv_ipv4(&info(), Duration::from_millis(100))
            .is_none());
        chip.stop_frame_trace();

        let trace = chip.frame_trace();
        assert_eq!(trace.len(), 1, "the rejected reply must still be recorded");
        assert!(trace[0].protected);
        assert!(!trace[0].decrypted);
        assert_eq!(
            trace[0].rejection,
            Some("protected frame the hardware did not decrypt")
        );
        assert_eq!(trace[0].receiver, OUR);
        assert!(trace[0].line().contains("rejected"));
    }

    #[test]
    fn the_dhcp_trace_records_an_accepted_reply_with_its_ethertype() {
        let packet = ipv4::build(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::new(192, 168, 1, 50),
            0,
            ipv4::PROTO_UDP,
            &[4, 5, 6],
        );
        let mock = MockTransport::default();
        mock.push_rx_frame(segment(&ap_data_frame(data::ETHERTYPE_IPV4, &packet)));
        let chip = Mt7601u::new(mock, device_info());

        chip.start_frame_trace();
        assert!(chip
            .recv_ipv4(&info(), Duration::from_millis(100))
            .is_some());
        chip.stop_frame_trace();

        let trace = chip.frame_trace();
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].ethertype, Some(data::ETHERTYPE_IPV4));
        assert_eq!(trace[0].rejection, None);
        assert_eq!(trace[0].type_, 2);
        assert!(trace[0].from_ds);
    }

    /// The DHCPDISCOVER descriptor, pinned against the hardware: the frame is
    /// carried to the AP on the station WCID (pairwise TK) with the Protected
    /// bit set and the WIV flag clear, so the hardware encrypts it with the key
    /// the AP can actually decrypt. Framing it on the group WCID (the GTK) with
    /// the broadcast MAC as Address 3 is what the reference driver does when
    /// mac80211 has no destination station — and what this AP never answers.
    #[test]
    fn dhcp_discover_tx_descriptor_matches_the_hardware() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        let discover = crate::net::dhcp::to_broadcast(
            &crate::net::dhcp::build_discover(0x1234_5678, &OUR),
            68,
            67,
        );
        chip.tx_ipv4(&info().encrypted(), &discover).unwrap();

        let writes = chip.transport().bulk_writes.borrow();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, 0x05, "AC_BE bulk OUT endpoint");

        let buffer = &writes[0].1;
        let info_word = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        assert_eq!(info_word >> 30, dma::INFO_TYPE_DMA_PACKET);
        assert_eq!((info_word >> 27) & 0x7, dma::PORT_WLAN);
        assert_ne!(info_word & dma::PKT_INFO_80211, 0);
        // The hardware encrypts, so the WIV flag must be clear.
        assert_eq!(info_word & dma::PKT_INFO_WIV, 0);
        assert_eq!(
            (info_word >> dma::PKT_INFO_QSEL_SHIFT) & 0x3,
            dma::QSEL_EDCA
        );
        // LEN is the 4-byte-rounded TXWI + 802.11 frame length.
        let payload_len = 20 + 24 + 8 + discover.len();
        assert_eq!(info_word & 0xffff, payload_len.next_multiple_of(4) as u32);

        let txwi = &buffer[4..4 + tx::TXWI_LEN];
        assert_eq!(txwi[5], STA_WCID, "the AP carries the frame");
        assert_ne!(txwi[4] & 0x1, 0, "a unicast frame asks for an ACK");
        assert_ne!(txwi[4] & 0x2, 0, "the hardware assigns the sequence");

        let frame = &buffer[4 + tx::TXWI_LEN..];
        assert_eq!(&frame[4..10], &AP); // Address 1 (RA) = BSSID
        assert_eq!(&frame[10..16], &OUR); // Address 2 (TA) = us
        assert_eq!(&frame[16..22], &AP); // Address 3 (DA) = the AP
        assert_ne!(
            u16::from_le_bytes([frame[0], frame[1]]) & 0x4000,
            0,
            "the Protected bit must be set on a keyed frame"
        );
        assert_eq!(&frame[24..27], &[0xaa, 0xaa, 0x03]);
        assert_eq!(&frame[30..32], &[0x08, 0x00]);
        // The DHCP payload keeps its 255.255.255.255 destination: only the L2
        // address changes, so the AP delivers it to the DHCP server as a
        // broadcast.
        assert_eq!(&frame[32..32 + discover.len()], discover.as_slice());
        let ip = crate::net::ipv4::parse(&discover).expect("IPv4");
        assert!(ip.destination.is_broadcast());
    }
}
