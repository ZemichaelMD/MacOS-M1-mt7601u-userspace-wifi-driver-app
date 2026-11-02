//! TX path: TXWI construction and bulk-OUT submission.
//!
//! Transcribed from `tx.c` (`mt7601u_push_txwi`, `mt7601u_tx`),
//! `dma.c` (`mt7601u_dma_enqueue_tx`) and `mac.h` (`struct mt76_txwi`).
//!
//! Buffer layout on the bulk OUT endpoint:
//! `[4B DMA info][TXWI 20B][802.11 frame][pad to 4B][4B zero]`.

use std::time::{Duration, Instant};

use crate::usb::{Transport, UsbError, UsbTransferType};

use super::device::Mt7601u;
use super::dma;
use super::regs;

/// `sizeof(struct mt76_txwi)`.
pub const TXWI_LEN: usize = 20;

/// Timeout for one bulk-OUT transfer.
const TX_TIMEOUT: Duration = Duration::from_millis(1000);

/// Cap on the entries one [`Mt7601u::drain_tx_status`] call reads. A full FIFO
/// is worked off over a few relay iterations rather than in one long hold of
/// the loop.
pub const TX_STATUS_DRAIN_MAX: usize = 64;

/// One `MT_TX_STAT_FIFO` entry (`struct mt76_tx_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxStatus {
    /// `MT_TX_STAT_FIFO_VALID`: the popped entry is real; an empty FIFO reads 0.
    pub valid: bool,
    /// `MT_TX_STAT_FIFO_SUCCESS`: the frame was acknowledged.
    pub success: bool,
    /// `MT_TX_STAT_FIFO_PID_TYPE`: the packet id the frame was sent with.
    pub pktid: u8,
    /// `MT_TX_STAT_FIFO_WCID`: the wireless client index used.
    pub wcid: u8,
    /// `MT_TX_STAT_FIFO_RATE`: the rate the frame finally went out at.
    pub rate: u16,
}

/// Totals from one `Mt7601u::drain_tx_status` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxStatusTotals {
    /// Entries popped from the FIFO.
    pub drained: u32,
    /// Popped entries whose frame was never acknowledged.
    pub failed: u32,
}

// `MT_TXWI_LEN_*` (mac.h).
const TXWI_LEN_BYTE_CNT: u16 = 0x0fff;
const TXWI_LEN_PKTID: u16 = 0x000f;
const TXWI_LEN_PKTID_SHIFT: u16 = 12;

// `MT_TXWI_ACK_CTL_*` (mac.h).
const TXWI_ACK_CTL_REQ: u8 = 1 << 0;
const TXWI_ACK_CTL_NSEQ: u8 = 1 << 1;

// `enum mt76_phy_type` (mac.h).
/// CCK.
pub const PHY_TYPE_CCK: u16 = 0;
/// OFDM.
pub const PHY_TYPE_OFDM: u16 = 1;
/// HT (mixed).
pub const PHY_TYPE_HT: u16 = 2;
/// HT (greenfield).
pub const PHY_TYPE_HT_GF: u16 = 3;

/// `MT_TXWI_RATE_*` field positions.
const RATE_MCS_MASK: u16 = 0x7f;
const RATE_BW_SHIFT: u16 = 7;
const RATE_SGI_SHIFT: u16 = 8;
const RATE_PHY_SHIFT: u16 = 14;

/// Access categories, in mac80211 order (`enum ieee80211_ac_numbers`).
pub const AC_VO: u8 = 0;
/// Video.
pub const AC_VI: u8 = 1;
/// Best effort.
pub const AC_BE: u8 = 2;
/// Background.
pub const AC_BK: u8 = 3;

/// Encode a rate into `rate_ctl` (`mt76_mac_tx_rate_val`).
pub fn rate_val(phy: u16, index: u8, bw40: bool, short_gi: bool) -> u16 {
    (u16::from(index) & RATE_MCS_MASK)
        | (u16::from(bw40) << RATE_BW_SHIFT)
        | (u16::from(short_gi) << RATE_SGI_SHIFT)
        | ((phy & 0x3) << RATE_PHY_SHIFT)
}

/// `mt7601u_tx_pktid_enc`: only 15 packet ids are available because 0 disables
/// status reporting.
pub fn pkt_id(rate_ctl: u16, is_probe: bool) -> u8 {
    let rate = (rate_ctl & RATE_MCS_MASK) as u8;
    let encoded = (rate + 1) + if is_probe { 8 } else { 0 };
    // MCS0 and MCS7-with-probe share packet id 9.
    if is_probe && rate == 7 {
        encoded - 7
    } else {
        encoded
    }
}

/// Build the 20-byte TXWI that precedes an 802.11 frame.
///
/// `frame_len` is the length of the 802.11 frame itself (not including the
/// TXWI). `flags` carries the `MT_TXWI_FLAGS_*` bits (AMPDU etc.), zero for a
/// plain management frame.
#[allow(clippy::too_many_arguments)]
pub fn build_txwi(
    frame_len: usize,
    wcid: u8,
    rate_ctl: u16,
    ack_req: bool,
    assign_seq: bool,
    is_probe: bool,
    flags: u16,
) -> [u8; TXWI_LEN] {
    let mut txwi = [0u8; TXWI_LEN];

    txwi[0..2].copy_from_slice(&flags.to_le_bytes());
    txwi[2..4].copy_from_slice(&rate_ctl.to_le_bytes());

    let mut ack_ctl = 0u8;
    if ack_req {
        ack_ctl |= TXWI_ACK_CTL_REQ;
    }
    if assign_seq {
        ack_ctl |= TXWI_ACK_CTL_NSEQ;
    }
    txwi[4] = ack_ctl;
    txwi[5] = wcid;

    let len_ctl = ((frame_len as u16) & TXWI_LEN_BYTE_CNT)
        | ((u16::from(pkt_id(rate_ctl, is_probe)) & TXWI_LEN_PKTID) << TXWI_LEN_PKTID_SHIFT);
    txwi[6..8].copy_from_slice(&len_ctl.to_le_bytes());

    // iv, eiv, aid, txstream, ctl stay zero (no hardware encryption).
    txwi
}

impl<T: Transport> Mt7601u<T> {
    /// Bulk OUT endpoint for an access category: `q2ep(q2hwq(ac))` with
    /// `q2hwq(q) = q ^ 3` and `q2ep(q) = q + 1`, indexing the OUT endpoints in
    /// descriptor order.
    pub fn ac_endpoint(&self, ac: u8) -> Result<u8, UsbError> {
        let hardware_queue = ac ^ 0x3;
        let index = usize::from(hardware_queue) + 1;
        self.endpoints()
            .into_iter()
            .filter(|endpoint| !endpoint.is_in && endpoint.transfer_type == UsbTransferType::Bulk)
            .nth(index)
            .map(|endpoint| endpoint.address)
            .ok_or_else(|| UsbError::Other(format!("no bulk OUT endpoint for AC {ac}")))
    }

    /// Wrap `TXWI || frame` in the TX DMA header and send it on `endpoint`.
    pub fn tx_frame(
        &self,
        txwi: &[u8; TXWI_LEN],
        frame: &[u8],
        endpoint: u8,
        qsel: u32,
        no_encryption: bool,
    ) -> Result<usize, UsbError> {
        let mut payload = Vec::with_capacity(TXWI_LEN + frame.len());
        payload.extend_from_slice(txwi);
        payload.extend_from_slice(frame);

        let mut flags = dma::PKT_INFO_80211 | (qsel << dma::PKT_INFO_QSEL_SHIFT);
        if no_encryption {
            flags |= dma::PKT_INFO_WIV;
        }

        let info = dma::info_word(
            dma::INFO_TYPE_DMA_PACKET,
            dma::PORT_WLAN,
            payload.len().next_multiple_of(4),
            flags,
        );
        let buffer = dma::wrap_buffer(&payload, info);

        // A send that takes unusually long means the device's transmit path is
        // filling up; one that times out means it has stopped accepting frames
        // altogether. Both are worth a log line — they are the first sign of a
        // wedging device, well before the link dies outright.
        let started = Instant::now();
        let written = match self.transport().bulk_out(endpoint, &buffer, TX_TIMEOUT) {
            Ok(written) => written,
            Err(error) => {
                tracing::info!(
                    "bulk out on 0x{endpoint:02x} failed after {:?}: {error}",
                    started.elapsed()
                );
                return Err(error);
            }
        };
        let elapsed = started.elapsed();
        if elapsed > Duration::from_millis(250) {
            tracing::info!(
                "slow bulk out on 0x{endpoint:02x}: {} bytes took {elapsed:?}",
                buffer.len()
            );
        }
        if written != buffer.len() {
            return Err(UsbError::Other(format!(
                "TX short write: {written}/{}",
                buffer.len()
            )));
        }
        Ok(written)
    }

    /// Pop one entry from the TX status FIFO
    /// (`mt7601u_mac_fetch_tx_status`).
    pub fn tx_status(&self) -> Result<TxStatus, UsbError> {
        let value = self.read_reg(regs::MT_TX_STAT_FIFO)?;
        Ok(TxStatus {
            valid: value & regs::MT_TX_STAT_FIFO_VALID != 0,
            success: value & regs::MT_TX_STAT_FIFO_SUCCESS != 0,
            pktid: ((value >> regs::MT_TX_STAT_FIFO_PID_TYPE_SHIFT)
                & regs::MT_TX_STAT_FIFO_PID_TYPE) as u8,
            wcid: ((value >> regs::MT_TX_STAT_FIFO_WCID_SHIFT) & regs::MT_TX_STAT_FIFO_WCID) as u8,
            rate: ((value >> regs::MT_TX_STAT_FIFO_RATE_SHIFT) & regs::MT_TX_STAT_FIFO_RATE) as u16,
        })
    }

    /// Drain retired TX frames (`mt7601u_tx_stat`), up to `max` entries.
    ///
    /// Every transmitted frame that carries a non-zero packet id is reported
    /// here once the hardware is done with it. The kernel driver drains this
    /// FIFO continuously (each completed TX URB schedules `mt7601u_tx_stat`).
    /// Left unread it fills up after roughly a thousand frames, the hardware
    /// stops retiring frames, and transmission stops dead — the link then dies
    /// under load and only recovers by being re-established.
    pub fn drain_tx_status(&self, max: usize) -> Result<TxStatusTotals, UsbError> {
        let mut totals = TxStatusTotals::default();
        for _ in 0..max {
            let status = self.tx_status()?;
            if !status.valid {
                break;
            }
            totals.drained += 1;
            if !status.success {
                totals.failed += 1;
            }
        }
        Ok(totals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{device_info, MockTransport};

    #[test]
    fn rate_val_encodes_phy_and_index() {
        // Lowest OFDM rate: phy=OFDM(1), index 0.
        assert_eq!(rate_val(PHY_TYPE_OFDM, 0, false, false), 1 << 14);
        // Lowest CCK rate: phy=CCK(0), index 0 -> 0.
        assert_eq!(rate_val(PHY_TYPE_CCK, 0, false, false), 0);
        // BW40 + SGI set their bits.
        assert_eq!(
            rate_val(PHY_TYPE_OFDM, 7, true, true),
            7 | (1 << 7) | (1 << 8) | (1 << 14)
        );
    }

    #[test]
    fn pkt_id_matches_the_driver_encoding() {
        // rate_ctl with MCS field 0, not a probe -> id 1.
        assert_eq!(pkt_id(rate_val(PHY_TYPE_OFDM, 0, false, false), false), 1);
        // MCS 3 probe -> 4 + 8 = 12.
        assert_eq!(pkt_id(rate_val(PHY_TYPE_OFDM, 3, false, false), true), 12);
        // MCS 7 probe shares id 9.
        assert_eq!(pkt_id(rate_val(PHY_TYPE_OFDM, 7, false, false), true), 9);
    }

    #[test]
    fn tx_status_decodes_a_fifo_entry() {
        let value = regs::MT_TX_STAT_FIFO_VALID
            | (5 << regs::MT_TX_STAT_FIFO_PID_TYPE_SHIFT)
            | regs::MT_TX_STAT_FIFO_SUCCESS
            | (3 << regs::MT_TX_STAT_FIFO_WCID_SHIFT)
            | (0x8001 << regs::MT_TX_STAT_FIFO_RATE_SHIFT);
        let mock = MockTransport::default();
        mock.push_reg_read(regs::MT_TX_STAT_FIFO, value);
        let chip = Mt7601u::new(mock, device_info());

        assert_eq!(
            chip.tx_status().unwrap(),
            TxStatus {
                valid: true,
                success: true,
                pktid: 5,
                wcid: 3,
                rate: 0x8001,
            }
        );
    }

    #[test]
    fn drain_tx_status_stops_at_the_first_empty_read() {
        let mock = MockTransport::default();
        mock.push_reg_read(
            regs::MT_TX_STAT_FIFO,
            regs::MT_TX_STAT_FIFO_VALID | regs::MT_TX_STAT_FIFO_SUCCESS,
        );
        mock.push_reg_read(regs::MT_TX_STAT_FIFO, regs::MT_TX_STAT_FIFO_VALID);
        let chip = Mt7601u::new(mock, device_info());

        let totals = chip.drain_tx_status(TX_STATUS_DRAIN_MAX).unwrap();
        assert_eq!(totals.drained, 2);
        assert_eq!(totals.failed, 1);

        // Reads pop entries, so by now the FIFO is empty and a second drain
        // finds nothing.
        let again = chip.drain_tx_status(TX_STATUS_DRAIN_MAX).unwrap();
        assert_eq!(again, TxStatusTotals::default());
    }

    #[test]
    fn drain_tx_status_stops_at_the_cap() {
        let mock = MockTransport::default();
        for _ in 0..TX_STATUS_DRAIN_MAX + 10 {
            mock.push_reg_read(
                regs::MT_TX_STAT_FIFO,
                regs::MT_TX_STAT_FIFO_VALID | regs::MT_TX_STAT_FIFO_SUCCESS,
            );
        }
        let chip = Mt7601u::new(mock, device_info());

        let totals = chip.drain_tx_status(TX_STATUS_DRAIN_MAX).unwrap();
        assert_eq!(totals.drained as usize, TX_STATUS_DRAIN_MAX);
        assert_eq!(totals.failed, 0);

        // The rest is still queued for the next call.
        let rest = chip.drain_tx_status(TX_STATUS_DRAIN_MAX).unwrap();
        assert_eq!(rest.drained, 10);
    }

    #[test]
    fn txwi_layout() {
        let rate = rate_val(PHY_TYPE_OFDM, 0, false, false);
        let txwi = build_txwi(24, 0xff, rate, true, true, false, 0);

        assert_eq!(txwi.len(), TXWI_LEN);
        assert_eq!(&txwi[0..2], &[0, 0]); // no flags
        assert_eq!(&txwi[2..4], &rate.to_le_bytes());
        assert_eq!(txwi[4], 0b11); // ACK_REQ | NSEQ
        assert_eq!(txwi[5], 0xff); // wcid
        let len_ctl = u16::from_le_bytes([txwi[6], txwi[7]]);
        assert_eq!(len_ctl & TXWI_LEN_BYTE_CNT, 24);
        assert_eq!(
            len_ctl >> TXWI_LEN_PKTID_SHIFT,
            u16::from(pkt_id(rate, false))
        );
        // iv/eiv/aid/txstream/ctl untouched.
        assert_eq!(&txwi[8..20], &[0u8; 12]);
    }

    #[test]
    fn ac_endpoint_maps_access_categories() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        // Descriptor order of OUT endpoints is 0x08, 0x04, 0x05, ...
        // AC_BE: q2hwq(2) = 1, q2ep(1) = 2 -> OUT endpoint index 2 = 0x05.
        assert_eq!(chip.ac_endpoint(AC_BE).unwrap(), 0x05);
        // AC_BK: q2hwq(3) = 0, index 1 -> 0x04.
        assert_eq!(chip.ac_endpoint(AC_BK).unwrap(), 0x04);
    }

    #[test]
    fn tx_frame_wraps_txwi_and_frame() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        let txwi = build_txwi(4, 0, 0, false, false, false, 0);
        let written = chip
            .tx_frame(&txwi, &[0xaa, 0xbb, 0xcc, 0xdd], 0x08, dma::QSEL_EDCA, true)
            .unwrap();

        // 4 (info) + 20 (txwi) + 4 (frame) + 4 (zero) = 32, already 4-aligned.
        assert_eq!(written, 32);

        let writes = chip.transport().bulk_writes.borrow();
        let buffer = &writes[0].1;
        let info = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        // TYPE = DMA_PACKET (0), D_PORT = WLAN (0), LEN = 24.
        assert_eq!(info >> 30, dma::INFO_TYPE_DMA_PACKET);
        assert_eq!((info >> 27) & 0x7, dma::PORT_WLAN);
        assert_eq!(info & 0xffff, 24);
        // 802.11 + WIV + QSEL = EDCA
        assert_ne!(info & dma::PKT_INFO_80211, 0);
        assert_ne!(info & dma::PKT_INFO_WIV, 0);
        assert_eq!((info >> dma::PKT_INFO_QSEL_SHIFT) & 0x3, dma::QSEL_EDCA);
        // TXWI followed by the frame.
        assert_eq!(&buffer[4..24], &txwi);
        assert_eq!(&buffer[24..28], &[0xaa, 0xbb, 0xcc, 0xdd]);
    }
}
