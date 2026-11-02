//! Hardware initialization sequence, transcribed from `init.c`.
//!
//! Covers `mt7601u_write_mac_initvals` through `mt7601u_reset_counters`.
//! `mt7601u_eeprom_init`, `mt7601u_phy_init` (RF tables) and the antenna/path
//! setup are not implemented.

use std::time::{Duration, Instant};

use crate::usb::{Transport, UsbError};

use super::data::RX_BUFFER_LEN;
use super::device::Mt7601u;
use super::initvals::{self, RegPair};
use super::{mcu, regs};

/// `beacon_offsets` from `mt7601u_init_hardware` (512 bytes per beacon).
pub const BEACON_OFFSETS: [u32; 16] = [
    0xc000, 0xc200, 0xc400, 0xc600, 0xc800, 0xca00, 0xcc00, 0xce00, 0xd000, 0xd200, 0xd400, 0xd600,
    0xd800, 0xda00, 0xdc00, 0xde00,
];

/// `N_WCIDS` (`mt7601u.h`).
pub const N_WCIDS: usize = 128;

/// Compute the four `MT_BCN_OFFSET` words (`mt76_init_beacon_offsets`).
pub fn beacon_offset_words() -> [u32; 4] {
    let mut words = [0u32; 4];
    for (index, address) in BEACON_OFFSETS.iter().enumerate() {
        let relative = (address - regs::MT_BEACON_BASE) / 64;
        words[index / 4] |= relative << (8 * (index % 4));
    }
    words
}

impl<T: Transport> Mt7601u<T> {
    /// `mt7601u_write_mac_initvals`.
    pub fn write_mac_initvals(&self) -> Result<(), UsbError> {
        self.mcu_write_reg_pairs(mcu::MT_MCU_MEMMAP_WLAN, initvals::MAC_COMMON_VALS)?;
        self.mcu_write_reg_pairs(mcu::MT_MCU_MEMMAP_WLAN, initvals::MAC_CHIP_VALS)?;
        self.write_beacon_offsets()?;
        self.write_reg(regs::MT_AUX_CLK_CFG, 0)?;
        Ok(())
    }

    /// `mt76_init_beacon_offsets`.
    fn write_beacon_offsets(&self) -> Result<(), UsbError> {
        for (index, value) in beacon_offset_words().into_iter().enumerate() {
            self.write_reg(regs::MT_BCN_OFFSET_BASE + index as u32 * 4, value)?;
        }
        Ok(())
    }

    /// `mt7601u_init_bbp`.
    pub fn init_bbp(&self) -> Result<(), UsbError> {
        self.wait_bbp_ready(20, Duration::from_millis(1))?;
        self.write_bbp_pairs(initvals::BBP_COMMON_VALS)?;
        self.write_bbp_pairs(initvals::BBP_CHIP_VALS)
    }

    fn write_bbp_pairs(&self, pairs: &[RegPair]) -> Result<(), UsbError> {
        for (offset, value) in pairs {
            self.bbp_wr(*offset as u8, *value as u8)?;
        }
        Ok(())
    }

    /// `mt7601u_init_wcid_mem`.
    pub fn init_wcid_mem(&self) -> Result<(), UsbError> {
        let mut values = Vec::with_capacity(N_WCIDS * 2);
        for _ in 0..N_WCIDS {
            values.push(0xffff_ffff);
            values.push(0x00ff_ffff);
        }
        self.mcu_burst_write_regs(regs::MT_WCID_ADDR_BASE, &values)
    }

    /// `mt7601u_init_key_mem`.
    pub fn init_key_mem(&self) -> Result<(), UsbError> {
        self.mcu_burst_write_regs(regs::MT_SKEY_MODE_BASE_0, &[0, 0, 0, 0])
    }

    /// `mt7601u_init_wcid_attr_mem`.
    pub fn init_wcid_attr_mem(&self) -> Result<(), UsbError> {
        let values = vec![1u32; N_WCIDS * 2];
        self.mcu_burst_write_regs(regs::MT_WCID_ATTR_BASE, &values)
    }

    /// `mt7601u_reset_counters` (reads clear the statistics counters).
    pub fn reset_counters(&self) -> Result<(), UsbError> {
        for index in 0..3 {
            self.read_reg(regs::MT_RX_STA_CNT0 + index * 4)?;
            self.read_reg(regs::MT_TX_STA_CNT0 + index * 4)?;
        }
        Ok(())
    }

    /// `mt76_clear(MT_BEACON_TIME_CFG, ...)`.
    pub fn clear_beacon_timer(&self) -> Result<(), UsbError> {
        self.rmw(
            regs::MT_BEACON_TIME_CFG,
            regs::MT_BEACON_TIME_CFG_TIMER_EN
                | regs::MT_BEACON_TIME_CFG_SYNC_MODE
                | regs::MT_BEACON_TIME_CFG_TBTT_EN
                | regs::MT_BEACON_TIME_CFG_BEACON_TX,
            0,
        )?;
        Ok(())
    }

    /// `mt7601u_mac_stop_hw` (`init.c`): stop the MAC and drain both DMA
    /// directions.
    ///
    /// Called before the device is released and before a running device is
    /// re-initialized, because a MAC left running while the host closes the USB
    /// pipes is what wedges the chip's DMA block. The driver warns instead of
    /// failing on every timeout here, and so does this port — the goal is a
    /// quiescent chip, not an aborted shutdown.
    pub fn mac_stop(&self) {
        let _ = self.clear_beacon_timer();

        if let Err(error) = self.poll_reg(
            regs::MT_USB_DMA_CFG,
            regs::MT_USB_DMA_CFG_TX_BUSY,
            0,
            Duration::from_millis(1000),
        ) {
            tracing::warn!("TX DMA did not stop: {error}");
        }

        // Page count on TxQ.
        for _ in 0..200 {
            if !self.txq_has_pages() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        if let Err(error) = self.poll_reg(
            regs::MT_MAC_STATUS,
            regs::MT_MAC_STATUS_TX,
            0,
            Duration::from_millis(1000),
        ) {
            tracing::warn!("MAC TX did not stop: {error}");
        }

        let _ = self.rmw(
            regs::MT_MAC_SYS_CTRL,
            regs::MT_MAC_SYS_CTRL_ENABLE_RX | regs::MT_MAC_SYS_CTRL_ENABLE_TX,
            0,
        );

        // Page count on RxQ; the driver requires several consecutive clean reads.
        let mut clean = 0;
        for _ in 0..200 {
            if self.rxq_has_pages() {
                clean = 0;
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            clean += 1;
            if clean > 5 {
                break;
            }
        }

        if let Err(error) = self.poll_reg(
            regs::MT_MAC_STATUS,
            regs::MT_MAC_STATUS_RX,
            0,
            Duration::from_millis(1000),
        ) {
            tracing::warn!("MAC RX did not stop: {error}");
        }

        // The RX DMA engine only finishes the transfer it has in flight when
        // the host keeps a bulk IN armed: with no IN token it waits forever and
        // keeps reporting RX_BUSY. Left like that it wedges the next bring-up
        // (the MCU command channel then times out), which is the "unplug and
        // replug" failure. The reference drivers never let receive transfers go
        // unarmed, so drain the endpoint while we wait for the engine to idle.
        if let Err(error) = self.drain_rx_until_idle(Duration::from_millis(1000)) {
            tracing::warn!("RX DMA did not stop: {error}");
        }
    }

    /// Wait for the RX DMA engine to go idle, keeping a bulk IN transfer armed
    /// so the transfer already in flight can complete.
    ///
    /// `mt7601u_mac_stop_hw` polls `MT_USB_DMA_CFG.RX_BUSY`; on real hardware
    /// that bit only clears once the pending DMA has been read out — which is
    /// exactly what the Linux driver's always-queued URBs keep happening.
    /// Reading the receive endpoint here is what makes Stop/Start and a rescan
    /// work without a physical replug.
    fn drain_rx_until_idle(&self, timeout: Duration) -> Result<(), UsbError> {
        let deadline = Instant::now() + timeout;
        let endpoint = self.rx_endpoint().ok();
        let mut buffer = vec![0u8; RX_BUFFER_LEN];
        loop {
            if (self.read_reg(regs::MT_USB_DMA_CFG)? & regs::MT_USB_DMA_CFG_RX_BUSY) == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(UsbError::Other(format!(
                    "timeout polling register 0x{:08x}",
                    regs::MT_USB_DMA_CFG
                )));
            }
            match endpoint {
                // A short timeout so a quiet device does not stall the drain.
                Some(endpoint) => {
                    let _ =
                        self.transport()
                            .bulk_in(endpoint, &mut buffer, Duration::from_millis(20));
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }

    /// Any pages still queued on TxQ (`mt7601u_mac_stop_hw`).
    ///
    /// A register read that fails counts as "no pages", so a device that has
    /// already gone away cannot make the drain loop spin.
    fn txq_has_pages(&self) -> bool {
        fn pages(chip: &Mt7601u<impl Transport>, offset: u32, mask: u32) -> bool {
            match chip.read_reg(offset) {
                Ok(value) => value & mask != 0,
                Err(_) => false,
            }
        }

        pages(self, regs::MT_TXQ_PAGE_COUNT, u32::MAX)
            || pages(
                self,
                regs::MT_Q_PAGE_COUNT_0A30,
                regs::MT_PAGE_COUNT_LOW_BYTE,
            )
            || pages(self, regs::MT_Q_PAGE_COUNT_0A34, regs::MT_PAGE_COUNT_SPLIT)
    }

    /// Any pages still queued on RxQ (`mt7601u_mac_stop_hw`).
    fn rxq_has_pages(&self) -> bool {
        fn pages(chip: &Mt7601u<impl Transport>, offset: u32, mask: u32) -> bool {
            match chip.read_reg(offset) {
                Ok(value) => value & mask != 0,
                Err(_) => false,
            }
        }

        pages(self, regs::MT_RXQ_STA, regs::MT_RXQ_STA_PAGE_COUNT)
            || pages(self, regs::MT_Q_PAGE_COUNT_0A30, u32::MAX)
            || pages(self, regs::MT_Q_PAGE_COUNT_0A34, u32::MAX)
    }

    /// Wait for the MAC TX/RX engines to report idle.
    pub fn wait_mac_idle(&self, timeout: Duration) -> Result<(), UsbError> {
        self.poll_reg(
            regs::MT_MAC_STATUS,
            regs::MT_MAC_STATUS_TX | regs::MT_MAC_STATUS_RX,
            0,
            timeout,
        )
    }

    /// The part of `mt7601u_init_hardware` from `mcu_cmd_init` up to (but not
    /// including) `mt7601u_eeprom_init` / `mt7601u_phy_init`.
    pub fn init_radio_registers(&self) -> Result<(), UsbError> {
        self.mcu_cmd_init()?;
        self.write_mac_initvals()?;
        self.wait_mac_idle(Duration::from_millis(100))?;
        self.init_bbp()?;
        self.init_wcid_mem()?;
        self.init_key_mem()?;
        self.init_wcid_attr_mem()?;
        self.clear_beacon_timer()?;
        self.reset_counters()?;
        self.rmw(regs::MT_US_CYC_CFG, regs::MT_US_CYC_CNT, 0x1e)?;
        self.write_reg(
            regs::MT_TXOP_CTRL_CFG,
            regs::MT_TXOP_TRUN_EN | (0x58 << regs::MT_TXOP_EXT_CCA_DLY_SHIFT),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{device_info, MockTransport};

    #[test]
    fn beacon_offset_words_match_mac_chip_vals() {
        let words = beacon_offset_words();
        assert_eq!(words[0], 0x1810_0800);
        assert_eq!(words[1], 0x3830_2820);
        assert_eq!(words[2], 0x5850_4840);
        assert_eq!(words[3], 0x7870_6860);
        // The first two words must agree with the transcribed table.
        assert_eq!(words[0], initvals::MAC_CHIP_VALS[1].1);
        assert_eq!(words[1], initvals::MAC_CHIP_VALS[2].1);
    }

    #[test]
    fn init_radio_registers_runs_end_to_end() {
        // BBP version reads 0x05 (register number 0, not 0/0xff) and BUSY is
        // clear; MAC status is idle. The mock auto-acks MCU commands.
        let mock = MockTransport::with_registers(&[
            (regs::MT_BBP_CSR_CFG, 0x05),
            (regs::MT_MAC_STATUS, 0),
        ]);
        mock.ack_mcu_commands();
        let chip = Mt7601u::new(mock, device_info());

        chip.init_radio_registers().unwrap();
        // MAC initvals, WCID/key memory and MCU commands all used bulk writes.
        assert!(!chip.transport().bulk_writes.borrow().is_empty());
    }

    #[test]
    fn mac_stop_drains_the_rx_endpoint_until_the_dma_goes_idle() {
        // RX DMA reports itself busy until a bulk IN reads the pending data out;
        // with nothing armed it stays busy and the next bring-up wedges.
        let mock = MockTransport::with_registers(&[
            (regs::MT_USB_DMA_CFG, regs::MT_USB_DMA_CFG_RX_BUSY),
            (regs::MT_MAC_STATUS, 0),
        ]);
        mock.clear_rx_busy_after_bulk_in();
        mock.push_rx_frame(vec![0u8; 64]);
        let chip = Mt7601u::new(mock, device_info());

        chip.mac_stop();

        assert_eq!(
            chip.read_reg(regs::MT_USB_DMA_CFG).unwrap() & regs::MT_USB_DMA_CFG_RX_BUSY,
            0
        );
    }
}
