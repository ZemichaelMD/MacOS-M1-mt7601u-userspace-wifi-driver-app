//! RF register access and init tables, transcribed from `phy.c` /
//! `initvals_phy.h`.
//!
//! RF registers are reached through `MT_RF_CSR_CFG` (write the bank/offset, kick,
//! poll), but the init tables are written as MCU register pairs whose key already
//! encodes `MT_MCU_MEMMAP_RF | bank << 16 | reg`.

use std::time::Duration;

use crate::usb::{Transport, UsbError};

use super::device::Mt7601u;
use super::initvals::RegPair;
use super::mcu;
use super::regs;

/// Timeout for a single RF access (`mt76_poll(..., 100)`).
const RF_TIMEOUT: Duration = Duration::from_millis(100);

/// Build an `RF_REG_PAIR(bank, reg, value)` key.
const fn rf_pair(bank: u32, reg: u32, value: u32) -> RegPair {
    (mcu::MT_MCU_MEMMAP_RF | (bank << 16) | reg, value)
}

/// `rf_central`: bank 0 (BG, PLL, XTAL, LO, ADC/DAC).
pub static RF_CENTRAL: &[RegPair] = &[
    rf_pair(0, 0, 0x02),
    rf_pair(0, 1, 0x01),
    rf_pair(0, 2, 0x11),
    rf_pair(0, 3, 0xff),
    rf_pair(0, 4, 0x0a),
    rf_pair(0, 5, 0x20),
    rf_pair(0, 6, 0x00),
    rf_pair(0, 7, 0x00),
    rf_pair(0, 8, 0x00),
    rf_pair(0, 9, 0x00),
    rf_pair(0, 10, 0x00),
    rf_pair(0, 11, 0x21),
    rf_pair(0, 13, 0x00),
    rf_pair(0, 14, 0x7c),
    rf_pair(0, 15, 0x22),
    rf_pair(0, 16, 0x80),
    rf_pair(0, 17, 0x99),
    rf_pair(0, 18, 0x99),
    rf_pair(0, 19, 0x09),
    rf_pair(0, 20, 0x50),
    rf_pair(0, 21, 0xb0),
    rf_pair(0, 22, 0x00),
    rf_pair(0, 23, 0xc5),
    rf_pair(0, 24, 0xfc),
    rf_pair(0, 25, 0x40),
    rf_pair(0, 26, 0x4d),
    rf_pair(0, 27, 0x02),
    rf_pair(0, 28, 0x72),
    rf_pair(0, 29, 0x01),
    rf_pair(0, 30, 0x00),
    rf_pair(0, 31, 0x00),
    rf_pair(0, 32, 0x00),
    rf_pair(0, 33, 0x00),
    rf_pair(0, 34, 0x23),
    rf_pair(0, 35, 0x01),
    rf_pair(0, 36, 0x00),
    rf_pair(0, 37, 0x00),
    rf_pair(0, 38, 0x00),
    rf_pair(0, 39, 0x20),
    rf_pair(0, 40, 0x00),
    rf_pair(0, 41, 0xd0),
    rf_pair(0, 42, 0x1b),
    rf_pair(0, 43, 0x02),
    rf_pair(0, 44, 0x00),
];

/// `rf_channel`: bank 4 (LDO, RX, LOGEN, TX, PA).
#[rustfmt::skip]
pub static RF_CHANNEL: &[RegPair] = &[
    rf_pair(4, 0, 0x01), rf_pair(4, 1, 0x00), rf_pair(4, 2, 0x00), rf_pair(4, 3, 0x00),
    rf_pair(4, 4, 0x00), rf_pair(4, 5, 0x08), rf_pair(4, 6, 0x00),
    rf_pair(4, 7, 0x5b), rf_pair(4, 8, 0x52), rf_pair(4, 9, 0xb6), rf_pair(4, 10, 0x57),
    rf_pair(4, 11, 0x33), rf_pair(4, 12, 0x22), rf_pair(4, 13, 0x3d), rf_pair(4, 14, 0x3e),
    rf_pair(4, 15, 0x13), rf_pair(4, 16, 0x22), rf_pair(4, 17, 0x23), rf_pair(4, 18, 0x02),
    rf_pair(4, 19, 0xa4), rf_pair(4, 20, 0x01), rf_pair(4, 21, 0x12), rf_pair(4, 22, 0x80),
    rf_pair(4, 23, 0xb3), rf_pair(4, 24, 0x00), rf_pair(4, 25, 0x00), rf_pair(4, 26, 0x00),
    rf_pair(4, 27, 0x00),
    rf_pair(4, 28, 0x18), rf_pair(4, 29, 0xee), rf_pair(4, 30, 0x6b), rf_pair(4, 31, 0x31),
    rf_pair(4, 32, 0x5d), rf_pair(4, 33, 0x00),
    rf_pair(4, 34, 0x96), rf_pair(4, 35, 0x55), rf_pair(4, 36, 0x08), rf_pair(4, 37, 0xbb),
    rf_pair(4, 38, 0xb3), rf_pair(4, 39, 0xb3), rf_pair(4, 40, 0x03), rf_pair(4, 41, 0x00),
    rf_pair(4, 42, 0x00), rf_pair(4, 43, 0xc5), rf_pair(4, 44, 0xc5), rf_pair(4, 45, 0xc5),
    rf_pair(4, 46, 0x07), rf_pair(4, 47, 0xa8), rf_pair(4, 48, 0xef), rf_pair(4, 49, 0x1a),
    rf_pair(4, 54, 0x07), rf_pair(4, 55, 0xa7), rf_pair(4, 56, 0xcc), rf_pair(4, 57, 0x14),
    rf_pair(4, 58, 0x07), rf_pair(4, 59, 0xa8), rf_pair(4, 60, 0xd7), rf_pair(4, 61, 0x10),
    rf_pair(4, 62, 0x1c), rf_pair(4, 63, 0x00),
];

/// `rf_vga`: bank 5.
#[rustfmt::skip]
pub static RF_VGA: &[RegPair] = &[
    rf_pair(5, 0, 0x47), rf_pair(5, 1, 0x00), rf_pair(5, 2, 0x00), rf_pair(5, 3, 0x08),
    rf_pair(5, 4, 0x04), rf_pair(5, 5, 0x20), rf_pair(5, 6, 0x3a), rf_pair(5, 7, 0x3a),
    rf_pair(5, 8, 0x00), rf_pair(5, 9, 0x00), rf_pair(5, 10, 0x10), rf_pair(5, 11, 0x10),
    rf_pair(5, 12, 0x10), rf_pair(5, 13, 0x10), rf_pair(5, 14, 0x10), rf_pair(5, 15, 0x20),
    rf_pair(5, 16, 0x22), rf_pair(5, 17, 0x7c), rf_pair(5, 18, 0x00), rf_pair(5, 19, 0x00),
    rf_pair(5, 20, 0x00), rf_pair(5, 21, 0xf1), rf_pair(5, 22, 0x11), rf_pair(5, 23, 0x02),
    rf_pair(5, 24, 0x41), rf_pair(5, 25, 0x20), rf_pair(5, 26, 0x00), rf_pair(5, 27, 0xd7),
    rf_pair(5, 28, 0xa2), rf_pair(5, 29, 0x20), rf_pair(5, 30, 0x49), rf_pair(5, 31, 0x20),
    rf_pair(5, 32, 0x04), rf_pair(5, 33, 0xf1), rf_pair(5, 34, 0xa1), rf_pair(5, 35, 0x01),
    rf_pair(5, 41, 0x00), rf_pair(5, 42, 0x00), rf_pair(5, 43, 0x00), rf_pair(5, 44, 0x00),
    rf_pair(5, 45, 0x00), rf_pair(5, 46, 0x00), rf_pair(5, 47, 0x00), rf_pair(5, 48, 0x00),
    rf_pair(5, 49, 0x00), rf_pair(5, 50, 0x00), rf_pair(5, 51, 0x00), rf_pair(5, 52, 0x00),
    rf_pair(5, 53, 0x00), rf_pair(5, 54, 0x00), rf_pair(5, 55, 0x00), rf_pair(5, 56, 0x00),
    rf_pair(5, 57, 0x00), rf_pair(5, 58, 0x31), rf_pair(5, 59, 0x31), rf_pair(5, 60, 0x0a),
    rf_pair(5, 61, 0x02), rf_pair(5, 62, 0x00), rf_pair(5, 63, 0x00),
];

impl<T: Transport> Mt7601u<T> {
    /// `mt7601u_rf_wr`.
    pub fn rf_wr(&self, bank: u8, offset: u8, value: u8) -> Result<(), UsbError> {
        if offset > 63 {
            return Err(UsbError::Other(format!("RF offset {offset} out of range")));
        }
        self.poll_reg(regs::MT_RF_CSR_CFG, regs::MT_RF_CSR_CFG_KICK, 0, RF_TIMEOUT)?;

        let reg = (u32::from(value) & regs::MT_RF_CSR_CFG_DATA)
            | ((u32::from(offset) & regs::MT_RF_CSR_CFG_REG_ID)
                << regs::MT_RF_CSR_CFG_REG_ID_SHIFT)
            | ((u32::from(bank) & regs::MT_RF_CSR_CFG_REG_BANK)
                << regs::MT_RF_CSR_CFG_REG_BANK_SHIFT)
            | regs::MT_RF_CSR_CFG_WR
            | regs::MT_RF_CSR_CFG_KICK;
        self.write_reg(regs::MT_RF_CSR_CFG, reg)
    }

    /// `mt7601u_rf_rr`.
    pub fn rf_rr(&self, bank: u8, offset: u8) -> Result<u8, UsbError> {
        if offset > 63 {
            return Err(UsbError::Other(format!("RF offset {offset} out of range")));
        }
        self.poll_reg(regs::MT_RF_CSR_CFG, regs::MT_RF_CSR_CFG_KICK, 0, RF_TIMEOUT)?;

        let reg = ((u32::from(offset) & regs::MT_RF_CSR_CFG_REG_ID)
            << regs::MT_RF_CSR_CFG_REG_ID_SHIFT)
            | ((u32::from(bank) & regs::MT_RF_CSR_CFG_REG_BANK)
                << regs::MT_RF_CSR_CFG_REG_BANK_SHIFT)
            | regs::MT_RF_CSR_CFG_KICK;
        self.write_reg(regs::MT_RF_CSR_CFG, reg)?;
        self.poll_reg(regs::MT_RF_CSR_CFG, regs::MT_RF_CSR_CFG_KICK, 0, RF_TIMEOUT)?;

        let value = self.read_reg(regs::MT_RF_CSR_CFG)?;
        let got_offset =
            ((value >> regs::MT_RF_CSR_CFG_REG_ID_SHIFT) & regs::MT_RF_CSR_CFG_REG_ID) as u8;
        let got_bank =
            ((value >> regs::MT_RF_CSR_CFG_REG_BANK_SHIFT) & regs::MT_RF_CSR_CFG_REG_BANK) as u8;
        if got_offset == offset && got_bank == bank {
            Ok((value & regs::MT_RF_CSR_CFG_DATA) as u8)
        } else {
            Err(UsbError::Other(format!(
                "RF read bank {bank} offset {offset} returned bank {got_bank} offset {got_offset}"
            )))
        }
    }

    /// `mt7601u_rf_rmw`.
    pub fn rf_rmw(&self, bank: u8, offset: u8, mask: u8, value: u8) -> Result<u8, UsbError> {
        let current = self.rf_rr(bank, offset)?;
        let merged = value | (current & !mask);
        self.rf_wr(bank, offset, merged)?;
        Ok(merged)
    }

    /// `mt7601u_rf_set`.
    pub fn rf_set(&self, bank: u8, offset: u8, value: u8) -> Result<u8, UsbError> {
        self.rf_rmw(bank, offset, 0, value)
    }

    /// `mt7601u_rf_clear`.
    pub fn rf_clear(&self, bank: u8, offset: u8, mask: u8) -> Result<u8, UsbError> {
        self.rf_rmw(bank, offset, mask, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rf_pair_encodes_bank_and_register() {
        assert_eq!(rf_pair(4, 7, 0).0, mcu::MT_MCU_MEMMAP_RF | (4 << 16) | 7);
        assert_eq!(RF_CENTRAL[0].0, mcu::MT_MCU_MEMMAP_RF);
        assert_eq!(RF_CENTRAL[0].1, 0x02);
    }

    #[test]
    fn table_sizes() {
        assert_eq!(RF_CENTRAL.len(), 44);
        assert_eq!(RF_CHANNEL.len(), 60);
        assert_eq!(RF_VGA.len(), 59);
    }
}
