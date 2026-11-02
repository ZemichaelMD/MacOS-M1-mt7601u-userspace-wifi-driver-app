//! BBP register access and readiness, transcribed from `phy.c`.
//!
//! BBP registers are reached indirectly through `MT_BBP_CSR_CFG`: write the
//! register number plus an operation, then poll `BUSY`.

use std::time::Duration;

use crate::usb::{Transport, UsbError};

use super::device::Mt7601u;
use super::regs;

/// Timeout for a single BBP access (`mt76_poll(..., 1000)`).
const BBP_TIMEOUT: Duration = Duration::from_millis(100);

impl<T: Transport> Mt7601u<T> {
    /// `mt7601u_bbp_wr`.
    pub fn bbp_wr(&self, offset: u8, value: u8) -> Result<(), UsbError> {
        self.poll_reg(
            regs::MT_BBP_CSR_CFG,
            regs::MT_BBP_CSR_CFG_BUSY,
            0,
            BBP_TIMEOUT,
        )?;

        let reg = (u32::from(value) & regs::MT_BBP_CSR_CFG_VAL)
            | ((u32::from(offset) & regs::MT_BBP_CSR_CFG_REG_NUM)
                << regs::MT_BBP_CSR_CFG_REG_NUM_SHIFT)
            | regs::MT_BBP_CSR_CFG_RW_MODE
            | regs::MT_BBP_CSR_CFG_BUSY;
        self.write_reg(regs::MT_BBP_CSR_CFG, reg)
    }

    /// `mt7601u_bbp_rr`.
    pub fn bbp_rr(&self, offset: u8) -> Result<u8, UsbError> {
        self.poll_reg(
            regs::MT_BBP_CSR_CFG,
            regs::MT_BBP_CSR_CFG_BUSY,
            0,
            BBP_TIMEOUT,
        )?;

        let reg = ((u32::from(offset) & regs::MT_BBP_CSR_CFG_REG_NUM)
            << regs::MT_BBP_CSR_CFG_REG_NUM_SHIFT)
            | regs::MT_BBP_CSR_CFG_RW_MODE
            | regs::MT_BBP_CSR_CFG_BUSY
            | regs::MT_BBP_CSR_CFG_READ;
        self.write_reg(regs::MT_BBP_CSR_CFG, reg)?;
        self.poll_reg(
            regs::MT_BBP_CSR_CFG,
            regs::MT_BBP_CSR_CFG_BUSY,
            0,
            BBP_TIMEOUT,
        )?;

        let value = self.read_reg(regs::MT_BBP_CSR_CFG)?;
        let register =
            ((value >> regs::MT_BBP_CSR_CFG_REG_NUM_SHIFT) & regs::MT_BBP_CSR_CFG_REG_NUM) as u8;
        if register == offset {
            Ok((value & regs::MT_BBP_CSR_CFG_VAL) as u8)
        } else {
            Err(UsbError::Other(format!(
                "BBP read at register {offset} returned register {register}"
            )))
        }
    }

    /// `mt7601u_wait_bbp_ready`: poll `MT_BBP_REG_VERSION` until it reads a
    /// value that is neither 0 nor all-ones.
    pub fn wait_bbp_ready(&self, attempts: u32, delay: Duration) -> Result<(), UsbError> {
        for _ in 0..attempts {
            let value = self.bbp_rr(regs::MT_BBP_REG_VERSION)?;
            if value != 0 && value != 0xff {
                return Ok(());
            }
            std::thread::sleep(delay);
        }
        Err(UsbError::Other("BBP is not ready".to_string()))
    }
}
