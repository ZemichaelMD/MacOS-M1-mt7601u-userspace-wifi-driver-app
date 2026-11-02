//! PHY initialization, channel setting and MAC start, transcribed from `phy.c`
//! and `init.c`.
//!
//! This is a **partial** port: it covers RF init, the channel switch and the
//! main calibration kicks (`MCU_CAL_*`). The TSSI DC/gain calibration and
//! temperature compensation are **not** ported, so TX power control is
//! incomplete.

use std::time::Duration;

use crate::usb::{Transport, UsbError};

use super::device::Mt7601u;
use super::eeprom::Eeprom;
use super::initvals::RegPair;
use super::{mcu, regs, rf};

/// `MT_BW_20`.
pub const MT_BW_20: u8 = 0;
/// `MT_BW_40`.
pub const MT_BW_40: u8 = 1;
/// `MT_TEMP_MODE_NORMAL`.
pub const MT_TEMP_MODE_NORMAL: u8 = 0;
/// `MT_TEMP_MODE_HIGH`.
pub const MT_TEMP_MODE_HIGH: u8 = 1;
/// `MT_TEMP_MODE_LOW`.
pub const MT_TEMP_MODE_LOW: u8 = 2;
/// `MT_EE_TEMPERATURE_SLOPE`.
pub const MT_EE_TEMPERATURE_SLOPE: i32 = 39;

/// `MT_RX_FILTR_CFG` value used by `mt7601u_mac_start` (promiscuous). The driver
/// ORs a set of `MT_RX_FILTR_CFG_*` bits that sum to this value; the same value
/// is also written by the MAC initvals.
pub const RX_FILTER_PROMISCUOUS: u32 = 0x0001_7f97;

/// Channel frequency plan (`freq_plan` in `__mt7601u_phy_set_channel`), 14 rows
/// of 4 RF register values for RF registers 17..20.
pub const FREQ_PLAN: [[u8; 4]; 14] = [
    [0x99, 0x99, 0x09, 0x50],
    [0x46, 0x44, 0x0a, 0x50],
    [0xec, 0xee, 0x0a, 0x50],
    [0x99, 0x99, 0x0b, 0x50],
    [0x46, 0x44, 0x08, 0x51],
    [0xec, 0xee, 0x08, 0x51],
    [0x99, 0x99, 0x09, 0x51],
    [0x46, 0x44, 0x0a, 0x51],
    [0xec, 0xee, 0x0a, 0x51],
    [0x99, 0x99, 0x0b, 0x51],
    [0x46, 0x44, 0x08, 0x52],
    [0xec, 0xee, 0x08, 0x52],
    [0x99, 0x99, 0x09, 0x52],
    [0x33, 0x33, 0x0b, 0x52],
];

// BBP temperature-mode tables (`initvals_phy.h`).
#[rustfmt::skip]
static BBP_HIGH_TEMP: &[RegPair] = &[
    (75, 0x60), (92, 0x02), (178, 0xff), (195, 0x88), (196, 0x60),
];
#[rustfmt::skip]
static BBP_HIGH_TEMP_BW20: &[RegPair] = &[
    (69, 0x12), (91, 0x07),
    (195, 0x23), (196, 0x17), (195, 0x24), (196, 0x06),
    (195, 0x81), (196, 0x12), (195, 0x83), (196, 0x17),
];
#[rustfmt::skip]
static BBP_HIGH_TEMP_BW40: &[RegPair] = &[
    (69, 0x15), (91, 0x04),
    (195, 0x23), (196, 0x12), (195, 0x24), (196, 0x08),
    (195, 0x81), (196, 0x15), (195, 0x83), (196, 0x16),
];
#[rustfmt::skip]
static BBP_LOW_TEMP: &[RegPair] = &[(178, 0xff)];
#[rustfmt::skip]
static BBP_LOW_TEMP_BW20: &[RegPair] = &[
    (69, 0x12), (75, 0x5e), (91, 0x07), (92, 0x02),
    (195, 0x23), (196, 0x17), (195, 0x24), (196, 0x06),
    (195, 0x81), (196, 0x12), (195, 0x83), (196, 0x17),
    (195, 0x88), (196, 0x5e),
];
#[rustfmt::skip]
static BBP_LOW_TEMP_BW40: &[RegPair] = &[
    (69, 0x15), (75, 0x5c), (91, 0x04), (92, 0x03),
    (195, 0x23), (196, 0x10), (195, 0x24), (196, 0x08),
    (195, 0x81), (196, 0x15), (195, 0x83), (196, 0x16),
    (195, 0x88), (196, 0x5b),
];
#[rustfmt::skip]
static BBP_NORMAL_TEMP: &[RegPair] = &[
    (75, 0x60), (92, 0x02), (178, 0xff), (195, 0x88), (196, 0x60),
];
#[rustfmt::skip]
static BBP_NORMAL_TEMP_BW20: &[RegPair] = &[
    (69, 0x12), (91, 0x07),
    (195, 0x23), (196, 0x17), (195, 0x24), (196, 0x06),
    (195, 0x81), (196, 0x12), (195, 0x83), (196, 0x17),
];
#[rustfmt::skip]
static BBP_NORMAL_TEMP_BW40: &[RegPair] = &[
    (69, 0x15), (91, 0x04),
    (195, 0x23), (196, 0x12), (195, 0x24), (196, 0x08),
    (195, 0x81), (196, 0x15), (195, 0x83), (196, 0x16),
];

/// `bbp_mode_table[temp_mode][bw]`; index 2 is the base (common) table.
static BBP_MODE_TABLE: [[&[RegPair]; 3]; 3] = [
    [BBP_NORMAL_TEMP_BW20, BBP_NORMAL_TEMP_BW40, BBP_NORMAL_TEMP],
    [BBP_HIGH_TEMP_BW20, BBP_HIGH_TEMP_BW40, BBP_HIGH_TEMP],
    [BBP_LOW_TEMP_BW20, BBP_LOW_TEMP_BW40, BBP_LOW_TEMP],
];

/// Mutable radio state carried across calls (the driver keeps this in `dev`).
#[derive(Debug, Clone, Copy)]
pub struct RadioState {
    pub bw: u8,
    pub temp_mode: u8,
}

impl Default for RadioState {
    fn default() -> Self {
        Self {
            bw: MT_BW_20,
            temp_mode: MT_TEMP_MODE_NORMAL,
        }
    }
}

/// `int_to_s6`: clamp an integer into a 6-bit signed field.
pub fn int_to_s6(value: i32) -> u32 {
    if value < -0x20 {
        0x20
    } else if value > 0x1f {
        0x1f
    } else {
        (value & 0x3f) as u32
    }
}

/// `mt7601u_agc_default`.
pub fn agc_default(lna_gain: i8) -> u8 {
    ((i32::from(lna_gain) - 8) * 2 + 0x34) as u8
}

impl<T: Transport> Mt7601u<T> {
    /// `mt7601u_bbp_rmw`.
    pub fn bbp_rmw(&self, offset: u8, mask: u8, value: u8) -> Result<u8, UsbError> {
        let current = self.bbp_rr(offset)?;
        let merged = value | (current & !mask);
        self.bbp_wr(offset, merged)?;
        Ok(merged)
    }

    /// `mt7601u_bbp_rmc` (only writes when the value changes).
    pub fn bbp_rmc(&self, offset: u8, mask: u8, value: u8) -> Result<u8, UsbError> {
        let current = self.bbp_rr(offset)?;
        let merged = value | (current & !mask);
        if merged != current {
            self.bbp_wr(offset, merged)?;
        }
        Ok(merged)
    }

    /// `mt7601u_bbp_r47_get`.
    fn bbp_r47_get(&self, reg: u8, flag: u8) -> Result<u8, UsbError> {
        let value = flag | (reg & !0x7);
        self.bbp_wr(47, value)?;
        std::thread::sleep(Duration::from_micros(600));
        self.bbp_rr(49)
    }

    /// `mt7601u_read_bootup_temp`.
    pub fn read_bootup_temp(&self) -> Result<i8, UsbError> {
        let rf_set = self.read_reg(regs::MT_RF_SETTING_0)?;
        let rf_bp = self.read_reg(regs::MT_RF_BYPASS_0)?;

        self.write_reg(regs::MT_RF_BYPASS_0, 0)?;
        self.write_reg(regs::MT_RF_SETTING_0, 0x0000_0010)?;
        self.write_reg(regs::MT_RF_BYPASS_0, 0x0000_0010)?;

        let mut bbp_val = self.bbp_rmw(47, 0, 0x10)?;
        self.bbp_wr(22, 0x40)?;
        for _ in 0..100 {
            if bbp_val & 0x10 == 0 {
                break;
            }
            bbp_val = self.bbp_rr(47)?;
        }

        let temp = self.bbp_r47_get(bbp_val, 4)?;

        self.bbp_wr(22, 0)?;
        let mut value = self.bbp_rr(21)?;
        value |= 0x02;
        self.bbp_wr(21, value)?;
        value &= !0x02;
        self.bbp_wr(21, value)?;

        self.write_reg(regs::MT_RF_BYPASS_0, 0)?;
        self.write_reg(regs::MT_RF_SETTING_0, rf_set)?;
        self.write_reg(regs::MT_RF_BYPASS_0, rf_bp)?;
        Ok(temp as i8)
    }

    /// `mt7601u_rxdc_cal`.
    fn rxdc_cal(&self) -> Result<(), UsbError> {
        const INTRO: &[RegPair] = &[(158, 0x8d), (159, 0xfc), (158, 0x8c), (159, 0x4c)];
        const OUTRO: &[RegPair] = &[(158, 0x8d), (159, 0xe0)];

        let mac_ctrl = self.read_reg(regs::MT_MAC_SYS_CTRL)?;
        self.write_reg(regs::MT_MAC_SYS_CTRL, regs::MT_MAC_SYS_CTRL_ENABLE_RX)?;
        self.mcu_write_reg_pairs(mcu::MT_MCU_MEMMAP_BBP, INTRO)?;

        for _ in 0..20 {
            std::thread::sleep(Duration::from_micros(400));
            self.bbp_wr(158, 0x8c)?;
            if self.bbp_rr(159)? == 0x0c {
                break;
            }
        }

        self.write_reg(regs::MT_MAC_SYS_CTRL, 0)?;
        self.mcu_write_reg_pairs(mcu::MT_MCU_MEMMAP_BBP, OUTRO)?;
        self.write_reg(regs::MT_MAC_SYS_CTRL, mac_ctrl)?;
        Ok(())
    }

    /// `mt7601u_set_bw_filter`.
    fn set_bw_filter(&self, state: &RadioState, cal: bool) -> Result<(), UsbError> {
        let mut filter = 0u32;
        if !cal {
            filter |= 0x10000;
        }
        if state.bw != MT_BW_20 {
            filter |= 0x00100;
        }
        // TX
        self.mcu_calibrate(mcu::CAL_BW, filter | 1)?;
        // RX
        self.mcu_calibrate(mcu::CAL_BW, filter)
    }

    /// `mt7601u_load_bbp_temp_table_bw`.
    fn load_bbp_temp_table_bw(&self, state: &RadioState) -> Result<(), UsbError> {
        let table = BBP_MODE_TABLE[state.temp_mode as usize][state.bw as usize];
        self.mcu_write_reg_pairs(mcu::MT_MCU_MEMMAP_BBP, table)
    }

    /// `mt7601u_vco_cal`.
    fn vco_cal(&self) -> Result<(), UsbError> {
        self.rf_wr(0, 4, 0x0a)?;
        self.rf_wr(0, 5, 0x20)?;
        self.rf_set(0, 4, 1 << 7)?;
        std::thread::sleep(Duration::from_millis(2));
        Ok(())
    }

    /// `mt7601u_bbp_set_bw`.
    pub fn bbp_set_bw(&self, state: &mut RadioState, bw: u8) -> Result<(), UsbError> {
        if bw == state.bw {
            self.bbp_rmc(4, 0x18, if bw == MT_BW_20 { 0 } else { 0x10 })?;
            return Ok(());
        }
        state.bw = bw;

        let old = self.read_reg(regs::MT_MAC_SYS_CTRL)?;
        let value = old & !(regs::MT_MAC_SYS_CTRL_ENABLE_TX | regs::MT_MAC_SYS_CTRL_ENABLE_RX);
        self.write_reg(regs::MT_MAC_SYS_CTRL, value)?;
        let _ = self.poll_reg(
            regs::MT_MAC_STATUS,
            regs::MT_MAC_STATUS_TX | regs::MT_MAC_STATUS_RX,
            0,
            Duration::from_millis(500),
        );

        self.bbp_rmc(4, 0x18, if bw == MT_BW_20 { 0 } else { 0x10 })?;
        self.write_reg(regs::MT_MAC_SYS_CTRL, old)?;
        self.load_bbp_temp_table_bw(state)
    }

    /// `mt7601u_set_rx_path`.
    pub fn set_rx_path(&self, path: u8) -> Result<u8, UsbError> {
        self.bbp_rmw(3, 0x18, path << 3)
    }

    /// `mt7601u_set_tx_dac`.
    pub fn set_tx_dac(&self, dac: u8) -> Result<u8, UsbError> {
        self.bbp_rmc(1, 0x18, dac << 3)
    }

    /// `mt7601u_agc_reset`.
    pub fn agc_reset(&self, lna_gain: i8) -> Result<(), UsbError> {
        self.bbp_wr(66, agc_default(lna_gain))
    }

    /// `mt7601u_agc_save`.
    pub fn agc_save(&self) -> Result<u8, UsbError> {
        self.bbp_rr(66)
    }

    /// `mt7601u_agc_restore`.
    pub fn agc_restore(&self, value: u8) -> Result<(), UsbError> {
        self.bbp_wr(66, value)
    }

    /// `mt7601u_mac_start` (`init.c`).
    pub fn mac_start(&self) -> Result<(), UsbError> {
        self.write_reg(regs::MT_MAC_SYS_CTRL, regs::MT_MAC_SYS_CTRL_ENABLE_TX)?;
        self.poll_reg(
            regs::MT_WPDMA_GLO_CFG,
            regs::MT_WPDMA_GLO_CFG_TX_DMA_BUSY | regs::MT_WPDMA_GLO_CFG_RX_DMA_BUSY,
            0,
            Duration::from_millis(200),
        )?;

        self.write_reg(regs::MT_RX_FILTR_CFG, RX_FILTER_PROMISCUOUS)?;
        self.write_reg(
            regs::MT_MAC_SYS_CTRL,
            regs::MT_MAC_SYS_CTRL_ENABLE_TX | regs::MT_MAC_SYS_CTRL_ENABLE_RX,
        )?;
        self.poll_reg(
            regs::MT_WPDMA_GLO_CFG,
            regs::MT_WPDMA_GLO_CFG_TX_DMA_BUSY | regs::MT_WPDMA_GLO_CFG_RX_DMA_BUSY,
            0,
            Duration::from_millis(50),
        )
    }

    /// `mt7601u_phy_init`: RF tables + calibration.
    pub fn phy_init(&self, eeprom: &Eeprom, state: &mut RadioState) -> Result<(), UsbError> {
        // `dev->rf_pa_mode[]` is read here by the driver but only used for TX
        // power control, which this port does not implement.
        self.rf_wr(0, 12, eeprom.rf_freq_off)?;
        self.mcu_write_reg_pairs(0, rf::RF_CENTRAL)?;
        self.mcu_write_reg_pairs(0, rf::RF_CHANNEL)?;
        self.mcu_write_reg_pairs(0, rf::RF_VGA)?;
        self.init_cal(eeprom, state)
    }

    /// `mt7601u_init_cal` (TSSI DC/gain calibration omitted).
    fn init_cal(&self, eeprom: &Eeprom, state: &mut RadioState) -> Result<(), UsbError> {
        let raw_temp = self.read_bootup_temp()?;
        let dpd_temp = (i32::from(raw_temp) - i32::from(eeprom.ref_temp)) * MT_EE_TEMPERATURE_SLOPE;

        let mac_ctrl = self.read_reg(regs::MT_MAC_SYS_CTRL)?;

        self.mcu_calibrate(mcu::CAL_R, 0)?;

        let value = self.rf_rr(0, 4)? | 0x80;
        self.rf_wr(0, 4, value)?;
        std::thread::sleep(Duration::from_millis(2));

        self.mcu_calibrate(mcu::CAL_TXDCOC, 0)?;
        self.rxdc_cal()?;
        self.set_bw_filter(state, true)?;
        self.mcu_calibrate(mcu::CAL_LOFT, 0)?;
        self.mcu_calibrate(mcu::CAL_TXIQ, 0)?;
        self.mcu_calibrate(mcu::CAL_RXIQ, 0)?;
        self.mcu_calibrate(mcu::CAL_DPD, dpd_temp as u32)?;
        self.rxdc_cal()?;

        self.write_reg(regs::MT_MAC_SYS_CTRL, mac_ctrl)?;
        Ok(())
    }

    /// `__mt7601u_phy_set_channel` for 20 MHz operation.
    pub fn phy_set_channel(
        &self,
        eeprom: &Eeprom,
        state: &mut RadioState,
        channel: u8,
    ) -> Result<(), UsbError> {
        let index = usize::from(channel).checked_sub(1);
        let Some(index) = index.filter(|index| *index < FREQ_PLAN.len()) else {
            return Err(UsbError::Other(format!("channel {channel} out of range")));
        };

        let plan = FREQ_PLAN[index];
        let freq_plan: [RegPair; 4] = [
            (17, u32::from(plan[0])),
            (18, u32::from(plan[1])),
            (19, u32::from(plan[2])),
            (20, u32::from(plan[3])),
        ];
        self.mcu_write_reg_pairs(mcu::MT_MCU_MEMMAP_RF, &freq_plan)?;

        self.rmw(
            regs::MT_TX_ALC_CFG_0,
            0x3f3f,
            u32::from(eeprom.chan_pwr[index]) & 0x3f,
        )?;

        let lna = 0x37 - i32::from(eeprom.lna_gain);
        let bbp_settings: [RegPair; 3] = [
            (62, lna as u32 & 0xff),
            (63, lna as u32 & 0xff),
            (64, lna as u32 & 0xff),
        ];
        self.mcu_write_reg_pairs(mcu::MT_MCU_MEMMAP_BBP, &bbp_settings)?;

        self.vco_cal()?;
        self.bbp_set_bw(state, MT_BW_20)?;
        self.set_bw_filter(state, false)?;

        let (cck0, cck1) = self.apply_ch14_fixup(eeprom, channel)?;

        let table = &eeprom.power_rate_table;
        self.write_reg(
            regs::MT_TX_PWR_CFG_0,
            int_to_s6(i32::from(table.ofdm[1].bw20)) << 24
                | int_to_s6(i32::from(table.ofdm[0].bw20)) << 16
                | int_to_s6(i32::from(cck1)) << 8
                | int_to_s6(i32::from(cck0)),
        )?;
        Ok(())
    }

    /// `mt7601u_apply_ch14_fixup`; returns the CCK BW20 powers to program.
    fn apply_ch14_fixup(&self, eeprom: &Eeprom, channel: u8) -> Result<(i8, i8), UsbError> {
        if channel != 14 {
            self.bbp_rmw(4, 0x20, 0)?;
            self.bbp_wr(178, 0xff)?;
            Ok((eeprom.real_cck_bw20[0], eeprom.real_cck_bw20[1]))
        } else {
            self.bbp_wr(4, 0x60)?;
            self.bbp_wr(178, 0)?;
            Ok((eeprom.real_cck_bw20[0] - 2, eeprom.real_cck_bw20[1] - 2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_to_s6_clamps_and_wraps() {
        assert_eq!(int_to_s6(5), 5);
        assert_eq!(int_to_s6(-1) & 0x3f, 0x3f);
        assert_eq!(int_to_s6(100), 0x1f);
        assert_eq!(int_to_s6(-100), 0x20);
    }

    #[test]
    fn agc_default_matches_formula() {
        assert_eq!(agc_default(0), 0x24);
        assert_eq!(agc_default(8), 0x34);
    }

    #[test]
    fn freq_plan_has_14_channels() {
        assert_eq!(FREQ_PLAN.len(), 14);
        assert_eq!(FREQ_PLAN[0], [0x99, 0x99, 0x09, 0x50]);
        assert_eq!(FREQ_PLAN[13], [0x33, 0x33, 0x0b, 0x52]);
    }

    #[test]
    fn bbp_mode_table_is_indexed_by_temp_and_bw() {
        assert_eq!(
            BBP_MODE_TABLE[MT_TEMP_MODE_NORMAL as usize][MT_BW_20 as usize].len(),
            10
        );
        assert_eq!(BBP_MODE_TABLE[MT_TEMP_MODE_NORMAL as usize][2].len(), 5);
    }
}
