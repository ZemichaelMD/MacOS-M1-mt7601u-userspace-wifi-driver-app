//! eFuse / EEPROM reading, transcribed from `eeprom.c` / `eeprom.h`.
//!
//! The MT7601U stores its MAC address, channel plan and TX-power calibration in
//! an on-chip eFuse, read through `MT_EFUSE_CTRL` / `MT_EFUSE_DATA(n)`.

use std::time::Duration;

use crate::usb::{Transport, UsbError};

use super::device::Mt7601u;
use super::regs;

/// `MT7601U_EEPROM_SIZE`.
pub const EEPROM_SIZE: usize = 256;
/// `MT7601U_EE_MAX_VER`.
pub const EE_MAX_VER: u8 = 0x0d;
/// `MT7601U_DEFAULT_TX_POWER`.
pub const DEFAULT_TX_POWER: i8 = 6;
/// `MT_EFUSE_USAGE_MAP_SIZE`.
pub const EFUSE_USAGE_MAP_SIZE: usize = EE_USAGE_MAP_END - EE_USAGE_MAP_START + 1;

// `enum mt76_eeprom_field` offsets.
/// `MT_EE_VERSION_FAE`.
pub const EE_VERSION_FAE: usize = 0x02;
/// `MT_EE_VERSION_EE`.
pub const EE_VERSION_EE: usize = 0x03;
/// `MT_EE_MAC_ADDR`.
pub const EE_MAC_ADDR: usize = 0x04;
/// `MT_EE_NIC_CONF_0`.
pub const EE_NIC_CONF_0: usize = 0x34;
/// `MT_EE_NIC_CONF_1`.
pub const EE_NIC_CONF_1: usize = 0x36;
/// `MT_EE_COUNTRY_REGION`.
pub const EE_COUNTRY_REGION: usize = 0x39;
/// `MT_EE_FREQ_OFFSET`.
pub const EE_FREQ_OFFSET: usize = 0x3a;
/// `MT_EE_LNA_GAIN`.
pub const EE_LNA_GAIN: usize = 0x44;
/// `MT_EE_RSSI_OFFSET`.
pub const EE_RSSI_OFFSET: usize = 0x46;
/// `MT_EE_TX_POWER_DELTA_BW40`.
pub const EE_TX_POWER_DELTA_BW40: usize = 0x50;
/// `MT_EE_TX_POWER_OFFSET`.
pub const EE_TX_POWER_OFFSET: usize = 0x52;
/// `MT_EE_TX_TSSI_TARGET_POWER`.
pub const EE_TX_TSSI_TARGET_POWER: usize = 0xd0;
/// `MT_EE_REF_TEMP`.
pub const EE_REF_TEMP: usize = 0xd1;
/// `MT_EE_FREQ_OFFSET_COMPENSATION`.
pub const EE_FREQ_OFFSET_COMP: usize = 0xdb;
/// `MT_EE_TX_POWER_BYRATE_BASE`.
pub const EE_TX_POWER_BYRATE_BASE: usize = 0xde;
/// `MT_EE_USAGE_MAP_START`.
pub const EE_USAGE_MAP_START: usize = 0x1e0;
/// `MT_EE_USAGE_MAP_END`.
pub const EE_USAGE_MAP_END: usize = 0x1fc;

/// `MT_EE_NIC_CONF_0_RX_PATH` (`GENMASK(3, 0)`).
pub const EE_NIC_CONF_0_RX_PATH: u16 = 0xf;
/// `MT_EE_NIC_CONF_0_TX_PATH` (`GENMASK(7, 4)`).
pub const EE_NIC_CONF_0_TX_PATH: u16 = 0xf0;
/// `MT_EE_NIC_CONF_1_HW_RF_CTRL` (`BIT(0)`).
pub const EE_NIC_CONF_1_HW_RF_CTRL: u16 = 1 << 0;
/// `MT_EE_NIC_CONF_1_TEMP_TX_ALC` (`BIT(1)`).
pub const EE_NIC_CONF_1_TEMP_TX_ALC: u16 = 1 << 1;
/// `MT_EE_NIC_CONF_1_TX_ALC_EN` (`BIT(13)`).
pub const EE_NIC_CONF_1_TX_ALC_EN: u16 = 1 << 13;

/// `enum mt7601u_eeprom_access_modes`.
pub const EE_READ: u32 = 0;
/// Physical eFuse read used for the usage map.
pub const EE_PHYSICAL_READ: u32 = 1;

/// Channel regions (`chan_bounds` in `mt7601u_set_country_reg`).
pub const CHAN_BOUNDS: [(u8, u8); 10] = [
    (1, 11),
    (1, 13),
    (10, 2),
    (10, 4),
    (14, 1),
    (1, 14),
    (3, 7),
    (5, 9),
    (1, 11),
    (1, 14),
];

/// `struct power_per_rate`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PowerPerRate {
    /// Validated s6 value.
    pub raw: u8,
    /// Sign-extended BW20 power.
    pub bw20: i8,
    /// BW40 power (BW20 + delta).
    pub bw40: i8,
}

/// `struct mt7601u_rate_power`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RatePower {
    pub cck: [PowerPerRate; 2],
    pub ofdm: [PowerPerRate; 4],
    pub ht: [PowerPerRate; 4],
}

/// Parsed EEPROM parameters (`struct mt7601u_eeprom_params`).
#[derive(Debug, Clone)]
pub struct Eeprom {
    /// Raw 256-byte image.
    pub raw: [u8; EEPROM_SIZE],
    pub version_ee: u8,
    pub version_fae: u8,
    pub mac_addr: [u8; 6],
    pub tssi_enabled: bool,
    pub rf_freq_off: u8,
    pub rssi_offset: [i8; 2],
    pub ref_temp: i8,
    pub lna_gain: i8,
    pub chan_pwr: [u8; 14],
    pub power_rate_table: RatePower,
    pub real_cck_bw20: [i8; 2],
    /// First channel of the region.
    pub channel_start: u8,
    /// Number of channels in the region.
    pub channel_count: u8,
}

impl Eeprom {
    /// Inclusive channel range.
    pub fn channels(&self) -> std::ops::RangeInclusive<u8> {
        self.channel_start..=self.channel_start + self.channel_count - 1
    }

    /// MAC address formatted `aa:bb:cc:dd:ee:ff`.
    pub fn mac_string(&self) -> String {
        self.mac_addr
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// `s6_validate` + `s6_to_int`: interpret a 6-bit signed value.
pub fn s6_to_int(value: u32) -> i32 {
    let s6 = value & 0x3f;
    if s6 & 0x20 != 0 {
        s6 as i32 - 0x40
    } else {
        s6 as i32
    }
}

/// Country-region byte to channel `(start, count)` (`mt7601u_set_country_reg`).
/// Invalid regions fall back to channels 1-14.
pub fn country_channels(value: u8) -> (u8, u8) {
    let index = if value < 8 {
        Some(value as usize)
    } else if value == 32 {
        Some(8)
    } else {
        None
    };
    match index {
        Some(index) => CHAN_BOUNDS[index],
        None => CHAN_BOUNDS[5],
    }
}

/// `field_valid`: 0xff means "not present".
pub fn field_valid(value: u8) -> bool {
    value != 0xff
}

fn field_validate(value: u8) -> i8 {
    if field_valid(value) {
        value as i8
    } else {
        0
    }
}

/// `get_delta`: decode the BW40 power delta byte.
pub fn get_delta(value: u8) -> i8 {
    if !field_valid(value) || value & 0x80 == 0 {
        return 0;
    }
    let mut ret = (value & 0x1f) as i8;
    if ret > 8 {
        ret = 8;
    }
    if value & 0x40 != 0 {
        ret = -ret;
    }
    ret
}

/// `mt7601u_set_power_rate`.
fn set_power_rate(rate: &mut PowerPerRate, delta: i8, value: u8) {
    if value == 0xff {
        return;
    }
    rate.raw = value & 0x3f;
    rate.bw20 = s6_to_int(u32::from(value)) as i8;
    rate.bw40 = rate.bw20.saturating_add(delta);
}

/// `mt7601u_save_power_rate`.
fn save_power_rate(table: &mut RatePower, delta: i8, value: u32, index: usize) {
    match index {
        0 => {
            set_power_rate(&mut table.cck[0], delta, (value & 0xff) as u8);
            set_power_rate(&mut table.cck[1], delta, ((value >> 8) & 0xff) as u8);
            set_power_rate(&mut table.ofdm[0], delta, ((value >> 16) & 0xff) as u8);
            set_power_rate(&mut table.ofdm[1], delta, ((value >> 24) & 0xff) as u8);
        }
        1 => {
            set_power_rate(&mut table.ofdm[2], delta, (value & 0xff) as u8);
            set_power_rate(&mut table.ofdm[3], delta, ((value >> 8) & 0xff) as u8);
            set_power_rate(&mut table.ht[0], delta, ((value >> 16) & 0xff) as u8);
            set_power_rate(&mut table.ht[1], delta, ((value >> 24) & 0xff) as u8);
        }
        2 => {
            set_power_rate(&mut table.ht[2], delta, (value & 0xff) as u8);
            set_power_rate(&mut table.ht[3], delta, ((value >> 8) & 0xff) as u8);
        }
        _ => {}
    }
}

impl<T: Transport> Mt7601u<T> {
    /// `mt7601u_efuse_read`: read 16 bytes starting at `addr`.
    pub fn efuse_read(&self, addr: u16, mode: u32) -> Result<[u8; 16], UsbError> {
        let mut value = self.read_reg(regs::MT_EFUSE_CTRL)?;
        value &= !((regs::MT_EFUSE_CTRL_AIN << regs::MT_EFUSE_CTRL_AIN_SHIFT)
            | (regs::MT_EFUSE_CTRL_MODE << regs::MT_EFUSE_CTRL_MODE_SHIFT));
        value |= (u32::from(addr) & !0xf) << regs::MT_EFUSE_CTRL_AIN_SHIFT;
        value |= (mode & regs::MT_EFUSE_CTRL_MODE) << regs::MT_EFUSE_CTRL_MODE_SHIFT;
        value |= regs::MT_EFUSE_CTRL_KICK;
        self.write_reg(regs::MT_EFUSE_CTRL, value)?;

        self.poll_reg(
            regs::MT_EFUSE_CTRL,
            regs::MT_EFUSE_CTRL_KICK,
            0,
            Duration::from_millis(100),
        )?;

        let value = self.read_reg(regs::MT_EFUSE_CTRL)?;
        if value & regs::MT_EFUSE_CTRL_AOUT == regs::MT_EFUSE_CTRL_AOUT {
            return Ok([0xff; 16]);
        }

        let mut data = [0u8; 16];
        for index in 0..4u32 {
            let word = self.read_reg(regs::MT_EFUSE_DATA_BASE + index * 4)?;
            data[index as usize * 4..index as usize * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(data)
    }

    /// `mt7601u_efuse_physical_size_check`: require at least 5 used bytes.
    fn efuse_physical_size_check(&self) -> Result<(), UsbError> {
        let reads = EFUSE_USAGE_MAP_SIZE.div_ceil(16);
        let mut data = [0u8; EFUSE_USAGE_MAP_SIZE.next_multiple_of(16)];
        for index in 0..reads {
            let chunk =
                self.efuse_read((EE_USAGE_MAP_START + index * 16) as u16, EE_PHYSICAL_READ)?;
            data[index * 16..index * 16 + 16].copy_from_slice(&chunk);
        }

        // `start` stays 0 when no zero byte is found, matching the C code.
        let mut start = 0usize;
        let mut end = 0usize;
        for (index, byte) in data[..EFUSE_USAGE_MAP_SIZE].iter().enumerate() {
            if *byte == 0 {
                if start == 0 {
                    start = EE_USAGE_MAP_START + index;
                }
                end = EE_USAGE_MAP_START + index;
            }
        }
        let free = if start == 0 { 1 } else { end - start + 1 };

        if EFUSE_USAGE_MAP_SIZE - free < 5 {
            return Err(UsbError::Other(
                "device needs a default EEPROM file (unsupported)".to_string(),
            ));
        }
        Ok(())
    }

    /// `mt7601u_set_macaddr` / `mt7601u_addr_wr`.
    pub fn set_mac_address(&self, address: &[u8; 6]) -> Result<(), UsbError> {
        let low = u32::from_le_bytes([address[0], address[1], address[2], address[3]]);
        self.write_reg(regs::MT_MAC_ADDR_DW0, low)?;
        let high = u32::from(address[4]) | (u32::from(address[5]) << 8);
        self.write_reg(regs::MT_MAC_ADDR_DW1, high)?;
        Ok(())
    }

    /// `mt7601u_set_chip_cap`.
    fn set_chip_cap(&self, nic_conf_0: u16, nic_conf_1: u16) -> bool {
        if nic_conf_1 & EE_NIC_CONF_1_HW_RF_CTRL != 0 {
            tracing::warn!("this driver does not support HW RF control");
        }

        if field_valid((nic_conf_0 >> 8) as u8) {
            let rx_path = nic_conf_0 & EE_NIC_CONF_0_RX_PATH;
            let tx_path = (nic_conf_0 & EE_NIC_CONF_0_TX_PATH) >> 4;
            if rx_path > 1 || tx_path > 1 {
                tracing::warn!("device reports more than one RX/TX stream");
            }
        }

        let has_tssi = nic_conf_1 != 0xffff && nic_conf_1 & EE_NIC_CONF_1_TX_ALC_EN != 0;
        has_tssi && nic_conf_1 & EE_NIC_CONF_1_TEMP_TX_ALC == 0
    }

    /// `mt7601u_set_channel_power`.
    fn set_channel_power(
        &self,
        eeprom: &[u8; EEPROM_SIZE],
        tssi_enabled: bool,
    ) -> Result<[u8; 14], UsbError> {
        let value = self.read_reg(regs::MT_TX_ALC_CFG_0)?;
        let max_pwr =
            ((value >> regs::MT_TX_ALC_CFG_0_LIMIT_0_SHIFT) & regs::MT_TX_ALC_CFG_0_LIMIT_0) as u8;

        if tssi_enabled {
            let mut target = eeprom[EE_TX_TSSI_TARGET_POWER];
            if target > max_pwr || target == 0 {
                tracing::warn!("EEPROM target power invalid {target:#04x}");
                target = 0x20;
            }
            return Ok([target; 14]);
        }

        let mut chan_pwr = [0u8; 14];
        for (index, slot) in chan_pwr.iter_mut().enumerate() {
            let mut power = field_validate(eeprom[EE_TX_POWER_OFFSET + index]);
            if power > max_pwr as i8 || power < 0 {
                power = DEFAULT_TX_POWER;
            }
            *slot = power as u8;
        }
        Ok(chan_pwr)
    }

    /// `mt7601u_set_rf_freq_off`.
    fn set_rf_freq_off(&self, eeprom: &[u8; EEPROM_SIZE]) -> u8 {
        let base = field_validate(eeprom[EE_FREQ_OFFSET]) as u8;
        let compensation = field_validate(eeprom[EE_FREQ_OFFSET_COMP]) as u8;
        if compensation & 0x80 != 0 {
            base.wrapping_sub(compensation & 0x7f)
        } else {
            base.wrapping_add(compensation)
        }
    }

    /// `mt7601u_set_rssi_offset`.
    fn set_rssi_offset(eeprom: &[u8; EEPROM_SIZE]) -> [i8; 2] {
        let mut offsets = [0i8; 2];
        for (index, slot) in offsets.iter_mut().enumerate() {
            let value = eeprom[EE_RSSI_OFFSET + index] as i8;
            if !(-10..=10).contains(&value) {
                tracing::warn!("EEPROM RSSI offset invalid {value}");
                *slot = 0;
            } else {
                *slot = value;
            }
        }
        offsets
    }

    /// `mt7601u_config_tx_power_per_rate` + `mt7601u_extra_power_over_mac`.
    fn config_tx_power_per_rate(
        &self,
        eeprom: &[u8; EEPROM_SIZE],
    ) -> Result<(RatePower, [i8; 2]), UsbError> {
        let delta = get_delta(eeprom[EE_TX_POWER_DELTA_BW40]);
        let mut table = RatePower::default();

        for index in 0..5usize {
            let offset = EE_TX_POWER_BYRATE_BASE + index * 4;
            let value = u32::from_le_bytes([
                eeprom[offset],
                eeprom[offset + 1],
                eeprom[offset + 2],
                eeprom[offset + 3],
            ]);

            save_power_rate(&mut table, delta, value, index);

            if value != 0xffff_ffff {
                self.write_reg(regs::MT_TX_PWR_CFG_0 + index as u32 * 4, value)?;
            }
        }

        let real_cck_bw20 = [table.cck[0].bw20, table.cck[1].bw20];

        let mut value = (self.read_reg(regs::MT_TX_PWR_CFG_1)? & 0x0000_ff00) >> 8;
        value |= (self.read_reg(regs::MT_TX_PWR_CFG_2)? & 0x0000_ff00) << 8;
        self.write_reg(regs::MT_TX_PWR_CFG_7, value)?;

        let value = (self.read_reg(regs::MT_TX_PWR_CFG_4)? & 0x0000_ff00) >> 8;
        self.write_reg(regs::MT_TX_PWR_CFG_9, value)?;

        Ok((table, real_cck_bw20))
    }

    /// `mt7601u_eeprom_init`: read the eFuse, program the MAC address and TX
    /// power, and return the parsed parameters.
    pub fn eeprom_init(&self) -> Result<Eeprom, UsbError> {
        self.efuse_physical_size_check()?;

        let mut raw = [0u8; EEPROM_SIZE];
        for offset in (0..EEPROM_SIZE).step_by(16) {
            let chunk = self.efuse_read(offset as u16, EE_READ)?;
            raw[offset..offset + 16].copy_from_slice(&chunk);
        }

        let mut mac_addr = [0u8; 6];
        mac_addr.copy_from_slice(&raw[EE_MAC_ADDR..EE_MAC_ADDR + 6]);
        self.set_mac_address(&mac_addr)?;

        let nic_conf_0 = u16::from_le_bytes([raw[EE_NIC_CONF_0], raw[EE_NIC_CONF_0 + 1]]);
        let mut nic_conf_1 = u16::from_le_bytes([raw[EE_NIC_CONF_1], raw[EE_NIC_CONF_1 + 1]]);
        if !field_valid((nic_conf_1 & 0xff) as u8) {
            nic_conf_1 &= 0xff00;
        }
        let tssi_enabled = self.set_chip_cap(nic_conf_0, nic_conf_1);

        let chan_pwr = self.set_channel_power(&raw, tssi_enabled)?;
        let (channel_start, channel_count) = country_channels(raw[EE_COUNTRY_REGION]);
        let rf_freq_off = self.set_rf_freq_off(&raw);
        let rssi_offset = Self::set_rssi_offset(&raw);
        let (power_rate_table, real_cck_bw20) = self.config_tx_power_per_rate(&raw)?;

        Ok(Eeprom {
            raw,
            version_ee: raw[EE_VERSION_EE],
            version_fae: raw[EE_VERSION_FAE],
            mac_addr,
            tssi_enabled,
            rf_freq_off,
            rssi_offset,
            ref_temp: raw[EE_REF_TEMP] as i8,
            lna_gain: raw[EE_LNA_GAIN] as i8,
            chan_pwr,
            power_rate_table,
            real_cck_bw20,
            channel_start,
            channel_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{device_info, MockTransport};

    #[test]
    fn s6_conversion_sign_extends() {
        assert_eq!(s6_to_int(0x0a), 10);
        assert_eq!(s6_to_int(0x3f), -1);
        assert_eq!(s6_to_int(0x20), -32);
    }

    #[test]
    fn country_region_maps_to_channels() {
        assert_eq!(country_channels(0), (1, 11));
        assert_eq!(country_channels(5), (1, 14));
        assert_eq!(country_channels(32), (1, 11));
        assert_eq!(country_channels(40), (1, 14));
    }

    #[test]
    fn get_delta_decodes_bw40_delta() {
        assert_eq!(get_delta(0xff), 0);
        assert_eq!(get_delta(0x05), 0); // high bit clear -> not a delta
        assert_eq!(get_delta(0x80 | 5), 5);
        assert_eq!(get_delta(0x80 | 0x40 | 3), -3);
        assert_eq!(get_delta(0x80 | 0x1f), 8); // clamped
    }

    #[test]
    fn save_power_rate_places_values() {
        let mut table = RatePower::default();
        // cck0=0x05, cck1=0x06, ofdm0=0x07, ofdm1=0x08
        save_power_rate(&mut table, 2, 0x0807_0605, 0);
        assert_eq!(table.cck[0].bw20, 5);
        assert_eq!(table.cck[1].bw20, 6);
        assert_eq!(table.ofdm[0].bw20, 7);
        assert_eq!(table.ofdm[1].bw20, 8);
        assert_eq!(table.cck[0].bw40, 7);
    }

    #[test]
    fn power_rate_ignores_unset_bytes() {
        let mut table = RatePower::default();
        save_power_rate(&mut table, 0, 0xffff_ffff, 0);
        assert_eq!(table.cck[0], PowerPerRate::default());
    }

    #[test]
    fn eeprom_channels_range_is_inclusive_and_formats_mac() {
        let eeprom = Eeprom {
            raw: [0; EEPROM_SIZE],
            version_ee: 0,
            version_fae: 0,
            mac_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            tssi_enabled: false,
            rf_freq_off: 0,
            rssi_offset: [0, 0],
            ref_temp: 0,
            lna_gain: 0,
            chan_pwr: [0; 14],
            power_rate_table: RatePower::default(),
            real_cck_bw20: [0, 0],
            channel_start: 1,
            channel_count: 13,
        };
        assert_eq!(eeprom.channels().start(), &1);
        assert_eq!(eeprom.channels().end(), &13);
        assert_eq!(eeprom.mac_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn efuse_read_all_ones_on_unmapped_area() {
        let mock =
            MockTransport::with_registers(&[(regs::MT_EFUSE_CTRL, regs::MT_EFUSE_CTRL_AOUT)]);
        let chip = Mt7601u::new(mock, device_info());
        assert_eq!(chip.efuse_read(0, EE_READ).unwrap(), [0xff; 16]);
    }

    #[test]
    fn efuse_read_returns_data_words() {
        let mock = MockTransport::with_registers(&[
            (regs::MT_EFUSE_CTRL, 0),
            (regs::MT_EFUSE_DATA_BASE, 0x0403_0201),
            (regs::MT_EFUSE_DATA_BASE + 4, 0x0807_0605),
            (regs::MT_EFUSE_DATA_BASE + 8, 0x0c0b_0a09),
            (regs::MT_EFUSE_DATA_BASE + 12, 0x100f_0e0d),
        ]);
        let chip = Mt7601u::new(mock, device_info());
        let data = chip.efuse_read(0, EE_READ).unwrap();
        assert_eq!(data[0..4], [1, 2, 3, 4]);
        assert_eq!(data[12..16], [13, 14, 15, 16]);
    }

    #[test]
    fn field_valid_rejects_ff() {
        assert!(field_valid(0x00));
        assert!(!field_valid(0xff));
    }
}
