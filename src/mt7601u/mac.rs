//! MAC-layer station setup, transcribed from `mac.c` and the
//! `mt7601u_bss_info_changed` callback in `main.c`.
//!
//! These primitives program the station's own address, the AP BSSID and its
//! WCID entry, the beacon/TSF timer and the basic-rate fallback tables. They are
//! the register half of association; the 802.11 exchange itself lives in
//! [`super::station`].

use crate::usb::{Transport, UsbError};

use super::device::Mt7601u;
use super::regs;

/// `N_WCIDS` (`mt7601u.h`).
pub const N_WCIDS: u8 = 128;
/// `GROUP_WCID(0)` (`mt7601u.h`): the group WCID, used for management frames
/// and broadcast/multicast data frames. Its key slot holds the group key (GTK)
/// once WPA2 keys are installed (`mt7601u_set_key` with `sta == NULL`).
pub const GROUP_WCID_0: u8 = N_WCIDS - 2;

/// `mt76_wcid_alloc` in `mt7601u_sta_add`: the WCID entry programmed for the
/// associated AP. Unicast data frames use this entry, whose key slot holds the
/// pairwise key (PTK).
pub const STA_WCID: u8 = 1;

/// A WCID entry programmed with this station's **own** address, holding the
/// pairwise key.
///
/// The hardware picks the key to decrypt a received frame by matching the
/// frame's addresses against the WCID address table (that is why the group WCID
/// must keep the broadcast address for group-addressed traffic). Nothing else
/// holds our own address, so without this entry a **unicast** frame addressed to
/// us — a DHCP OFFER, an ARP reply, an ICMP echo reply — has no key to decrypt
/// it with and is dropped. The handshake EAPOL frames are sent unencrypted, so
/// this was never exercised until real reply traffic arrived.
pub const OWN_WCID: u8 = 2;

// The station entry must stay below the group range.
const _: () = assert!(STA_WCID < GROUP_WCID_0);

// Values written by `bss_info_changed`'s `BSS_CHANGED_BASIC_RATES` branch.
const HT_FBK_CFG0_VALUE: u32 = 0x6543_2100;
const HT_FBK_CFG1_VALUE: u32 = 0xedcb_a980;
const LG_FBK_CFG0_VALUE: u32 = 0xedcb_a988;
const LG_FBK_CFG1_VALUE: u32 = 0x0000_2100;
// `MT_MAX_LEN_CFG` non-AMPDU bits written by `mt7601u_mac_set_ampdu_factor`.
const MAX_LEN_CFG_BASE: u32 = 0xa0fff;

impl<T: Transport> Mt7601u<T> {
    /// `mt7601u_addr_wr`: write a 6-byte address as two little-endian words.
    pub fn addr_wr(&self, offset: u32, addr: &[u8; 6]) -> Result<(), UsbError> {
        let low = u32::from_le_bytes([addr[0], addr[1], addr[2], addr[3]]);
        self.write_reg(offset, low)?;
        let high = u32::from(addr[4]) | (u32::from(addr[5]) << 8);
        self.write_reg(offset + 4, high)
    }

    /// `mt7601u_set_macaddr`: program the station's own MAC address. The high
    /// word also sets `MT_MAC_ADDR_DW1_U2ME` to 0xff, so unicast frames
    /// addressed to this station pass the receive filter.
    pub fn set_macaddr(&self, addr: &[u8; 6]) -> Result<(), UsbError> {
        let low = u32::from_le_bytes([addr[0], addr[1], addr[2], addr[3]]);
        self.write_reg(regs::MT_MAC_ADDR_DW0, low)?;
        let high = u32::from(addr[4])
            | (u32::from(addr[5]) << 8)
            | (regs::MT_MAC_ADDR_DW1_U2ME << regs::MT_MAC_ADDR_DW1_U2ME_SHIFT);
        self.write_reg(regs::MT_MAC_ADDR_DW1, high)
    }

    /// Set the AP BSSID (`MT_MAC_BSSID_DW0`), from the `BSS_CHANGED_BSSID`
    /// branch of `mt7601u_bss_info_changed`.
    pub fn set_bssid(&self, bssid: &[u8; 6]) -> Result<(), UsbError> {
        self.addr_wr(regs::MT_MAC_BSSID_DW0, bssid)
    }

    /// `mt7601u_mac_wcid_setup`: program the VIF index in the WCID attribute
    /// table and the peer address in the WCID address table. `mac == None`
    /// clears the entry with a zero address.
    pub fn mac_wcid_setup(
        &self,
        index: u8,
        vif_index: u8,
        mac: Option<&[u8; 6]>,
    ) -> Result<(), UsbError> {
        let mut attr =
            (u32::from(vif_index) & regs::MT_WCID_ATTR_BSS_IDX) << regs::MT_WCID_ATTR_BSS_IDX_SHIFT;
        if vif_index & 8 != 0 {
            attr |= regs::MT_WCID_ATTR_BSS_IDX_EXT;
        }
        self.write_reg(regs::mt_wcid_attr(index), attr)?;

        let zero = [0u8; 6];
        self.addr_wr(regs::mt_wcid_addr(index), mac.unwrap_or(&zero))
    }

    /// `mt76_clear(MT_WCID_DROP(idx), MT_WCID_DROP_MASK(idx))` from
    /// `mt7601u_sta_add`: allow traffic for this WCID entry.
    pub fn mac_wcid_clear_drop(&self, index: u8) -> Result<(), UsbError> {
        self.rmw(regs::mt_wcid_drop(index), regs::mt_wcid_drop_mask(index), 0)
            .map(|_| ())
    }

    /// `mt7601u_mac_config_tsf`: enable/disable the beacon timer and TSF sync.
    ///
    /// Note: upstream `mac.c` computes the enabled value but omits the final
    /// `mt7601u_wr` (the function falls through without writing). That appears
    /// to be a bug — the timer would never be enabled — so this port writes the
    /// configured value.
    pub fn mac_config_tsf(&self, enable: bool, interval: u16) -> Result<(), UsbError> {
        let mut value = self.read_reg(regs::MT_BEACON_TIME_CFG)?;
        value &= !(regs::MT_BEACON_TIME_CFG_TIMER_EN
            | regs::MT_BEACON_TIME_CFG_SYNC_MODE
            | regs::MT_BEACON_TIME_CFG_TBTT_EN);

        if !enable {
            return self.write_reg(regs::MT_BEACON_TIME_CFG, value);
        }

        value &= !regs::MT_BEACON_TIME_CFG_INTVAL;
        value |= (u32::from(interval) << 4) & regs::MT_BEACON_TIME_CFG_INTVAL;
        value |= regs::MT_BEACON_TIME_CFG_TIMER_EN
            | regs::MT_BEACON_TIME_CFG_SYNC_MODE
            | regs::MT_BEACON_TIME_CFG_TBTT_EN;
        self.write_reg(regs::MT_BEACON_TIME_CFG, value)
    }

    /// `MT_LEGACY_BASIC_RATE` plus the HT/legacy fallback tables, from the
    /// `BSS_CHANGED_BASIC_RATES` branch of `mt7601u_bss_info_changed`.
    pub fn mac_set_basic_rates(&self, basic_rates: u32) -> Result<(), UsbError> {
        self.write_reg(regs::MT_LEGACY_BASIC_RATE, basic_rates)?;
        self.write_reg(regs::MT_HT_FBK_CFG0, HT_FBK_CFG0_VALUE)?;
        self.write_reg(regs::MT_HT_FBK_CFG1, HT_FBK_CFG1_VALUE)?;
        self.write_reg(regs::MT_LG_FBK_CFG0, LG_FBK_CFG0_VALUE)?;
        self.write_reg(regs::MT_LG_FBK_CFG1, LG_FBK_CFG1_VALUE)
    }

    /// `mt7601u_mac_set_short_preamble`.
    pub fn mac_set_short_preamble(&self, short: bool) -> Result<(), UsbError> {
        if short {
            self.set_bits(regs::MT_AUTO_RSP_CFG, regs::MT_AUTO_RSP_PREAMB_SHORT)
        } else {
            self.rmw(regs::MT_AUTO_RSP_CFG, regs::MT_AUTO_RSP_PREAMB_SHORT, 0)
        }
        .map(|_| ())
    }

    /// Slot time, from the `BSS_CHANGED_ERP_SLOT` branch of
    /// `mt7601u_bss_info_changed` (`9` µs short slot, `20` µs long slot).
    pub fn mac_set_slot_time(&self, slot_us: u32) -> Result<(), UsbError> {
        self.rmw(
            regs::MT_BKOFF_SLOT_CFG,
            regs::MT_BKOFF_SLOT_CFG_SLOTTIME,
            slot_us & regs::MT_BKOFF_SLOT_CFG_SLOTTIME,
        )
        .map(|_| ())
    }

    /// `MT_MAX_LEN_CFG` AMPDU factor, from `mt7601u_mac_set_ampdu_factor`.
    pub fn mac_set_ampdu_factor(&self, factor: u8) -> Result<(), UsbError> {
        let value = MAX_LEN_CFG_BASE
            | ((u32::from(factor) & regs::MT_MAX_LEN_CFG_AMPDU)
                << regs::MT_MAX_LEN_CFG_AMPDU_SHIFT);
        self.write_reg(regs::MT_MAX_LEN_CFG, value)
    }

    /// `mt7601u_wr_copy`: burst-write raw bytes into the WLAN memory map.
    pub fn wr_copy(&self, offset: u32, data: &[u8]) -> Result<(), UsbError> {
        if !data.len().is_multiple_of(4) {
            return Err(UsbError::Other(format!(
                "wr_copy length {} is not a multiple of 4",
                data.len()
            )));
        }
        let words: Vec<u32> = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_le_bytes(*chunk))
            .collect();
        self.mcu_burst_write_regs(offset, &words)
    }

    /// `mt76_mac_wcid_set_key`: install a pairwise key for a WCID entry.
    ///
    /// `key` is the 32-byte key slot (a CCMP TK padded with zeros).
    pub fn mac_wcid_set_key(
        &self,
        index: u8,
        key: &[u8; 32],
        cipher: u8,
        key_index: u8,
        pairwise: bool,
    ) -> Result<(), UsbError> {
        self.wr_copy(regs::mt_wcid_key(index), key)?;

        let mut iv = [0u8; 8];
        if cipher != regs::MT_CIPHER_NONE {
            iv[3] = key_index << 6;
            if cipher >= regs::MT_CIPHER_TKIP {
                // Start the packet number at 1 (vendor driver note).
                iv[0] |= 1;
                iv[3] |= 0x20;
            }
        }
        self.wr_copy(regs::mt_wcid_iv(index), &iv)?;

        let attr = regs::mt_wcid_attr(index);
        let mut value = self.read_reg(attr)?;
        value &= !(regs::MT_WCID_ATTR_PKEY_MODE | regs::MT_WCID_ATTR_PKEY_MODE_EXT);
        value |= (u32::from(cipher) & regs::MT_WCID_ATTR_PKEY_MODE_FIELD)
            << regs::MT_WCID_ATTR_PKEY_MODE_SHIFT;
        value |= ((u32::from(cipher) >> 3) & 1) << regs::MT_WCID_ATTR_PKEY_MODE_EXT_SHIFT;
        value &= !regs::MT_WCID_ATTR_PAIRWISE;
        if pairwise {
            value |= regs::MT_WCID_ATTR_PAIRWISE;
        }
        self.write_reg(attr, value)
    }

    /// `mt76_mac_shared_key_setup`: install a group key for a VIF.
    pub fn mac_shared_key_setup(
        &self,
        vif: u8,
        key_index: u8,
        key: &[u8; 32],
        cipher: u8,
    ) -> Result<(), UsbError> {
        self.wr_copy(regs::mt_skey(vif, key_index), key)?;

        let mode = regs::mt_skey_mode(vif);
        let shift = regs::mt_skey_mode_shift(vif, key_index);
        let mut value = self.read_reg(mode)?;
        value &= !(regs::MT_SKEY_MODE_MASK << shift);
        value |= (u32::from(cipher) & regs::MT_SKEY_MODE_MASK) << shift;
        self.write_reg(mode, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{device_info, Call, MockTransport};

    fn chip(mock: MockTransport) -> Mt7601u<MockTransport> {
        Mt7601u::new(mock, device_info())
    }

    /// The `(value, index)` pairs of the register OUT transfers, in order.
    fn writes(chip: &Mt7601u<MockTransport>) -> Vec<(u16, u16)> {
        chip.transport()
            .calls()
            .iter()
            .filter_map(|call| match call {
                Call::Out { value, index, .. } => Some((*value, *index)),
                Call::In { .. } => None,
            })
            .collect()
    }

    /// The low/high halves of the final `write_reg`.
    fn last_write(chip: &Mt7601u<MockTransport>) -> (u32, u32) {
        let out = writes(chip);
        let low = u32::from(out[out.len() - 2].0);
        let high = u32::from(out[out.len() - 1].0);
        (low, high)
    }

    #[test]
    fn set_macaddr_sets_u2me_in_the_high_word() {
        let chip = chip(MockTransport::default());
        chip.set_macaddr(&[0x88, 0x82, 0x79, 0x24, 0x0e, 0xc0])
            .unwrap();

        let out = writes(&chip);
        // DW0 little-endian = 0x24798288 -> low 0x8288, high 0x2479.
        assert_eq!(out[0], (0x8288, regs::MT_MAC_ADDR_DW0 as u16));
        assert_eq!(out[1], (0x2479, regs::MT_MAC_ADDR_DW0 as u16 + 2));
        // DW1 = 0xc00e | 0xff << 16 -> low 0xc00e, high 0x00ff (U2ME).
        assert_eq!(out[2], (0xc00e, regs::MT_MAC_ADDR_DW1 as u16));
        assert_eq!(out[3], (0x00ff, regs::MT_MAC_ADDR_DW1 as u16 + 2));
    }

    #[test]
    fn set_bssid_writes_two_words_at_the_bssid_register() {
        let chip = chip(MockTransport::default());
        chip.set_bssid(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
            .unwrap();

        let out = writes(&chip);
        // DW0 little-endian = 0xddccbbaa -> low 0xbbaa, high 0xddcc.
        assert_eq!(out[0], (0xbbaa, regs::MT_MAC_BSSID_DW0 as u16));
        assert_eq!(out[1], (0xddcc, regs::MT_MAC_BSSID_DW0 as u16 + 2));
        assert_eq!(out[2], (0xffee, regs::MT_MAC_BSSID_DW0 as u16 + 4));
        assert_eq!(out[3], (0x0000, regs::MT_MAC_BSSID_DW0 as u16 + 6));
    }

    #[test]
    fn wcid_setup_writes_attr_then_address() {
        let chip = chip(MockTransport::default());
        chip.mac_wcid_setup(GROUP_WCID_0, 3, Some(&[1, 2, 3, 4, 5, 6]))
            .unwrap();

        let out = writes(&chip);
        let attr = regs::mt_wcid_attr(GROUP_WCID_0);
        assert_eq!(out[0], (0x0030, attr as u16)); // vif 3 << 4
        assert_eq!(out[1], (0x0000, attr as u16 + 2));
        let addr = regs::mt_wcid_addr(GROUP_WCID_0);
        assert_eq!(addr, 0x1800 + u32::from(GROUP_WCID_0) * 8);
        // Address little-endian = 0x04030201 -> low 0x0201, high 0x0403.
        assert_eq!(out[2], (0x0201, addr as u16));
        assert_eq!(out[3], (0x0403, addr as u16 + 2));
        assert_eq!(out[4], (0x0605, addr as u16 + 4));
    }

    #[test]
    fn wcid_setup_sets_the_extended_vif_bit() {
        let chip = chip(MockTransport::default());
        chip.mac_wcid_setup(5, 8, None).unwrap();

        // The attribute write is the first pair of OUT transfers.
        let out = writes(&chip);
        let attr = u32::from(out[0].0) | (u32::from(out[1].0) << 16);
        // vif 8: BSS_IDX = 0, BSS_IDX_EXT (bit 11) set.
        assert_eq!(attr & regs::MT_WCID_ATTR_BSS_IDX_EXT, 1 << 11);
        assert_eq!(
            attr & (regs::MT_WCID_ATTR_BSS_IDX << regs::MT_WCID_ATTR_BSS_IDX_SHIFT),
            0
        );
    }

    #[test]
    fn config_tsf_enables_interval_and_timer() {
        let mock = MockTransport::with_registers(&[(regs::MT_BEACON_TIME_CFG, 0)]);
        let chip = chip(mock);
        chip.mac_config_tsf(true, 100).unwrap();

        let (low, high) = last_write(&chip);
        assert_eq!(
            (low | (high << 16)) & regs::MT_BEACON_TIME_CFG_INTVAL,
            100 << 4
        );
        let value = low | (high << 16);
        assert_ne!(value & regs::MT_BEACON_TIME_CFG_TIMER_EN, 0);
        assert_ne!(value & regs::MT_BEACON_TIME_CFG_SYNC_MODE, 0);
        assert_ne!(value & regs::MT_BEACON_TIME_CFG_TBTT_EN, 0);
    }

    #[test]
    fn config_tsf_disable_only_clears_control_bits() {
        let mock = MockTransport::with_registers(&[(
            regs::MT_BEACON_TIME_CFG,
            regs::MT_BEACON_TIME_CFG_INTVAL | regs::MT_BEACON_TIME_CFG_TIMER_EN,
        )]);
        let chip = chip(mock);
        chip.mac_config_tsf(false, 0).unwrap();

        let (low, high) = last_write(&chip);
        // Interval preserved, timer/sync/TBTT cleared.
        assert_eq!(low | (high << 16), regs::MT_BEACON_TIME_CFG_INTVAL);
    }

    #[test]
    fn basic_rates_write_the_fallback_tables() {
        let chip = chip(MockTransport::default());
        chip.mac_set_basic_rates(0x000f).unwrap();
        let out = writes(&chip);
        assert_eq!(out[0], (0x000f, regs::MT_LEGACY_BASIC_RATE as u16));
        assert_eq!(out[2], (0x2100, regs::MT_HT_FBK_CFG0 as u16));
        assert_eq!(out[4], (0xa980, regs::MT_HT_FBK_CFG1 as u16));
        assert_eq!(out[6], (0xa988, regs::MT_LG_FBK_CFG0 as u16));
        assert_eq!(out[8], (0x2100, regs::MT_LG_FBK_CFG1 as u16));
    }

    #[test]
    fn short_preamble_toggles_the_auto_response_bit() {
        let set = chip(MockTransport::with_registers(&[(regs::MT_AUTO_RSP_CFG, 0)]));
        set.mac_set_short_preamble(true).unwrap();
        let (low, high) = last_write(&set);
        assert_ne!((low | (high << 16)) & regs::MT_AUTO_RSP_PREAMB_SHORT, 0);

        let cleared = chip(MockTransport::with_registers(&[(
            regs::MT_AUTO_RSP_CFG,
            regs::MT_AUTO_RSP_PREAMB_SHORT,
        )]));
        cleared.mac_set_short_preamble(false).unwrap();
        let (low, high) = last_write(&cleared);
        assert_eq!((low | (high << 16)) & regs::MT_AUTO_RSP_PREAMB_SHORT, 0);
    }

    #[test]
    fn slot_time_writes_the_low_byte() {
        let mock = MockTransport::with_registers(&[(regs::MT_BKOFF_SLOT_CFG, 0x1234_5600)]);
        let chip = chip(mock);
        chip.mac_set_slot_time(20).unwrap();
        // The low byte becomes 20, the rest of the word is preserved.
        let (low, high) = last_write(&chip);
        assert_eq!(low | (high << 16), 0x1234_5614);
    }

    #[test]
    fn ampdu_factor_lands_in_max_len_cfg() {
        let chip = chip(MockTransport::default());
        chip.mac_set_ampdu_factor(3).unwrap();
        let (low, high) = last_write(&chip);
        let expected = MAX_LEN_CFG_BASE | (3 << regs::MT_MAX_LEN_CFG_AMPDU_SHIFT);
        assert_eq!(low | (high << 16), expected);
    }

    #[test]
    fn group_wcid_is_near_the_top_of_the_table() {
        assert_eq!(GROUP_WCID_0, 126);
        assert_eq!(N_WCIDS, 128);
        assert_eq!(STA_WCID, 1);
    }

    #[test]
    fn wcid_clear_drop_clears_only_this_entry() {
        // Drop bit 1 already set: clearing WCID 1 must leave it clear and keep
        // the other entries.
        let mock = MockTransport::with_registers(&[(regs::mt_wcid_drop(1), 0x0000_0002)]);
        let chip = chip(mock);
        chip.mac_wcid_clear_drop(1).unwrap();
        let (low, high) = last_write(&chip);
        assert_eq!(low | (high << 16), 0);
    }

    #[test]
    fn drop_mask_helpers_match_the_header() {
        assert_eq!(regs::mt_wcid_drop(0), 0x106c);
        assert_eq!(regs::mt_wcid_drop(32), 0x1070);
        assert_eq!(regs::mt_wcid_drop_mask(0), 1);
        assert_eq!(regs::mt_wcid_drop_mask(31), 1 << 31);
        assert_eq!(regs::mt_wcid_drop_mask(32), 1);
    }

    /// The low-half value written to `index`, if any.
    fn written(chip: &Mt7601u<MockTransport>, index: u16) -> Option<u32> {
        chip.transport().calls().iter().find_map(|call| match call {
            Call::Out {
                value, index: at, ..
            } if *at == index => Some(u32::from(*value)),
            _ => None,
        })
    }

    #[test]
    fn wcid_set_key_programs_attr_for_ccmp_pairwise() {
        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        let chip = chip(mock);
        chip.mac_wcid_set_key(3, &[0u8; 32], regs::MT_CIPHER_AES_CCMP, 0, true)
            .unwrap();

        let value = written(&chip, regs::mt_wcid_attr(3) as u16).expect("attribute write");
        assert_eq!(
            value & regs::MT_WCID_ATTR_PAIRWISE,
            regs::MT_WCID_ATTR_PAIRWISE
        );
        assert_eq!(
            value & regs::MT_WCID_ATTR_PKEY_MODE,
            u32::from(regs::MT_CIPHER_AES_CCMP) << regs::MT_WCID_ATTR_PKEY_MODE_SHIFT
        );
        assert_eq!(value & regs::MT_WCID_ATTR_PKEY_MODE_EXT, 0);
    }

    #[test]
    fn shared_key_setup_shifts_the_cipher_into_the_mode_register() {
        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        let chip = chip(mock);
        chip.mac_shared_key_setup(0, 1, &[0u8; 32], regs::MT_CIPHER_AES_CCMP)
            .unwrap();

        let shift = regs::mt_skey_mode_shift(0, 1);
        let value = written(&chip, regs::mt_skey_mode(0) as u16).expect("mode write");
        assert_eq!(
            value & (regs::MT_SKEY_MODE_MASK << shift),
            u32::from(regs::MT_CIPHER_AES_CCMP) << shift
        );
    }

    #[test]
    fn key_register_offsets_match_the_header() {
        assert_eq!(regs::mt_wcid_key(0), 0x8000);
        assert_eq!(regs::mt_wcid_key(1), 0x8020);
        assert_eq!(regs::mt_wcid_iv(0), 0xa000);
        assert_eq!(regs::mt_skey(0, 0), 0xac00);
        assert_eq!(regs::mt_skey(0, 1), 0xac20);
        assert_eq!(regs::mt_skey(8, 0), 0xb400);
        assert_eq!(regs::mt_skey_mode(0), 0xb000);
        assert_eq!(regs::mt_skey_mode(2), 0xb004);
        assert_eq!(regs::mt_skey_mode(8), 0xb3f0);
        assert_eq!(regs::mt_skey_mode_shift(0, 0), 0);
        assert_eq!(regs::mt_skey_mode_shift(0, 1), 4);
        assert_eq!(regs::mt_skey_mode_shift(1, 0), 16);
    }

    #[test]
    fn wr_copy_rejects_unaligned_lengths() {
        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        let chip = chip(mock);
        assert!(chip.wr_copy(0, &[0u8; 6]).is_err());
        assert!(chip.wr_copy(0, &[0u8; 8]).is_ok());
    }
}
