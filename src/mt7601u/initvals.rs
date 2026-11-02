//! Register initialization tables, transcribed verbatim from `initvals.h`.
//!
//! These are register `(offset, value)` pairs. MAC tables use `regs::` names so
//! the mapping stays reviewable against the source; BBP tables address BBP
//! registers by number, so the pair key is the BBP register index.

use super::regs;

/// A `struct mt76_reg_pair`.
pub type RegPair = (u32, u32);

/// `bbp_common_vals`.
pub static BBP_COMMON_VALS: &[RegPair] = &[
    (65, 0x2c),
    (66, 0x38),
    (68, 0x0b),
    (69, 0x12),
    (70, 0x0a),
    (73, 0x10),
    (81, 0x37),
    (82, 0x62),
    (83, 0x6a),
    (84, 0x99),
    (86, 0x00),
    (91, 0x04),
    (92, 0x00),
    (103, 0x00),
    (105, 0x05),
    (106, 0x35),
];

/// `bbp_chip_vals`.
#[rustfmt::skip]
pub static BBP_CHIP_VALS: &[RegPair] = &[
    (1, 0x04), (4, 0x40), (20, 0x06), (31, 0x08),
    /* CCK Tx Control */
    (178, 0xff),
    /* AGC/Sync controls */
    (66, 0x14), (68, 0x8b), (69, 0x12), (70, 0x09),
    (73, 0x11), (75, 0x60), (76, 0x44), (84, 0x9a),
    (86, 0x38), (91, 0x07), (92, 0x02),
    /* Rx Path Controls */
    (99, 0x50), (101, 0x00), (103, 0xc0), (104, 0x92),
    (105, 0x3c), (106, 0x03), (128, 0x12),
    /* Change RXWI content: Gain Report */
    (142, 0x04), (143, 0x37),
    /* Change RXWI content: Antenna Report */
    (142, 0x03), (143, 0x99),
    /* CCK Receiver Control */
    (160, 0xeb), (161, 0xc4), (162, 0x77), (163, 0xf9),
    (164, 0x88), (165, 0x80), (166, 0xff), (167, 0xe4),
    /* AGC/GLRT registers accessed through R195/R196 */
    (195, 0x00), (196, 0x00),
    (195, 0x01), (196, 0x04),
    (195, 0x02), (196, 0x20),
    (195, 0x03), (196, 0x0a),
    (195, 0x06), (196, 0x16),
    (195, 0x07), (196, 0x05),
    (195, 0x08), (196, 0x37),
    (195, 0x0a), (196, 0x15),
    (195, 0x0b), (196, 0x17),
    (195, 0x0c), (196, 0x06),
    (195, 0x0d), (196, 0x09),
    (195, 0x0e), (196, 0x05),
    (195, 0x0f), (196, 0x09),
    (195, 0x10), (196, 0x20),
    (195, 0x20), (196, 0x17),
    (195, 0x21), (196, 0x06),
    (195, 0x22), (196, 0x09),
    (195, 0x23), (196, 0x17),
    (195, 0x24), (196, 0x06),
    (195, 0x25), (196, 0x09),
    (195, 0x26), (196, 0x17),
    (195, 0x27), (196, 0x06),
    (195, 0x28), (196, 0x09),
    (195, 0x29), (196, 0x05),
    (195, 0x2a), (196, 0x09),
    (195, 0x80), (196, 0x8b),
    (195, 0x81), (196, 0x12),
    (195, 0x82), (196, 0x09),
    (195, 0x83), (196, 0x17),
    (195, 0x84), (196, 0x11),
    (195, 0x85), (196, 0x00),
    (195, 0x86), (196, 0x00),
    (195, 0x87), (196, 0x18),
    (195, 0x88), (196, 0x60),
    (195, 0x89), (196, 0x44),
    (195, 0x8a), (196, 0x8b),
    (195, 0x8b), (196, 0x8b),
    (195, 0x8c), (196, 0x8b),
    (195, 0x8d), (196, 0x8b),
    (195, 0x8e), (196, 0x09),
    (195, 0x8f), (196, 0x09),
    (195, 0x90), (196, 0x09),
    (195, 0x91), (196, 0x09),
    (195, 0x92), (196, 0x11),
    (195, 0x93), (196, 0x11),
    (195, 0x94), (196, 0x11),
    (195, 0x95), (196, 0x11),
    /* PPAD */
    (47, 0x80), (60, 0x80), (150, 0xd2), (151, 0x32),
    (152, 0x23), (153, 0x41), (154, 0x00), (155, 0x4f),
    (253, 0x7e), (195, 0x30), (196, 0x32), (195, 0x31),
    (196, 0x23), (195, 0x32), (196, 0x45), (195, 0x35),
    (196, 0x4a), (195, 0x36), (196, 0x5a), (195, 0x37),
    (196, 0x5a),
];

/// `mac_common_vals`.
pub static MAC_COMMON_VALS: &[RegPair] = &[
    (regs::MT_LEGACY_BASIC_RATE, 0x0000_013f),
    (regs::MT_HT_BASIC_RATE, 0x0000_8003),
    (regs::MT_MAC_SYS_CTRL, 0x0000_0000),
    (regs::MT_RX_FILTR_CFG, 0x0001_7f97),
    (regs::MT_BKOFF_SLOT_CFG, 0x0000_0209),
    (regs::MT_TX_SW_CFG0, 0x0000_0000),
    (regs::MT_TX_SW_CFG1, 0x0008_0606),
    (regs::MT_TX_LINK_CFG, 0x0000_1020),
    (regs::MT_TX_TIMEOUT_CFG, 0x000a_2090),
    (regs::MT_MAX_LEN_CFG, 0x0000_3fff),
    (regs::MT_PBF_TX_MAX_PCNT, 0x1fbf_1f1f),
    (regs::MT_PBF_RX_MAX_PCNT, 0x0000_009f),
    (regs::MT_TX_RETRY_CFG, 0x47d0_1f0f),
    (regs::MT_AUTO_RSP_CFG, 0x0000_0013),
    (regs::MT_CCK_PROT_CFG, 0x0574_0003),
    (regs::MT_OFDM_PROT_CFG, 0x0574_0003),
    (regs::MT_MM40_PROT_CFG, 0x03f4_4084),
    (regs::MT_GF20_PROT_CFG, 0x0174_4004),
    (regs::MT_GF40_PROT_CFG, 0x03f4_4084),
    (regs::MT_MM20_PROT_CFG, 0x0174_4004),
    (regs::MT_TXOP_CTRL_CFG, 0x0000_583f),
    (regs::MT_TX_RTS_CFG, 0x0109_2b20),
    (regs::MT_EXP_ACK_TIME, 0x0024_00ca),
    (regs::MT_TXOP_HLDR_ET, 0x0000_0002),
    (regs::MT_XIFS_TIME_CFG, 0x33a4_1010),
    (regs::MT_PWR_PIN_CFG, 0x0000_0000),
    (regs::MT_PN_PAD_MODE, 0x0000_0001),
];

/// `mac_chip_vals`.
pub static MAC_CHIP_VALS: &[RegPair] = &[
    (regs::MT_TSO_CTRL, 0x0000_6050),
    (regs::MT_BCN_OFFSET_BASE, 0x1810_0800),
    (regs::MT_BCN_OFFSET_BASE + 4, 0x3830_2820),
    (regs::MT_PBF_SYS_CTRL, 0x0008_0c00),
    (regs::MT_PBF_CFG, 0x7f72_3c1f),
    (regs::MT_FCE_PSE_CTRL, 0x0000_0001),
    (regs::MT_PAUSE_ENABLE_CONTROL1, 0x0000_0000),
    (regs::MT_TX0_RF_GAIN_CORR, 0x003b_0005),
    (regs::MT_TX0_RF_GAIN_ATTEN, 0x0000_6900),
    (regs::MT_TX0_BB_GAIN_ATTEN, 0x0000_0400),
    (regs::MT_TX_ALC_VGA3, 0x0006_0006),
    (regs::MT_TX_SW_CFG0, 0x0000_0402),
    (regs::MT_TX_SW_CFG1, 0x0000_0000),
    (regs::MT_TX_SW_CFG2, 0x0000_0000),
    (regs::MT_HEADER_TRANS_CTRL_REG, 0x0000_0000),
    (regs::MT_FCE_CSO, 0x0000_030f),
    (regs::MT_FCE_PARAMETERS, 0x0025_6f0f),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_sizes_match_the_source() {
        assert_eq!(BBP_COMMON_VALS.len(), 16);
        assert_eq!(MAC_COMMON_VALS.len(), 27);
        assert_eq!(MAC_CHIP_VALS.len(), 17);
    }

    #[test]
    fn beacon_offset_vals_are_first_and_second_registers() {
        assert_eq!(MAC_CHIP_VALS[1].0, 0x041c);
        assert_eq!(MAC_CHIP_VALS[2].0, 0x0420);
    }
}
