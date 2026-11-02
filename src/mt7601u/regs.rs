//! Register offsets and bit fields for the MT7601U.
//!
//! Each constant is transcribed from the Linux driver header and note the
//! source. Only registers used by the implemented operations are listed; do not
//! add speculative entries.

// --- regs.h ---

/// ASIC version register; the top 16 bits identify the chip (`0x7601`).
pub const MT_ASIC_VERSION: u32 = 0x0000;

/// eFuse control register.
pub const MT_EFUSE_CTRL: u32 = 0x0024;
/// eFuse control: "select" bit, set when an eFuse is present.
pub const MT_EFUSE_CTRL_SEL: u32 = 1 << 31;
/// `MT_EFUSE_CTRL_AOUT` (`GENMASK(5, 0)`).
pub const MT_EFUSE_CTRL_AOUT: u32 = 0x3f;
/// `MT_EFUSE_CTRL_MODE` shift (`GENMASK(7, 6)`).
pub const MT_EFUSE_CTRL_MODE_SHIFT: u32 = 6;
/// `MT_EFUSE_CTRL_MODE` mask.
pub const MT_EFUSE_CTRL_MODE: u32 = 0x3;
/// `MT_EFUSE_CTRL_AIN` shift (`GENMASK(25, 16)`).
pub const MT_EFUSE_CTRL_AIN_SHIFT: u32 = 16;
/// `MT_EFUSE_CTRL_AIN` mask.
pub const MT_EFUSE_CTRL_AIN: u32 = 0x3ff;
/// `MT_EFUSE_CTRL_KICK` (`BIT(30)`).
pub const MT_EFUSE_CTRL_KICK: u32 = 1 << 30;
/// `MT_EFUSE_DATA_BASE`; `MT_EFUSE_DATA(n) = base + n * 4`.
pub const MT_EFUSE_DATA_BASE: u32 = 0x0028;

/// Station MAC address (low double word).
pub const MT_MAC_ADDR_DW0: u32 = 0x1008;
/// Station MAC address (high double word).
pub const MT_MAC_ADDR_DW1: u32 = 0x100c;

/// TX ALC configuration 0.
pub const MT_TX_ALC_CFG_0: u32 = 0x13b0;
/// `MT_TX_ALC_CFG_0_LIMIT_0` shift (`GENMASK(21, 16)`).
pub const MT_TX_ALC_CFG_0_LIMIT_0_SHIFT: u32 = 16;
/// `MT_TX_ALC_CFG_0_LIMIT_0` mask.
pub const MT_TX_ALC_CFG_0_LIMIT_0: u32 = 0x3f;

/// FCE (frame engine) DMA destination address for firmware upload.
pub const MT_FCE_DMA_ADDR: u32 = 0x0230;
/// FCE DMA length register (length encoded in the high 16 bits).
pub const MT_FCE_DMA_LEN: u32 = 0x0234;

/// WPDMA global configuration register.
pub const MT_WPDMA_GLO_CFG: u32 = 0x0208;
/// WPDMA: TX DMA busy.
pub const MT_WPDMA_GLO_CFG_TX_DMA_BUSY: u32 = 1 << 1;
/// WPDMA: RX DMA busy.
pub const MT_WPDMA_GLO_CFG_RX_DMA_BUSY: u32 = 1 << 3;

/// USB DMA configuration register.
pub const MT_USB_DMA_CFG: u32 = 0x0238;
/// USB DMA: RX bulk aggregation timeout (`GENMASK(7, 0)`).
pub const MT_USB_DMA_CFG_RX_BULK_AGG_TOUT_MASK: u32 = 0xff;
/// USB DMA: RX bulk aggregation limit shift (`GENMASK(15, 8)`).
pub const MT_USB_DMA_CFG_RX_BULK_AGG_LMT_SHIFT: u32 = 8;
/// USB DMA: clear TX.
pub const MT_USB_DMA_CFG_TX_CLR: u32 = 1 << 19;
/// USB DMA: enable RX bulk aggregation.
pub const MT_USB_DMA_CFG_RX_BULK_AGG_EN: u32 = 1 << 21;
/// USB DMA: enable RX bulk.
pub const MT_USB_DMA_CFG_RX_BULK_EN: u32 = 1 << 22;
/// USB DMA: enable TX bulk.
pub const MT_USB_DMA_CFG_TX_BULK_EN: u32 = 1 << 23;
/// USB DMA: drop RX wireless LAN packets.
pub const MT_USB_DMA_CFG_UDMA_RX_WL_DROP: u32 = 1 << 25;
/// USB DMA: RX engine busy (`regs.h`: `BIT(30)`).
pub const MT_USB_DMA_CFG_RX_BUSY: u32 = 1 << 30;
/// USB DMA: TX engine busy (`regs.h`: `BIT(31)`).
pub const MT_USB_DMA_CFG_TX_BUSY: u32 = 1 << 31;

/// `MT_RXQ_STA` (0x0430); bits 16..23 hold the RxQ page count.
pub const MT_RXQ_STA: u32 = 0x0430;
/// RxQ page-count mask inside [`MT_RXQ_STA`] (`init.c::mt7601u_mac_stop_hw`).
pub const MT_RXQ_STA_PAGE_COUNT: u32 = 0x00ff_0000;

/// TxQ page count read by `mt7601u_mac_stop_hw` (raw literal `0x0438`).
pub const MT_TXQ_PAGE_COUNT: u32 = 0x0438;
/// `0x0a30`; its low byte is a page count in `mt7601u_mac_stop_hw`.
pub const MT_Q_PAGE_COUNT_0A30: u32 = 0x0a30;
/// `0x0a34`; bits 0..7 and 16..23 are page counts in `mt7601u_mac_stop_hw`.
pub const MT_Q_PAGE_COUNT_0A34: u32 = 0x0a34;
/// Page-count mask for [`MT_Q_PAGE_COUNT_0A30`].
pub const MT_PAGE_COUNT_LOW_BYTE: u32 = 0x0000_00ff;
/// Page-count mask for [`MT_Q_PAGE_COUNT_0A34`].
pub const MT_PAGE_COUNT_SPLIT: u32 = 0x00ff_00ff;

/// PBF system control register.
pub const MT_PBF_SYS_CTRL: u32 = 0x0400;

/// PBF configuration register.
pub const MT_PBF_CFG: u32 = 0x0404;
/// PBF CFG: TX queue 0 enable (bit 0) through TX queue 3 enable (bit 3).
pub const MT_PBF_CFG_TXQ_EN: u32 = 0x0f;

/// FCE packet buffer engine control.
pub const MT_FCE_PSE_CTRL: u32 = 0x0800;

/// FCE TX base pointer (used during firmware load).
pub const MT_TX_CPU_FROM_FCE_BASE_PTR: u32 = 0x09a0;
/// FCE TX max count (used during firmware load).
pub const MT_TX_CPU_FROM_FCE_MAX_COUNT: u32 = 0x09a4;
/// FCE TX descriptor index, incremented after each uploaded firmware chunk.
pub const MT_TX_CPU_FROM_FCE_CPU_DESC_IDX: u32 = 0x09a8;
/// FCE PDMA global configuration.
pub const MT_FCE_PDMA_GLOBAL_CONF: u32 = 0x09c4;
/// FCE skip FS.
pub const MT_FCE_SKIP_FS: u32 = 0x0a6c;

/// MAC CSR0; a value that is neither 0 nor all-ones means the ASIC is ready.
pub const MT_MAC_CSR0: u32 = 0x1000;

/// MAC system control register.
pub const MT_MAC_SYS_CTRL: u32 = 0x1004;
/// Reset the CSR block.
pub const MT_MAC_SYS_CTRL_RESET_CSR: u32 = 1 << 0;
/// Reset the BBP block.
pub const MT_MAC_SYS_CTRL_RESET_BBP: u32 = 1 << 1;
/// Enable TX.
pub const MT_MAC_SYS_CTRL_ENABLE_TX: u32 = 1 << 2;
/// Enable RX.
pub const MT_MAC_SYS_CTRL_ENABLE_RX: u32 = 1 << 3;

/// `MT_USB_AGGR_SIZE_LIMIT` (`mt7601u.h`): 28 * 1024 bytes.
pub const MT_USB_AGGR_SIZE_LIMIT: u32 = 28;
/// `MT_USB_AGGR_TIMEOUT` (`mt7601u.h`): 0x80 * 33 ns.
pub const MT_USB_AGGR_TIMEOUT: u32 = 0x80;

// --- mcu.h ---

/// MCU communication register 0; equals 1 once firmware is running.
pub const MT_MCU_COM_REG0: u32 = 0x0730;
/// MCU communication register 1; bit 31 signals chunk completion.
pub const MT_MCU_COM_REG1: u32 = 0x0734;
/// Bit 31 of `MT_MCU_COM_REG1`.
pub const MT_MCU_COM_REG1_FW_READY: u32 = 1 << 31;

/// IVB size (bootload vector) inside the firmware image.
pub const MT_MCU_IVB_SIZE: usize = 0x40;
/// Destination offset for the DLM firmware section.
pub const MT_MCU_DLM_OFFSET: u32 = 0x80000;

// --- mcu.c firmware-load literals (kept verbatim, with the source value) ---

/// Literal register written to 0 at the start of `mt7601u_load_firmware`.
pub const MT_LOAD_FW_REG_094C: u32 = 0x094c;
/// Literal register written to 0 in `mt7601u_load_firmware`.
pub const MT_LOAD_FW_REG_0A44: u32 = 0x0a44;
/// Value written to [`MT_FCE_DMA_ADDR`] during firmware load.
pub const MT_LOAD_FW_FCE_BASE: u32 = 0x84210;
/// Value written to [`MT_PBF_SYS_CTRL`] during firmware load.
pub const MT_LOAD_FW_PBF_SYS_CTRL_VALUE: u32 = 0x80c00;
/// Value written to [`MT_TX_CPU_FROM_FCE_BASE_PTR`] during firmware load.
pub const MT_LOAD_FW_TX_FCE_BASE: u32 = 0x400230;
/// Value written to [`MT_FCE_PDMA_GLOBAL_CONF`] during firmware load.
pub const MT_LOAD_FW_PDMA_GLOBAL_CONF: u32 = 0x44;
/// Value written to [`MT_FCE_SKIP_FS`] during firmware load.
pub const MT_LOAD_FW_SKIP_FS: u32 = 3;

// --- init.c / initvals registers (regs.h) ---

/// MAC status register.
pub const MT_MAC_STATUS: u32 = 0x1200;
/// MAC status: TX active.
pub const MT_MAC_STATUS_TX: u32 = 1 << 0;
/// MAC status: RX active.
pub const MT_MAC_STATUS_RX: u32 = 1 << 1;

/// WLAN function control (clock/enable).
pub const MT_WLAN_FUN_CTRL: u32 = 0x0080;
/// Enable WLAN.
pub const MT_WLAN_FUN_CTRL_WLAN_EN: u32 = 1 << 0;
/// Enable WLAN clock.
pub const MT_WLAN_FUN_CTRL_WLAN_CLK_EN: u32 = 1 << 1;
/// Reset RF.
pub const MT_WLAN_FUN_CTRL_WLAN_RESET_RF: u32 = 1 << 2;
/// Reset WLAN.
pub const MT_WLAN_FUN_CTRL_WLAN_RESET: u32 = 1 << 3;
/// Force WLAN antenna selection.
pub const MT_WLAN_FUN_CTRL_FRC_WL_ANT_SEL: u32 = 1 << 5;
/// GPIO output enable field.
pub const MT_WLAN_FUN_CTRL_GPIO_OUT_EN: u32 = 0xff << 24;

/// CMB control (clock/PLL status).
pub const MT_CMB_CTRL: u32 = 0x0020;
/// Crystal ready.
pub const MT_CMB_CTRL_XTAL_RDY: u32 = 1 << 22;
/// PLL locked.
pub const MT_CMB_CTRL_PLL_LD: u32 = 1 << 23;

/// Beacon base address (for computing beacon offsets).
pub const MT_BEACON_BASE: u32 = 0xc000;
/// Beacon-offset register base; `MT_BCN_OFFSET(n) = base + n * 4`.
pub const MT_BCN_OFFSET_BASE: u32 = 0x041c;
/// Auxiliary clock configuration.
pub const MT_AUX_CLK_CFG: u32 = 0x120c;

/// WCID address table base.
pub const MT_WCID_ADDR_BASE: u32 = 0x1800;
/// WCID attribute table base.
pub const MT_WCID_ATTR_BASE: u32 = 0xa800;
/// Shared-key mode table base.
pub const MT_SKEY_MODE_BASE_0: u32 = 0xb000;

/// RX statistics counter 0 (reads reset the counters).
pub const MT_RX_STA_CNT0: u32 = 0x1700;
/// TX statistics counter 0.
pub const MT_TX_STA_CNT0: u32 = 0x170c;

/// TX status FIFO (`regs.h`): one entry per transmitted frame that carried a
/// non-zero packet id. Reading the register pops the oldest entry; an empty
/// FIFO reads back as 0 (`VALID` clear). The kernel driver drains it after
/// every completed TX (`mt7601u_tx_stat`).
pub const MT_TX_STAT_FIFO: u32 = 0x1718;
/// `MT_TX_STAT_FIFO_VALID` (`BIT(0)`): the popped entry is real.
pub const MT_TX_STAT_FIFO_VALID: u32 = 1 << 0;
/// `MT_TX_STAT_FIFO_PID_TYPE` shift (`GENMASK(4, 1)`).
pub const MT_TX_STAT_FIFO_PID_TYPE_SHIFT: u32 = 1;
/// `MT_TX_STAT_FIFO_PID_TYPE` mask.
pub const MT_TX_STAT_FIFO_PID_TYPE: u32 = 0xf;
/// `MT_TX_STAT_FIFO_SUCCESS` (`BIT(5)`): the frame was acknowledged.
pub const MT_TX_STAT_FIFO_SUCCESS: u32 = 1 << 5;
/// `MT_TX_STAT_FIFO_WCID` shift (`GENMASK(15, 8)`).
pub const MT_TX_STAT_FIFO_WCID_SHIFT: u32 = 8;
/// `MT_TX_STAT_FIFO_WCID` mask.
pub const MT_TX_STAT_FIFO_WCID: u32 = 0xff;
/// `MT_TX_STAT_FIFO_RATE` shift (`GENMASK(31, 16)`).
pub const MT_TX_STAT_FIFO_RATE_SHIFT: u32 = 16;
/// `MT_TX_STAT_FIFO_RATE` mask.
pub const MT_TX_STAT_FIFO_RATE: u32 = 0xffff;

/// Microsecond cycle configuration.
pub const MT_US_CYC_CFG: u32 = 0x02a4;
/// `MT_US_CYC_CNT` field (`GENMASK(7, 0)`).
pub const MT_US_CYC_CNT: u32 = 0xff;

/// Beacon timer configuration.
pub const MT_BEACON_TIME_CFG: u32 = 0x1114;
/// Beacon timer enable.
pub const MT_BEACON_TIME_CFG_TIMER_EN: u32 = 1 << 16;
/// Beacon sync mode field.
pub const MT_BEACON_TIME_CFG_SYNC_MODE: u32 = 0x3 << 17;
/// TBTT enable.
pub const MT_BEACON_TIME_CFG_TBTT_EN: u32 = 1 << 19;
/// Beacon TX enable.
pub const MT_BEACON_TIME_CFG_BEACON_TX: u32 = 1 << 20;

/// TXOP control: truncation enable field.
pub const MT_TXOP_TRUN_EN: u32 = 0x3f;
/// TXOP control: extended CCA delay shift.
pub const MT_TXOP_EXT_CCA_DLY_SHIFT: u32 = 8;

// --- BBP access via MT_BBP_CSR_CFG (regs.h / phy.c) ---

/// BBP CSR configuration register.
pub const MT_BBP_CSR_CFG: u32 = 0x101c;
/// `MT_BBP_CSR_CFG_VAL` (`GENMASK(7, 0)`).
pub const MT_BBP_CSR_CFG_VAL: u32 = 0xff;
/// `MT_BBP_CSR_CFG_REG_NUM` shift (`GENMASK(15, 8)`).
pub const MT_BBP_CSR_CFG_REG_NUM_SHIFT: u32 = 8;
/// `MT_BBP_CSR_CFG_REG_NUM` mask.
pub const MT_BBP_CSR_CFG_REG_NUM: u32 = 0xff;
/// Initiate a BBP read.
pub const MT_BBP_CSR_CFG_READ: u32 = 1 << 16;
/// BBP access in progress.
pub const MT_BBP_CSR_CFG_BUSY: u32 = 1 << 17;
/// Parallel duration.
pub const MT_BBP_CSR_CFG_PAR_DUR: u32 = 1 << 18;
/// BBP read/write mode.
pub const MT_BBP_CSR_CFG_RW_MODE: u32 = 1 << 19;
/// `MT_BBP_REG_VERSION` (`mt7601u.h`): BBP readiness register.
pub const MT_BBP_REG_VERSION: u8 = 0x00;

// --- initvals.h register offsets ---
/// `MT_LEGACY_BASIC_RATE`.
pub const MT_LEGACY_BASIC_RATE: u32 = 0x1408;
/// `MT_HT_BASIC_RATE`.
pub const MT_HT_BASIC_RATE: u32 = 0x140c;
/// `MT_RX_FILTR_CFG`.
pub const MT_RX_FILTR_CFG: u32 = 0x1400;
/// `MT_BKOFF_SLOT_CFG`.
pub const MT_BKOFF_SLOT_CFG: u32 = 0x1104;
/// `MT_TX_SW_CFG0`.
pub const MT_TX_SW_CFG0: u32 = 0x1330;
/// `MT_TX_SW_CFG1`.
pub const MT_TX_SW_CFG1: u32 = 0x1334;
/// `MT_TX_SW_CFG2`.
pub const MT_TX_SW_CFG2: u32 = 0x1338;
/// `MT_TX_LINK_CFG`.
pub const MT_TX_LINK_CFG: u32 = 0x1350;
/// `MT_TX_TIMEOUT_CFG`.
pub const MT_TX_TIMEOUT_CFG: u32 = 0x1348;
/// `MT_MAX_LEN_CFG`.
pub const MT_MAX_LEN_CFG: u32 = 0x1018;
/// `MT_PBF_TX_MAX_PCNT`.
pub const MT_PBF_TX_MAX_PCNT: u32 = 0x0408;
/// `MT_PBF_RX_MAX_PCNT`.
pub const MT_PBF_RX_MAX_PCNT: u32 = 0x040c;
/// `MT_TX_RETRY_CFG`.
pub const MT_TX_RETRY_CFG: u32 = 0x134c;
/// `MT_AUTO_RSP_CFG`.
pub const MT_AUTO_RSP_CFG: u32 = 0x1404;
/// `MT_CCK_PROT_CFG`.
pub const MT_CCK_PROT_CFG: u32 = 0x1364;
/// `MT_OFDM_PROT_CFG`.
pub const MT_OFDM_PROT_CFG: u32 = 0x1368;
/// `MT_MM40_PROT_CFG`.
pub const MT_MM40_PROT_CFG: u32 = 0x1370;
/// `MT_GF20_PROT_CFG`.
pub const MT_GF20_PROT_CFG: u32 = 0x1374;
/// `MT_GF40_PROT_CFG`.
pub const MT_GF40_PROT_CFG: u32 = 0x1378;
/// `MT_MM20_PROT_CFG`.
pub const MT_MM20_PROT_CFG: u32 = 0x136c;
/// `MT_TXOP_CTRL_CFG`.
pub const MT_TXOP_CTRL_CFG: u32 = 0x1340;
/// `MT_TX_RTS_CFG`.
pub const MT_TX_RTS_CFG: u32 = 0x1344;
/// `MT_EXP_ACK_TIME`.
pub const MT_EXP_ACK_TIME: u32 = 0x1380;
/// `MT_TXOP_HLDR_ET`.
pub const MT_TXOP_HLDR_ET: u32 = 0x1608;
/// `MT_XIFS_TIME_CFG`.
pub const MT_XIFS_TIME_CFG: u32 = 0x1100;
/// `MT_PWR_PIN_CFG`.
pub const MT_PWR_PIN_CFG: u32 = 0x1204;
/// `MT_PN_PAD_MODE`.
pub const MT_PN_PAD_MODE: u32 = 0x150c;
/// `MT_TSO_CTRL`.
pub const MT_TSO_CTRL: u32 = 0x0250;
/// `MT_HEADER_TRANS_CTRL_REG`.
pub const MT_HEADER_TRANS_CTRL_REG: u32 = 0x0260;
/// `MT_PAUSE_ENABLE_CONTROL1`.
pub const MT_PAUSE_ENABLE_CONTROL1: u32 = 0x0a38;
/// `MT_TX0_RF_GAIN_CORR`.
pub const MT_TX0_RF_GAIN_CORR: u32 = 0x13a0;
/// `MT_TX0_RF_GAIN_ATTEN`.
pub const MT_TX0_RF_GAIN_ATTEN: u32 = 0x13a8;
/// `MT_TX0_BB_GAIN_ATTEN`.
pub const MT_TX0_BB_GAIN_ATTEN: u32 = 0x13c0;
/// `MT_TX_ALC_VGA3`.
pub const MT_TX_ALC_VGA3: u32 = 0x13c8;
/// `MT_FCE_CSO`.
pub const MT_FCE_CSO: u32 = 0x0808;
/// `MT_FCE_PARAMETERS`.
pub const MT_FCE_PARAMETERS: u32 = 0x0804;

// --- power-rate registers (regs.h) ---
/// `MT_TX_PWR_CFG_0`; the per-rate power table starts here.
pub const MT_TX_PWR_CFG_0: u32 = 0x1314;
/// `MT_TX_PWR_CFG_1`.
pub const MT_TX_PWR_CFG_1: u32 = 0x1318;
/// `MT_TX_PWR_CFG_2`.
pub const MT_TX_PWR_CFG_2: u32 = 0x131c;
/// `MT_TX_PWR_CFG_4`.
pub const MT_TX_PWR_CFG_4: u32 = 0x1324;
/// `MT_TX_PWR_CFG_7`.
pub const MT_TX_PWR_CFG_7: u32 = 0x13d4;
/// `MT_TX_PWR_CFG_9`.
pub const MT_TX_PWR_CFG_9: u32 = 0x13dc;

// --- RF access (regs.h / phy.c) ---
/// RF CSR configuration register.
pub const MT_RF_CSR_CFG: u32 = 0x0500;
/// `MT_RF_CSR_CFG_DATA` (`GENMASK(7, 0)`).
pub const MT_RF_CSR_CFG_DATA: u32 = 0xff;
/// `MT_RF_CSR_CFG_REG_ID` shift (`GENMASK(13, 8)`).
pub const MT_RF_CSR_CFG_REG_ID_SHIFT: u32 = 8;
/// `MT_RF_CSR_CFG_REG_ID` mask.
pub const MT_RF_CSR_CFG_REG_ID: u32 = 0x3f;
/// `MT_RF_CSR_CFG_REG_BANK` shift (`GENMASK(17, 14)`).
pub const MT_RF_CSR_CFG_REG_BANK_SHIFT: u32 = 14;
/// `MT_RF_CSR_CFG_REG_BANK` mask.
pub const MT_RF_CSR_CFG_REG_BANK: u32 = 0xf;
/// Write (rather than read) select.
pub const MT_RF_CSR_CFG_WR: u32 = 1 << 30;
/// Start an RF access.
pub const MT_RF_CSR_CFG_KICK: u32 = 1 << 31;
/// RF bypass register 0.
pub const MT_RF_BYPASS_0: u32 = 0x0504;
/// RF setting register 0.
pub const MT_RF_SETTING_0: u32 = 0x050c;
/// RF PA mode configuration 0.
pub const MT_RF_PA_MODE_CFG0: u32 = 0x121c;
/// RF PA mode configuration 1.
pub const MT_RF_PA_MODE_CFG1: u32 = 0x1220;

// --- station setup (mac.c / main.c) ---

/// AP BSSID (low double word); the BSSID is written as two words.
pub const MT_MAC_BSSID_DW0: u32 = 0x1010;
/// `MT_MAC_ADDR_DW1_U2ME_MASK` shift (`GENMASK(23, 16)`).
pub const MT_MAC_ADDR_DW1_U2ME_SHIFT: u32 = 16;
/// `MT_MAC_ADDR_DW1_U2ME_MASK`: "unicast to me" accept field.
pub const MT_MAC_ADDR_DW1_U2ME: u32 = 0xff;

/// `MT_WCID_ADDR(_n) = base + n * 8` (`MT_WCID_ADDR_BASE` above).
pub const fn mt_wcid_addr(index: u8) -> u32 {
    MT_WCID_ADDR_BASE + index as u32 * 8
}
/// `MT_WCID_ATTR(_n) = base + n * 4` (`MT_WCID_ATTR_BASE` above).
pub const fn mt_wcid_attr(index: u8) -> u32 {
    MT_WCID_ATTR_BASE + index as u32 * 4
}
/// `MT_WCID_ATTR_BSS_IDX` shift (`GENMASK(6, 4)`).
pub const MT_WCID_ATTR_BSS_IDX_SHIFT: u32 = 4;
/// `MT_WCID_ATTR_BSS_IDX` mask.
pub const MT_WCID_ATTR_BSS_IDX: u32 = 0x7;
/// `MT_WCID_ATTR_BSS_IDX_EXT` (`BIT(11)`): high bit of the VIF index.
pub const MT_WCID_ATTR_BSS_IDX_EXT: u32 = 1 << 11;

/// `MT_WCID_DROP_BASE`.
pub const MT_WCID_DROP_BASE: u32 = 0x106c;
/// `MT_WCID_DROP(_n) = base + (n / 32) * 4`.
pub const fn mt_wcid_drop(index: u8) -> u32 {
    MT_WCID_DROP_BASE + (index as u32 >> 5) * 4
}
/// `MT_WCID_DROP_MASK(_n)`.
pub const fn mt_wcid_drop_mask(index: u8) -> u32 {
    1u32 << (index % 32)
}

// --- key tables (regs.h / mac.c) ---

/// `MT_WCID_KEY_BASE`; `MT_WCID_KEY(_n) = base + n * 32`.
pub const MT_WCID_KEY_BASE: u32 = 0x8000;
/// `MT_WCID_KEY(_n)`.
pub const fn mt_wcid_key(index: u8) -> u32 {
    MT_WCID_KEY_BASE + index as u32 * 32
}
/// `MT_WCID_IV_BASE`; `MT_WCID_IV(_n) = base + n * 8`.
pub const MT_WCID_IV_BASE: u32 = 0xa000;
/// `MT_WCID_IV(_n)`.
pub const fn mt_wcid_iv(index: u8) -> u32 {
    MT_WCID_IV_BASE + index as u32 * 8
}

/// `MT_WCID_ATTR_PAIRWISE` (`BIT(0)`).
pub const MT_WCID_ATTR_PAIRWISE: u32 = 1 << 0;
/// `MT_WCID_ATTR_PKEY_MODE` shift (`GENMASK(3, 1)`).
pub const MT_WCID_ATTR_PKEY_MODE_SHIFT: u32 = 1;
/// `MT_WCID_ATTR_PKEY_MODE` field mask.
pub const MT_WCID_ATTR_PKEY_MODE_FIELD: u32 = 0x7;
/// `MT_WCID_ATTR_PKEY_MODE` shifted mask.
pub const MT_WCID_ATTR_PKEY_MODE: u32 =
    MT_WCID_ATTR_PKEY_MODE_FIELD << MT_WCID_ATTR_PKEY_MODE_SHIFT;
/// `MT_WCID_ATTR_PKEY_MODE_EXT` (`BIT(10)`): high bit of the cipher.
pub const MT_WCID_ATTR_PKEY_MODE_EXT: u32 = 1 << 10;
/// `MT_WCID_ATTR_PKEY_MODE_EXT` shift.
pub const MT_WCID_ATTR_PKEY_MODE_EXT_SHIFT: u32 = 10;

/// `enum mt76_cipher_type`: no cipher.
pub const MT_CIPHER_NONE: u8 = 0;
/// `MT_CIPHER_WEP40`.
pub const MT_CIPHER_WEP40: u8 = 1;
/// `MT_CIPHER_WEP104`.
pub const MT_CIPHER_WEP104: u8 = 2;
/// `MT_CIPHER_TKIP`.
pub const MT_CIPHER_TKIP: u8 = 3;
/// `MT_CIPHER_AES_CCMP`.
pub const MT_CIPHER_AES_CCMP: u8 = 4;

/// `MT_SKEY_BASE_0`.
pub const MT_SKEY_BASE_0: u32 = 0xac00;
/// `MT_SKEY_BASE_1`.
pub const MT_SKEY_BASE_1: u32 = 0xb400;
/// `MT_SKEY(_bss, _idx)`.
pub const fn mt_skey(bss: u8, index: u8) -> u32 {
    if bss & 8 != 0 {
        MT_SKEY_BASE_1 + (4 * (bss & 7) as u32 + index as u32) * 32
    } else {
        MT_SKEY_BASE_0 + (4 * bss as u32 + index as u32) * 32
    }
}
/// `MT_SKEY_MODE_BASE_1`.
pub const MT_SKEY_MODE_BASE_1: u32 = 0xb3f0;
/// `MT_SKEY_MODE(_bss)`.
pub const fn mt_skey_mode(bss: u8) -> u32 {
    if bss & 8 != 0 {
        MT_SKEY_MODE_BASE_1 + ((bss & 7) / 2) as u32 * 4
    } else {
        MT_SKEY_MODE_BASE_0 + (bss / 2) as u32 * 4
    }
}
/// `MT_SKEY_MODE_MASK` (`GENMASK(3, 0)`).
pub const MT_SKEY_MODE_MASK: u32 = 0xf;
/// `MT_SKEY_MODE_SHIFT(_bss, _idx)`.
pub const fn mt_skey_mode_shift(bss: u8, index: u8) -> u32 {
    4 * (index as u32 + 4 * (bss & 1) as u32)
}

/// `MT_HT_FBK_CFG0` (HT rate fallback table).
pub const MT_HT_FBK_CFG0: u32 = 0x1354;
/// `MT_HT_FBK_CFG1`.
pub const MT_HT_FBK_CFG1: u32 = 0x1358;
/// `MT_LG_FBK_CFG0` (legacy rate fallback table).
pub const MT_LG_FBK_CFG0: u32 = 0x135c;
/// `MT_LG_FBK_CFG1`.
pub const MT_LG_FBK_CFG1: u32 = 0x1360;

/// `MT_BEACON_TIME_CFG_INTVAL` mask (`GENMASK(15, 0)`).
pub const MT_BEACON_TIME_CFG_INTVAL: u32 = 0xffff;

/// `MT_AUTO_RSP_PREAMB_SHORT` (`main.c` / `mac.c`).
pub const MT_AUTO_RSP_PREAMB_SHORT: u32 = 1 << 4;
/// `MT_BKOFF_SLOT_CFG_SLOTTIME` mask.
pub const MT_BKOFF_SLOT_CFG_SLOTTIME: u32 = 0xff;
/// `MT_MAX_LEN_CFG_AMPDU` shift (`GENMASK(13, 12)`).
pub const MT_MAX_LEN_CFG_AMPDU_SHIFT: u32 = 12;
/// `MT_MAX_LEN_CFG_AMPDU` mask.
pub const MT_MAX_LEN_CFG_AMPDU: u32 = 0x3;
