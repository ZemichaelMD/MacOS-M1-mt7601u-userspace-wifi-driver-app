//! MT7601U device identity and driver layer.
//!
//! Only facts verified against the physical device and the upstream Linux
//! driver live here. Firmware upload and register access are transcribed from
//! `usb.c`, `core.c` and `mcu.c`; BBP/PHY/calibration remain unimplemented.

pub mod data;
pub mod device;
pub mod dma;
pub mod eeprom;
pub mod firmware;
pub mod init;
pub mod initvals;
pub mod mac;
pub mod mcu;
pub mod phy;
pub mod radio;
pub mod regs;
pub mod rf;
pub mod rx;
pub mod scan;
pub mod station;
pub mod tx;

#[cfg(test)]
pub(crate) mod testing;

pub use device::{FirmwareLoad, Ident, Mt7601u};

/// USB vendor ID (MediaTek).
pub const VENDOR_ID: u16 = 0x148f;

/// USB product ID (MT7601U).
pub const PRODUCT_ID: u16 = 0x7601;

/// Human-readable product name.
pub const PRODUCT_NAME: &str = "MediaTek MT7601U";

/// The single interface exposed by the stock firmware layout. The real value
/// must be confirmed from the device descriptors before any claim is attempted.
pub const DEFAULT_INTERFACE: u8 = 0;

/// Returns `true` if `vid`/`pid` identify an MT7601U.
pub const fn is_mt7601u(vid: u16, pid: u16) -> bool {
    vid == VENDOR_ID && pid == PRODUCT_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_ids() {
        assert!(is_mt7601u(0x148f, 0x7601));
        assert!(!is_mt7601u(0x148f, 0x7602));
        assert!(!is_mt7601u(0x0000, 0x7601));
    }
}
