//! MediaTek MT7601U user-space driver and GUI for Apple Silicon macOS.
//!
//! Provides USB device handling, the MT7601U driver layer, an 802.11 station
//! (passive scan + open-system association), the data path, and a `utun`
//! tunnel. WPA/WPA2 is **not** implemented. See `docs/` for the feasibility
//! analysis and the phased plan.

pub mod app;
pub mod app_state;
pub mod backend;
pub mod commands;
pub mod credentials;
pub mod format;
pub mod helper;
pub mod icon;
pub mod logging;
pub mod menu_bar;
pub mod mt7601u;
pub mod net;
pub mod paths;
pub mod theme;
pub mod tunnel;
pub mod usb;
pub mod wifi;
