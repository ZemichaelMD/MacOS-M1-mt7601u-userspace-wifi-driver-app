//! Channel message types shared between the GUI and the backend worker.

use std::net::Ipv4Addr;

use crate::logging::LogLine;
use crate::tunnel::TunnelState;
use crate::usb::DeviceStatus;
use crate::wifi::{Network, Security, WifiState};

/// How the tunnel's interface gets its address.
///
/// `Manual` mirrors TetherKit's "Manual" mode: when the AP's DHCP server does
/// not answer, the tunnel can be brought up with a fixed address, gateway and
/// DNS taken from the AP's subnet instead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Addressing {
    /// Ask the AP's DHCP server for a lease (the default).
    #[default]
    Dhcp,
    /// Use a fixed address in the AP's subnet.
    Manual {
        address: Ipv4Addr,
        gateway: Ipv4Addr,
        dns: Vec<Ipv4Addr>,
    },
}

impl Addressing {
    /// Short label for the UI.
    pub fn label(&self) -> &'static str {
        match self {
            Addressing::Dhcp => "Automatic (DHCP)",
            Addressing::Manual { .. } => "Manual",
        }
    }

    /// Whether DHCP should be used.
    pub fn is_dhcp(&self) -> bool {
        matches!(self, Addressing::Dhcp)
    }
}

/// Commands sent from the GUI to the backend worker.
#[derive(Clone)]
pub enum Command {
    /// Re-enumerate USB devices and report the MT7601U state.
    RefreshDevice,
    /// Open the device, claim its interface and resume the automatic pipeline.
    OpenDevice,
    /// Release the device, stop the tunnel and pause the automatic pipeline.
    CloseDevice,
    /// Read the identity registers (ASIC/MAC revision, eFuse presence).
    Identify,
    /// Initiate a passive Wi-Fi scan.
    Scan,
    /// Join `ssid`, then bring the tunnel up. One click in the picker.
    ///
    /// `password: None` uses the saved passphrase for the network. `remember`
    /// says whether a supplied passphrase should be stored for next time.
    Connect {
        ssid: String,
        password: Option<String>,
        remember: bool,
    },
    /// Disassociate and tear the tunnel down.
    Disconnect,
    /// Forget the saved passphrase for `ssid`.
    ForgetPassphrase { ssid: String },
    /// Reconnect to the last network automatically, or stop doing so.
    SetAutoConnect(bool),
    /// Choose how the tunnel is addressed (DHCP or a manual address).
    SetAddressing(Addressing),
    /// Stop the worker loop.
    Shutdown,
}

// Hand-written so a passphrase can never be revealed by a stray log statement.
impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::RefreshDevice => write!(f, "RefreshDevice"),
            Command::OpenDevice => write!(f, "OpenDevice"),
            Command::CloseDevice => write!(f, "CloseDevice"),
            Command::Identify => write!(f, "Identify"),
            Command::Scan => write!(f, "Scan"),
            Command::Connect { ssid, .. } => f
                .debug_struct("Connect")
                .field("ssid", ssid)
                .field("password", &"<redacted>")
                .finish(),
            Command::Disconnect => write!(f, "Disconnect"),
            Command::ForgetPassphrase { ssid } => f
                .debug_struct("ForgetPassphrase")
                .field("ssid", ssid)
                .finish(),
            Command::SetAutoConnect(enabled) => write!(f, "SetAutoConnect({enabled})"),
            Command::SetAddressing(addressing) => {
                write!(f, "SetAddressing({})", addressing.label())
            }
            Command::Shutdown => write!(f, "Shutdown"),
        }
    }
}

/// What the station is attached to, for the details view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkDetails {
    pub ssid: String,
    pub bssid: Option<[u8; 6]>,
    pub channel: Option<u8>,
    pub security: Security,
    /// Set once DHCP has handed us an address.
    pub ip: Option<std::net::Ipv4Addr>,
    /// The subnet mask, so the relay knows which destinations are on-link.
    pub subnet_mask: Option<std::net::Ipv4Addr>,
    pub router: Option<std::net::Ipv4Addr>,
    pub dns: Vec<std::net::Ipv4Addr>,
    /// The `utun` interface name, once the tunnel is up.
    pub interface: Option<String>,
}

impl LinkDetails {
    /// A link that is associated but has not finished DHCP yet.
    pub fn associated(network: &Network) -> Self {
        Self {
            ssid: network.ssid.clone(),
            bssid: network.bssid,
            channel: network.channel,
            security: network.security.clone(),
            ip: None,
            subnet_mask: None,
            router: None,
            dns: Vec::new(),
            interface: None,
        }
    }

    pub fn bssid_string(&self) -> Option<String> {
        self.bssid.map(|bssid| {
            bssid
                .iter()
                .map(|octet| format!("{octet:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
    }
}

/// A throughput sample, published while the tunnel is relaying.
///
/// The references are named from the network's point of view: `down` is traffic
/// arriving from the internet (Wi-Fi → macOS), `up` is traffic leaving it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Traffic {
    /// Bytes forwarded from the Wi-Fi link into macOS, cumulative.
    pub to_tun_bytes: u64,
    /// Packets forwarded from the Wi-Fi link into macOS, cumulative.
    pub to_tun_packets: u64,
    /// Bytes forwarded from macOS into the Wi-Fi link, cumulative.
    pub to_link_bytes: u64,
    /// Packets forwarded from macOS into the Wi-Fi link, cumulative.
    pub to_link_packets: u64,
    /// Smoothed download rate in bytes per second.
    pub down_bytes_per_sec: f64,
    /// Smoothed upload rate in bytes per second.
    pub up_bytes_per_sec: f64,
}

/// Events sent from the backend worker to the GUI.
#[derive(Debug, Clone)]
pub enum Event {
    /// A user-visible log line.
    Log(LogLine),
    /// MT7601U detection/open state changed.
    Device(DeviceStatus),
    /// High-level Wi-Fi state changed.
    Wifi(WifiState),
    /// A completed scan produced these access points.
    ScanResults(Vec<Network>),
    /// Tunnel state changed.
    Tunnel(TunnelState),
    /// Live throughput sample while relaying.
    Traffic(Traffic),
    /// Networks with a saved passphrase. The passphrases themselves stay in the
    /// credentials file and never reach the GUI.
    SavedNetworks(Vec<String>),
    /// What the current link is doing, or `None` when there is no link.
    Link(Option<LinkDetails>),
    /// The radio stopped answering: the dongle needs a physical replug.
    Replug(Option<String>),
    /// The device is attached but could not be opened, with the reason.
    DeviceProblem(Option<String>),
    /// Automatic reconnection preference changed.
    AutoConnect(bool),
    /// How the tunnel is addressed (DHCP or a manual address).
    Addressing(Addressing),
    /// The automatic pipeline is paused because the user stopped the device.
    Paused(bool),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_debug_redacts_password() {
        let command = Command::Connect {
            ssid: "home".into(),
            password: Some("hunter2".into()),
            remember: true,
        };
        let rendered = format!("{command:?}");
        assert!(rendered.contains("home"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn addressing_defaults_to_dhcp_and_labels_both_modes() {
        assert_eq!(Addressing::default(), Addressing::Dhcp);
        assert!(Addressing::default().is_dhcp());
        assert_eq!(Addressing::Dhcp.label(), "Automatic (DHCP)");

        let manual = Addressing::Manual {
            address: Ipv4Addr::new(192, 168, 43, 5),
            gateway: Ipv4Addr::new(192, 168, 43, 1),
            dns: vec![Ipv4Addr::new(8, 8, 8, 8)],
        };
        assert!(!manual.is_dhcp());
        assert_eq!(manual.label(), "Manual");
        // A manual address is not a secret, so the GUI may show it.
        assert!(format!("{manual:?}").contains("192.168.43.5"));
    }

    #[test]
    fn set_addressing_debug_shows_the_mode_not_the_address() {
        let command = Command::SetAddressing(Addressing::Manual {
            address: Ipv4Addr::new(10, 0, 0, 7),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            dns: Vec::new(),
        });
        assert_eq!(format!("{command:?}"), "SetAddressing(Manual)");
    }

    #[test]
    fn link_details_reports_the_bssid_as_lowercase_hex() {
        let details = LinkDetails {
            ssid: "home".into(),
            bssid: Some([0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]),
            channel: Some(6),
            security: Security::Wpa2,
            ip: None,
            subnet_mask: None,
            router: None,
            dns: Vec::new(),
            interface: None,
        };
        assert_eq!(details.bssid_string().as_deref(), Some("0a:1b:2c:3d:4e:5f"));
    }
}
