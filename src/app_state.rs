//! GUI-side application state and event application logic.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use crate::commands::{Addressing, Event, LinkDetails, Traffic};
use crate::logging::LogLine;
use crate::tunnel::TunnelState;
use crate::usb::DeviceStatus;
use crate::wifi::{Network, WifiState};

/// Maximum number of log lines retained in memory.
pub const MAX_LOG_LINES: usize = 2000;

/// Number of throughput samples kept for the live speed graph. At the backend's
/// reporting cadence this is a window of roughly half a minute.
pub const MAX_TRAFFIC_SAMPLES: usize = 96;

/// Bounded, append-only log buffer.
#[derive(Debug, Default)]
pub struct LogBuffer {
    lines: Vec<LogLine>,
}

impl LogBuffer {
    pub fn push(&mut self, line: LogLine) {
        self.lines.push(line);
        if self.lines.len() > MAX_LOG_LINES {
            let excess = self.lines.len() - MAX_LOG_LINES;
            self.lines.drain(0..excess);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &LogLine> {
        self.lines.iter()
    }

    /// The line at `index`, oldest first.
    pub fn get(&self, index: usize) -> Option<&LogLine> {
        self.lines.get(index)
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Flattened text used for clipboard copy and file export.
    pub fn as_text(&self) -> String {
        self.lines
            .iter()
            .map(LogLine::render)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Everything the GUI needs to render a frame.
#[derive(Debug, Default)]
pub struct AppState {
    pub device: DeviceStatus,
    pub wifi: WifiState,
    pub tunnel: TunnelState,
    /// The current link, once associated.
    pub link: Option<LinkDetails>,
    pub networks: Vec<Network>,
    /// SSIDs with a saved passphrase (never the passphrase itself).
    pub saved: Vec<String>,
    /// Set when the radio needs a physical replug, with the reason.
    pub replug: Option<String>,
    /// Set when the device is attached but cannot be opened, with the reason.
    pub device_problem: Option<String>,
    pub logs: LogBuffer,
    /// Reconnect to the last network automatically.
    pub auto_connect: bool,
    /// Address acquisition mode selected for the next tunnel connection.
    pub addressing: Addressing,
    /// Manual tunnel addressing as typed; parsed when applied. Kept here (not
    /// in `Addressing`) so a half-typed value is never used to bring a tunnel up.
    pub manual_address: String,
    pub manual_gateway: String,
    pub manual_dns: String,
    /// Set when the manual addressing failed to parse, with the reason.
    pub manual_problem: Option<String>,
    /// Set when the pipeline is paused because the user stopped the device.
    pub paused: bool,
    /// The network the passphrase prompt is open for, if any.
    pub awaiting_password: Option<String>,
    /// What the user typed into the passphrase prompt.
    pub password_input: String,
    pub auto_scroll_logs: bool,
    pub details_open: bool,
    /// The most recent throughput sample.
    pub traffic: Traffic,
    /// Recent download samples (bytes/s), oldest first, for the live graph.
    pub down_history: VecDeque<f32>,
    /// Recent upload samples (bytes/s), oldest first, for the live graph.
    pub up_history: VecDeque<f32>,
}

impl AppState {
    /// Apply one backend event to the GUI state.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Log(line) => self.logs.push(line),
            Event::Device(status) => {
                // Losing the device ends any link we had.
                if matches!(status, DeviceStatus::Absent) {
                    self.link = None;
                    self.tunnel = TunnelState::Stopped;
                    self.wifi = WifiState::Idle;
                    self.clear_traffic();
                }
                self.device = status;
            }
            Event::Wifi(state) => self.wifi = state,
            Event::Tunnel(state) => {
                // A tunnel that is not relaying has no throughput to show.
                if !state.is_running() {
                    self.clear_traffic();
                }
                self.tunnel = state;
            }
            Event::Traffic(traffic) => {
                self.traffic = traffic;
                self.down_history
                    .push_back(traffic.down_bytes_per_sec as f32);
                self.up_history.push_back(traffic.up_bytes_per_sec as f32);
                while self.down_history.len() > MAX_TRAFFIC_SAMPLES {
                    self.down_history.pop_front();
                }
                while self.up_history.len() > MAX_TRAFFIC_SAMPLES {
                    self.up_history.pop_front();
                }
            }
            Event::ScanResults(networks) => {
                self.wifi = WifiState::NetworksFound(networks.len());
                self.networks = networks;
                self.forget_vanished_prompt();
            }
            Event::SavedNetworks(saved) => self.saved = saved,
            Event::Link(link) => self.link = link,
            Event::Replug(hint) => self.replug = hint,
            Event::DeviceProblem(problem) => self.device_problem = problem,
            Event::AutoConnect(enabled) => self.auto_connect = enabled,
            Event::Addressing(addressing) => self.addressing = addressing,
            Event::Paused(paused) => self.paused = paused,
        }
    }

    /// Drop the throughput readout and its history (the link is not relaying).
    pub fn clear_traffic(&mut self) {
        self.traffic = Traffic::default();
        self.down_history.clear();
        self.up_history.clear();
    }

    /// Apply every queued event.
    pub fn apply_all(&mut self, events: impl IntoIterator<Item = Event>) {
        for event in events {
            self.apply(event);
        }
    }

    /// Parse the typed manual fields into an [`Addressing`], or say what is
    /// wrong with them. The tunnel is only brought up with a fully valid value.
    pub fn manual_addressing(&self) -> Result<Addressing, String> {
        let address = parse_ipv4("address", &self.manual_address)?;
        let gateway = parse_ipv4("gateway", &self.manual_gateway)?;
        if address.is_unspecified() {
            return Err("the address must not be 0.0.0.0".to_string());
        }
        if gateway.is_unspecified() {
            return Err("the gateway must not be 0.0.0.0".to_string());
        }
        let mut dns = Vec::new();
        for server in self
            .manual_dns
            .split(',')
            .map(str::trim)
            .filter(|server| !server.is_empty())
        {
            dns.push(parse_ipv4("DNS server", server)?);
        }
        Ok(Addressing::Manual {
            address,
            gateway,
            dns,
        })
    }

    /// The network with this SSID from the last scan.
    pub fn network(&self, ssid: &str) -> Option<&Network> {
        self.networks.iter().find(|network| network.ssid == ssid)
    }

    /// Whether a passphrase is stored for this network.
    pub fn is_saved(&self, ssid: &str) -> bool {
        self.saved.iter().any(|saved| saved == ssid)
    }

    /// The SSID we are associated with, if any.
    pub fn connected_ssid(&self) -> Option<&str> {
        match &self.wifi {
            WifiState::Connected { ssid } => Some(ssid),
            _ => None,
        }
    }

    /// Whether a connect is in flight.
    pub fn is_connecting(&self) -> bool {
        matches!(self.wifi, WifiState::Connecting { .. })
    }

    /// Whether a scan is in flight.
    pub fn is_scanning(&self) -> bool {
        matches!(self.wifi, WifiState::Scanning)
    }

    /// Drop a pending passphrase prompt when its network left the scan results,
    /// so a stale dialog cannot connect to something that is no longer there.
    fn forget_vanished_prompt(&mut self) {
        let vanished = self
            .awaiting_password
            .as_deref()
            .is_some_and(|ssid| self.network(ssid).is_none());
        if vanished {
            self.awaiting_password = None;
            self.password_input.clear();
        }
    }
}

/// Parse a trimmed IPv4 literal, naming it in the error.
fn parse_ipv4(what: &str, text: &str) -> Result<Ipv4Addr, String> {
    let text = text.trim();
    text.parse()
        .map_err(|_| format!("{what} \"{text}\" is not an IPv4 address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogLevel;
    use crate::usb::{DeviceInfo, UsbSpeed};
    use crate::wifi::Security;

    #[test]
    fn manual_addressing_parses_the_typed_fields() {
        let state = AppState {
            manual_address: " 192.168.43.5 ".into(),
            manual_gateway: "192.168.43.1".into(),
            manual_dns: "8.8.8.8, 1.1.1.1".into(),
            ..AppState::default()
        };
        assert_eq!(
            state.manual_addressing(),
            Ok(Addressing::Manual {
                address: Ipv4Addr::new(192, 168, 43, 5),
                gateway: Ipv4Addr::new(192, 168, 43, 1),
                dns: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)],
            })
        );
    }

    #[test]
    fn manual_addressing_admits_an_empty_dns_list() {
        let state = AppState {
            manual_address: "10.0.0.7".into(),
            manual_gateway: "10.0.0.1".into(),
            manual_dns: String::new(),
            ..AppState::default()
        };
        assert_eq!(
            state.manual_addressing(),
            Ok(Addressing::Manual {
                address: Ipv4Addr::new(10, 0, 0, 7),
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                dns: Vec::new(),
            })
        );
    }

    #[test]
    fn manual_addressing_reports_what_is_wrong() {
        let state = AppState::default();
        assert!(state.manual_addressing().unwrap_err().contains("address"));

        let state = AppState {
            manual_address: "192.168.1.5".into(),
            manual_gateway: "nope".into(),
            ..AppState::default()
        };
        assert!(state.manual_addressing().unwrap_err().contains("gateway"));

        let state = AppState {
            manual_address: "0.0.0.0".into(),
            manual_gateway: "192.168.1.1".into(),
            ..AppState::default()
        };
        assert!(state.manual_addressing().unwrap_err().contains("0.0.0.0"));

        let state = AppState {
            manual_address: "192.168.1.5".into(),
            manual_gateway: "192.168.1.1".into(),
            manual_dns: "8.8.8.8, junk".into(),
            ..AppState::default()
        };
        assert!(state.manual_addressing().unwrap_err().contains("DNS"));
    }

    #[test]
    fn addressing_events_update_the_selected_mode() {
        let mut state = AppState::default();
        assert_eq!(state.addressing, Addressing::Dhcp);
        state.apply(Event::Addressing(Addressing::Manual {
            address: Ipv4Addr::new(192, 168, 1, 5),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            dns: Vec::new(),
        }));
        assert!(!state.addressing.is_dhcp());
    }

    fn device() -> DeviceInfo {
        DeviceInfo {
            vid: 0x148f,
            pid: 0x7601,
            bus: 1,
            address: 3,
            speed: UsbSpeed::High,
            manufacturer: None,
            product: None,
            serial: None,
            configurations: Vec::new(),
        }
    }

    fn network(ssid: &str) -> Network {
        Network {
            ssid: ssid.into(),
            bssid: Some([1, 2, 3, 4, 5, 6]),
            signal_dbm: None,
            channel: Some(6),
            security: Security::Wpa2,
        }
    }

    #[test]
    fn applies_device_event() {
        let mut state = AppState::default();
        state.apply(Event::Device(DeviceStatus::Present(device())));
        assert!(matches!(state.device, DeviceStatus::Present(_)));
    }

    #[test]
    fn losing_the_device_clears_the_link() {
        let mut state = AppState {
            link: Some(LinkDetails::associated(&network("home"))),
            wifi: WifiState::Connected {
                ssid: "home".into(),
            },
            tunnel: TunnelState::Running {
                to_link_packets: 1,
                to_tun_packets: 2,
            },
            ..AppState::default()
        };
        state.apply(Event::Device(DeviceStatus::Absent));
        assert!(state.link.is_none());
        assert_eq!(state.tunnel, TunnelState::Stopped);
        assert_eq!(state.wifi, WifiState::Idle);
    }

    #[test]
    fn traffic_updates_the_readout_and_resets_when_the_tunnel_stops() {
        let mut state = AppState::default();
        state.apply(Event::Traffic(Traffic {
            to_tun_bytes: 4096,
            to_link_bytes: 1024,
            down_bytes_per_sec: 1000.0,
            up_bytes_per_sec: 500.0,
            ..Traffic::default()
        }));
        assert_eq!(state.down_history.len(), 1);
        assert_eq!(state.up_history.len(), 1);
        assert!((state.traffic.down_bytes_per_sec - 1000.0).abs() < f64::EPSILON);
        assert_eq!(state.traffic.to_tun_bytes, 4096);

        state.apply(Event::Tunnel(TunnelState::Stopped));
        assert!(state.down_history.is_empty());
        assert_eq!(state.traffic, Traffic::default());
    }

    #[test]
    fn traffic_history_is_bounded() {
        let mut state = AppState::default();
        for _ in 0..(MAX_TRAFFIC_SAMPLES + 20) {
            state.apply(Event::Traffic(Traffic {
                down_bytes_per_sec: 1.0,
                ..Traffic::default()
            }));
        }
        assert_eq!(state.down_history.len(), MAX_TRAFFIC_SAMPLES);
    }

    #[test]
    fn scan_results_update_state_and_report_the_count() {
        let mut state = AppState::default();
        state.apply(Event::ScanResults(vec![network("net")]));
        assert_eq!(state.wifi, WifiState::NetworksFound(1));
        assert_eq!(state.networks.len(), 1);
        assert_eq!(state.network("net").map(|n| n.ssid.as_str()), Some("net"));
    }

    #[test]
    fn a_pending_prompt_closes_when_its_network_disappears() {
        let mut state = AppState {
            awaiting_password: Some("gone".into()),
            password_input: "typed".into(),
            ..AppState::default()
        };
        state.apply(Event::ScanResults(vec![network("other")]));
        assert_eq!(state.awaiting_password, None);
        assert!(state.password_input.is_empty());
    }

    #[test]
    fn a_pending_prompt_survives_a_rescan_of_the_same_network() {
        let mut state = AppState {
            awaiting_password: Some("home".into()),
            ..AppState::default()
        };
        state.apply(Event::ScanResults(vec![network("home")]));
        assert_eq!(state.awaiting_password.as_deref(), Some("home"));
    }

    #[test]
    fn saved_networks_are_matched_by_ssid() {
        let mut state = AppState::default();
        state.apply(Event::SavedNetworks(vec!["home".into()]));
        assert!(state.is_saved("home"));
        assert!(!state.is_saved("cafe"));
    }

    #[test]
    fn replug_hint_and_pause_flag_follow_their_events() {
        let mut state = AppState::default();
        state.apply(Event::Replug(Some("replug the dongle".into())));
        assert_eq!(state.replug.as_deref(), Some("replug the dongle"));
        state.apply(Event::Replug(None));
        assert_eq!(state.replug, None);

        state.apply(Event::Paused(true));
        assert!(state.paused);
        state.apply(Event::Paused(false));
        assert!(!state.paused);
    }

    #[test]
    fn an_open_failure_is_kept_until_it_is_cleared() {
        let mut state = AppState::default();
        state.apply(Event::DeviceProblem(Some("Access denied".into())));
        assert_eq!(state.device_problem.as_deref(), Some("Access denied"));
        state.apply(Event::Wifi(WifiState::Scanning));
        assert!(
            state.device_problem.is_some(),
            "unrelated events must not clear it"
        );
        state.apply(Event::DeviceProblem(None));
        assert_eq!(state.device_problem, None);
    }

    #[test]
    fn connected_ssid_only_reports_a_real_association() {
        let mut state = AppState::default();
        assert_eq!(state.connected_ssid(), None);
        state.apply(Event::Wifi(WifiState::Connecting {
            ssid: "home".into(),
        }));
        assert!(state.is_connecting());
        assert_eq!(state.connected_ssid(), None);
        state.apply(Event::Wifi(WifiState::Connected {
            ssid: "home".into(),
        }));
        assert_eq!(state.connected_ssid(), Some("home"));
    }

    #[test]
    fn log_buffer_is_bounded() {
        let mut buffer = LogBuffer::default();
        for i in 0..(MAX_LOG_LINES + 50) {
            buffer.push(LogLine::new(LogLevel::Info, format!("line {i}")));
        }
        assert_eq!(buffer.len(), MAX_LOG_LINES);
        // Oldest lines were dropped.
        assert!(buffer.as_text().contains("line 50"));
        assert!(!buffer.as_text().contains("line 0\n"));
    }

    #[test]
    fn as_text_renders_levels() {
        let mut buffer = LogBuffer::default();
        buffer.push(LogLine::error("boom"));
        assert_eq!(buffer.as_text(), "[ERROR] boom");
    }
}
