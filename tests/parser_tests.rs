//! Integration tests exercising the crate's public API.
//!
//! These cover the logic that must be correct before any hardware behaviour is
//! added: descriptor rendering, device-state transitions, Wi-Fi honesty, and
//! credential redaction.

use mt7601u_macos::app_state::{AppState, LogBuffer, MAX_LOG_LINES};
use mt7601u_macos::commands::{Command, Event};
use mt7601u_macos::logging::{LogLevel, LogLine};
use mt7601u_macos::usb::{
    ConfigurationInfo, DeviceInfo, DeviceStatus, EndpointInfo, InterfaceInfo, UsbSpeed,
    UsbTransferType,
};
use mt7601u_macos::wifi::{Network, Security, WifiState};

fn sample_device() -> DeviceInfo {
    DeviceInfo {
        vid: 0x148f,
        pid: 0x7601,
        bus: 1,
        address: 4,
        speed: UsbSpeed::High,
        manufacturer: Some("MediaTek".into()),
        product: Some("802.11 n WLAN".into()),
        serial: Some("1.0".into()),
        configurations: vec![ConfigurationInfo {
            number: 1,
            self_powered: false,
            remote_wakeup: false,
            max_power_ma: 320,
            interfaces: vec![InterfaceInfo {
                number: 0,
                alt_setting: 0,
                class: 0xff,
                subclass: 0xff,
                protocol: 0xff,
                endpoints: vec![
                    EndpointInfo {
                        address: 0x84,
                        is_in: true,
                        transfer_type: UsbTransferType::Bulk,
                        max_packet_size: 512,
                        interval: 0,
                    },
                    EndpointInfo {
                        address: 0x04,
                        is_in: false,
                        transfer_type: UsbTransferType::Bulk,
                        max_packet_size: 512,
                        interval: 0,
                    },
                ],
            }],
        }],
    }
}

#[test]
fn device_status_transitions_report_expected_labels() {
    let info = sample_device();
    assert_eq!(DeviceStatus::default(), DeviceStatus::Unknown);
    assert_eq!(DeviceStatus::Absent.label(), "Not detected");
    assert_eq!(
        DeviceStatus::Present(info.clone()).label(),
        "Detected (closed)"
    );
    assert_eq!(DeviceStatus::Open(info).label(), "Open (interface claimed)");
}

#[test]
fn descriptor_dump_redacts_serial_and_lists_endpoints() {
    let text = sample_device().describe();
    assert!(text.contains("148f:7601"));
    assert!(text.contains("Serial:       <present, redacted>"));
    assert!(text.contains("Endpoint 0x84 (IN Bulk)"));
    assert!(text.contains("Endpoint 0x04 (OUT Bulk)"));
    assert!(!text.contains("1.0\n"));
}

#[test]
fn connect_command_debug_never_reveals_password() {
    let command = Command::Connect {
        ssid: "office".into(),
        password: Some("correct-horse-battery-staple".into()),
        remember: true,
    };
    let rendered = format!("{command:?}");
    assert!(rendered.contains("office"));
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("correct-horse-battery-staple"));
}

#[test]
fn wifi_never_claims_connection_without_a_connected_event() {
    let mut state = AppState::default();
    state.apply(Event::Log(LogLine::info("backend started")));
    state.apply(Event::Device(DeviceStatus::Present(sample_device())));
    state.apply(Event::Wifi(WifiState::Scanning));

    assert_eq!(state.wifi, WifiState::Scanning);
    assert!(!state.wifi.label().contains("Connected"));

    // Only an explicit Connected event may produce that label.
    state.apply(Event::Wifi(WifiState::Connected {
        ssid: "home".into(),
    }));
    assert!(state.wifi.label().contains("Connected to home"));
}

#[test]
fn log_buffer_export_keeps_most_recent_lines() {
    let mut buffer = LogBuffer::default();
    for i in 0..(MAX_LOG_LINES + 10) {
        buffer.push(LogLine::new(LogLevel::Info, format!("entry {i}")));
    }
    assert_eq!(buffer.len(), MAX_LOG_LINES);
    let text = buffer.as_text();
    assert!(text.starts_with("[INFO] entry 10"));
}

#[test]
fn network_row_fields_survive_round_trip() {
    let network = Network {
        ssid: "lab".into(),
        bssid: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        signal_dbm: Some(-55),
        channel: Some(11),
        security: Security::Wpa2,
    };
    assert_eq!(network.bssid_string().as_deref(), Some("de:ad:be:ef:00:01"));
    assert_eq!(network.security.label(), "WPA2");
}

#[test]
fn captured_fixture_matches_device_constants() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mt7601u_usb_info.txt"
    );
    let text = std::fs::read_to_string(path).expect("fixture readable");
    assert!(text.contains("0x148f"));
    assert!(text.contains("0x7601"));
    assert!(mt7601u_macos::mt7601u::is_mt7601u(0x148f, 0x7601));
}
