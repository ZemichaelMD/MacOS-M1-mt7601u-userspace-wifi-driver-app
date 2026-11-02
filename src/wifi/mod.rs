//! Wi-Fi domain types.
//!
//! These describe what the backend *reports*; they do not implement any
//! 802.11 behavior. Scan and association are future work, so the default
//! state is [`WifiState::NotImplemented`] and the GUI must render it honestly.

pub mod data;
pub mod eapol;
pub mod frames;
pub mod handshake;
pub mod mgmt;
pub mod rsn;
pub mod sae;
pub mod wpa;

/// Security mode advertised by an access point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    Open,
    Wpa,
    Wpa2,
    Wpa3,
    Unknown,
}

impl Security {
    pub fn label(&self) -> &'static str {
        match self {
            Security::Open => "Open",
            Security::Wpa => "WPA",
            Security::Wpa2 => "WPA2",
            Security::Wpa3 => "WPA3",
            Security::Unknown => "Unknown",
        }
    }
}

/// A scan result. Only populated when the backend actually obtains data from
/// the device; the GUI never fabricates entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub ssid: String,
    pub bssid: Option<[u8; 6]>,
    pub signal_dbm: Option<i32>,
    pub channel: Option<u8>,
    pub security: Security,
}

impl Network {
    pub fn bssid_string(&self) -> Option<String> {
        self.bssid.map(|b| {
            b.iter()
                .map(|octet| format!("{octet:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
    }
}

/// High-level Wi-Fi state shown to the user.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum WifiState {
    /// Station behavior has not been implemented.
    #[default]
    NotImplemented,
    Idle,
    Scanning,
    NetworksFound(usize),
    Connecting {
        ssid: String,
    },
    Connected {
        ssid: String,
    },
    Error(String),
}

impl WifiState {
    /// Short label for the GUI status card.
    pub fn label(&self) -> String {
        match self {
            WifiState::NotImplemented => "Not implemented".to_string(),
            WifiState::Idle => "Idle".to_string(),
            WifiState::Scanning => "Scanning…".to_string(),
            WifiState::NetworksFound(n) => format!("Networks found: {n}"),
            WifiState::Connecting { ssid } => format!("Connecting to {ssid}…"),
            WifiState::Connected { ssid } => format!("Connected to {ssid}"),
            WifiState::Error(e) => format!("Error: {e}"),
        }
    }

    /// Whether the UI should present this state as a failure.
    pub fn is_error(&self) -> bool {
        matches!(self, WifiState::Error(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bssid_is_lowercase_hex_colon_separated() {
        let net = Network {
            ssid: "demo".into(),
            bssid: Some([0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]),
            signal_dbm: Some(-42),
            channel: Some(6),
            security: Security::Wpa2,
        };
        assert_eq!(net.bssid_string().as_deref(), Some("0a:1b:2c:3d:4e:5f"));
    }

    #[test]
    fn missing_bssid_renders_none() {
        let net = Network {
            ssid: "demo".into(),
            bssid: None,
            signal_dbm: None,
            channel: None,
            security: Security::Open,
        };
        assert_eq!(net.bssid_string(), None);
    }

    #[test]
    fn default_state_is_not_implemented() {
        assert_eq!(WifiState::default(), WifiState::NotImplemented);
        assert!(!WifiState::default().is_error());
        assert!(WifiState::Error("x".into()).is_error());
    }
}
