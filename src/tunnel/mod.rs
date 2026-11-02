//! macOS tunnel layer: a `utun` interface plus the route/DNS plumbing needed to
//! expose a user-space link to macOS as a normal network.
//!
//! `utun` is layer 3 and is **not** a Wi-Fi interface — see
//! `docs/macos-networking.md`. The backend relays packets between the associated
//! station (`crate::mt7601u::data`) and this interface. Creating and configuring
//! the interface needs root, so it is done either in-process (root) or by the
//! privileged helper daemon (`crate::helper`).

pub mod icmp;
pub mod relay;
pub mod utun;

pub use utun::{frame_ipv4, is_root, parse_frame, Utun, AF_INET6_HEADER, AF_INET_HEADER};

use relay::PacketTun;

/// A layer-3 tunnel endpoint the backend can relay on. Either the in-process
/// `utun` interface (used when running as root) or a connection to the
/// privileged helper daemon (`crate::helper`).
///
/// `Send` so the backend worker can own it on its thread.
pub trait TunnelLink: PacketTun + Send {
    /// Interface name, e.g. `utun4`.
    fn name(&self) -> String;
    /// Stop relaying and roll back the routes/DNS this tunnel added.
    fn stop(&mut self);

    /// A fatal connection problem, if one has been noticed.
    ///
    /// The relay checks this every iteration and re-establishes the link as
    /// soon as the tunnel's peer has died — nothing about the Wi-Fi link can
    /// revive it, and waiting for the stall watchdog wastes ten seconds.
    /// Transports that cannot detect this return `None`.
    fn health(&self) -> Option<String> {
        None
    }
}

impl TunnelLink for Utun {
    fn name(&self) -> String {
        Utun::name(self).to_string()
    }

    fn stop(&mut self) {
        self.teardown();
    }
}

/// High-level tunnel state shown to the user. `Starting`/`Running` are only ever
/// produced once a real `utun` interface exists; the GUI never fabricates them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TunnelState {
    /// No tunnel; the Wi-Fi link is not being relayed.
    #[default]
    Stopped,
    /// Creating/configuring the interface and acquiring an address.
    Starting,
    /// Relaying packets between the Wi-Fi link and macOS.
    Running {
        to_link_packets: u64,
        to_tun_packets: u64,
    },
    Error(String),
}

impl TunnelState {
    /// Short label for the GUI status card.
    pub fn label(&self) -> String {
        match self {
            TunnelState::Stopped => "Stopped".to_string(),
            TunnelState::Starting => "Starting…".to_string(),
            TunnelState::Running {
                to_link_packets,
                to_tun_packets,
            } => format!("Running ({to_tun_packets} in / {to_link_packets} out)"),
            TunnelState::Error(error) => format!("Error: {error}"),
        }
    }

    /// Whether the UI should present this state as a failure.
    pub fn is_error(&self) -> bool {
        matches!(self, TunnelState::Error(_))
    }

    /// Whether the tunnel is actively relaying.
    pub fn is_running(&self) -> bool {
        matches!(self, TunnelState::Running { .. })
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn default_state_is_stopped_and_not_an_error() {
        assert_eq!(TunnelState::default(), TunnelState::Stopped);
        assert!(!TunnelState::default().is_error());
        assert!(!TunnelState::default().is_running());
        assert!(TunnelState::Error("x".into()).is_error());
    }

    #[test]
    fn running_label_reports_counters() {
        let state = TunnelState::Running {
            to_link_packets: 2,
            to_tun_packets: 3,
        };
        assert!(state.is_running());
        assert!(state.label().contains("3 in"));
        assert!(state.label().contains("2 out"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let framed = frame_ipv4(&[1, 2, 3, 4]);
        assert_eq!(framed, [0, 0, 0, 2, 1, 2, 3, 4]);
        let (family, payload) = parse_frame(&framed).expect("frame");
        assert_eq!(family, AF_INET_HEADER);
        assert_eq!(payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn short_frame_is_rejected() {
        assert!(parse_frame(&[0, 0, 0]).is_none());
    }
}
