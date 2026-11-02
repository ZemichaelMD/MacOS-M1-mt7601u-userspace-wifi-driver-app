//! Privileged helper: a root launchd daemon that owns the `utun` interface on
//! behalf of the unprivileged GUI.
//!
//! Creating a `utun` interface and running `ifconfig`/`route`/`scutil` all need
//! root. Rather than asking the user to launch the whole GUI with `sudo`, the
//! GUI asks this helper — a LaunchDaemon installed once with
//! `--install-helper` — to bring the interface up, and then exchanges raw IP
//! packets with it over a Unix socket. This mirrors BetterTether's launchd
//! daemon (`mt7601u-refs/BetterTether`).
//!
//! Only the privileged plumbing lives here: the Wi-Fi station, DHCP and the
//! `utun` ⇄ Wi-Fi relay stay in the GUI process, because a second process
//! cannot claim the USB device at the same time.

pub mod client;
pub mod server;

pub use client::HelperClient;

/// Socket the daemon listens on.
pub const SOCKET_PATH: &str = "/var/run/mt7601u-helper.sock";
/// LaunchDaemon label (also the plist basename).
pub const LABEL: &str = "ai.commandcode.mt7601u";
/// Where the installed helper binary lives.
pub const HELPER_BINARY: &str = "/Library/PrivilegedHelperTools/ai.commandcode.mt7601u";
/// The installed LaunchDaemon property list.
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/ai.commandcode.mt7601u.plist";
/// Group allowed to talk to the daemon; `admin` (gid 80) on macOS, which is
/// where the interactive user account lives. The socket is `root:admin 0660`.
pub const SOCKET_GID: u32 = 80;

/// `Start` request: everything the daemon needs to bring the interface up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRequest {
    pub local: std::net::Ipv4Addr,
    pub peer: std::net::Ipv4Addr,
    pub mtu: u32,
    pub router: std::net::Ipv4Addr,
    pub dns: Vec<std::net::Ipv4Addr>,
}

// Message kinds. Requests are `0x0*`, responses `0x8*`; a packet is a data frame
// in either direction.
const KIND_PING: u8 = 0x01;
const KIND_START: u8 = 0x02;
const KIND_STOP: u8 = 0x03;
const KIND_PACKET: u8 = 0x40;
const KIND_OK: u8 = 0x81;
const KIND_STARTED: u8 = 0x82;
const KIND_ERROR: u8 = 0x83;

/// One message: `[kind:1][len:u32 LE][body]`.
pub(crate) fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

impl StartRequest {
    fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(17 + self.dns.len() * 4);
        body.extend_from_slice(&self.local.octets());
        body.extend_from_slice(&self.peer.octets());
        body.extend_from_slice(&self.mtu.to_le_bytes());
        body.extend_from_slice(&self.router.octets());
        body.push(self.dns.len() as u8);
        for server in &self.dns {
            body.extend_from_slice(&server.octets());
        }
        body
    }

    fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 17 {
            return None;
        }
        let ip =
            |at: usize| std::net::Ipv4Addr::new(body[at], body[at + 1], body[at + 2], body[at + 3]);
        let count = usize::from(body[16]);
        if body.len() < 17 + count * 4 {
            return None;
        }
        Some(Self {
            local: ip(0),
            peer: ip(4),
            mtu: u32::from_le_bytes([body[8], body[9], body[10], body[11]]),
            router: ip(12),
            dns: (0..count).map(|index| ip(17 + index * 4)).collect(),
        })
    }
}

fn encode_ifname(name: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + name.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body
}

fn decode_ifname(body: &[u8]) -> Option<String> {
    let length = usize::from(*body.first()?);
    let name = body.get(1..1 + length)?;
    Some(String::from_utf8_lossy(name).into_owned())
}

fn encode_error(message: &str) -> Vec<u8> {
    message.as_bytes().to_vec()
}

fn decode_error(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

/// The AppleScript that runs `<exe> --install-helper` as an administrator.
///
/// `do shell script … with administrator privileges` shows the standard macOS
/// authorization dialog, which is how an unsigned installer elevates
/// (`SMJobBless` would need a Developer ID).
pub fn install_script(exe: &std::path::Path) -> String {
    privileged_script(exe, "--install-helper")
}

/// The AppleScript that runs `<exe> --uninstall-helper` as an administrator.
pub fn uninstall_script(exe: &std::path::Path) -> String {
    privileged_script(exe, "--uninstall-helper")
}

/// `do shell script "<exe> <flag>" with administrator privileges`.
fn privileged_script(exe: &std::path::Path, flag: &str) -> String {
    let command = format!("{} {flag}", shell_quote(&exe.display().to_string()));
    format!(
        "do shell script \"{}\" with administrator privileges",
        apple_script_string(&command)
    )
}

/// Run [`install_script`] through `osascript`, prompting for the administrator
/// password. Blocks until the dialog is dismissed.
pub fn install_with_prompt(exe: &std::path::Path) -> Result<(), String> {
    run_privileged(install_script(exe))
}

/// Run [`uninstall_script`] through `osascript`, prompting for the administrator
/// password. Blocks until the dialog is dismissed.
pub fn uninstall_with_prompt(exe: &std::path::Path) -> Result<(), String> {
    run_privileged(uninstall_script(exe))
}

/// Run a prepared `do shell script …` through `osascript`, translating the
/// usual outcomes into readable errors.
fn run_privileged(script: String) -> Result<(), String> {
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|error| format!("could not run osascript: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let message = message.trim();
    if message.contains("User canceled") {
        Err("cancelled".to_string())
    } else if message.is_empty() {
        Err("the installer did not run".to_string())
    } else {
        Err(message.to_string())
    }
}

/// Escape a string for an AppleScript double-quoted literal.
fn apple_script_string(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Single-quote a string for `/bin/sh`.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Incremental decoder: `extend` with bytes read from the socket, then take
/// complete messages with `next`. Partial messages stay buffered.
#[derive(Debug, Default)]
pub(crate) struct FrameReader {
    buffer: Vec<u8>,
}

impl FrameReader {
    pub(crate) fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// The next complete message, if one has arrived.
    pub(crate) fn next(&mut self) -> Option<(u8, Vec<u8>)> {
        if self.buffer.len() < 5 {
            return None;
        }
        let kind = self.buffer[0];
        let length = u32::from_le_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]) as usize;
        if self.buffer.len() < 5 + length {
            return None;
        }
        let body = self.buffer[5..5 + length].to_vec();
        self.buffer.drain(..5 + length);
        Some((kind, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn start_request_round_trips() {
        let request = StartRequest {
            local: Ipv4Addr::new(192, 168, 1, 50),
            peer: Ipv4Addr::new(192, 168, 1, 1),
            mtu: 1500,
            router: Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)],
        };
        assert_eq!(StartRequest::decode(&request.encode()).unwrap(), request);
    }

    #[test]
    fn start_request_rejects_truncated_bodies() {
        assert!(StartRequest::decode(&[0u8; 16]).is_none());
        // Claims two DNS servers but carries none.
        let mut body = vec![0u8; 17];
        body[16] = 2;
        assert!(StartRequest::decode(&body).is_none());
    }

    #[test]
    fn ifname_and_error_round_trip() {
        assert_eq!(decode_ifname(&encode_ifname("utun4")).unwrap(), "utun4");
        assert_eq!(decode_error(&encode_error("boom")), "boom");
        assert!(decode_ifname(&[]).is_none());
    }

    #[test]
    fn frame_reader_reassembles_across_reads() {
        let mut stream = frame(KIND_PACKET, &[1, 2, 3, 4]);
        stream.extend_from_slice(&frame(KIND_STOP, &[]));
        let mut reader = FrameReader::default();

        // Feed it one byte at a time; nothing completes until the first frame is
        // whole, then the second.
        for byte in &stream[..8] {
            reader.extend(&[*byte]);
            assert!(reader.next().is_none());
        }
        reader.extend(&stream[8..]);
        assert_eq!(reader.next(), Some((KIND_PACKET, vec![1, 2, 3, 4])));
        assert_eq!(reader.next(), Some((KIND_STOP, Vec::new())));
        assert!(reader.next().is_none());
    }

    #[test]
    fn frame_reader_handles_a_zero_length_body() {
        let mut reader = FrameReader::default();
        reader.extend(&frame(KIND_PING, &[]));
        assert_eq!(reader.next(), Some((KIND_PING, Vec::new())));
    }

    #[test]
    fn install_script_quotes_the_path_and_asks_for_privileges() {
        let script = install_script(std::path::Path::new(
            "/Applications/MT7601U.app/Contents/MacOS/MT7601U",
        ));
        assert!(script.starts_with("do shell script \""));
        assert!(script.ends_with("\" with administrator privileges"));
        assert!(script.contains("--install-helper"));
        // The path is single-quoted so spaces are preserved for /bin/sh.
        assert!(
            script.contains("'/Applications/MT7601U.app/Contents/MacOS/MT7601U' --install-helper")
        );
    }

    #[test]
    fn install_script_escapes_quotes_and_backslashes() {
        // A path with a double quote must not break out of the AppleScript
        // string literal.
        let script = install_script(std::path::Path::new("/tmp/we\"ird"));
        assert!(!script.contains("\"/tmp/we\"ird\" --install-helper"));
        assert!(script.contains("\\\""));
    }

    #[test]
    fn uninstall_script_asks_for_privileges_and_removes_the_helper() {
        let script = uninstall_script(std::path::Path::new(
            "/Applications/MT7601U.app/Contents/MacOS/MT7601U",
        ));
        assert!(script.starts_with("do shell script \""));
        assert!(script.ends_with("\" with administrator privileges"));
        assert!(
            script.contains("'/Applications/MT7601U.app/Contents/MacOS/MT7601U' --uninstall-helper")
        );
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(shell_quote("plain"), "'plain'");
    }

    #[test]
    fn apple_script_string_escapes_quotes_and_backslashes() {
        assert_eq!(apple_script_string("a\"b\\c"), "a\\\"b\\\\c");
    }
}
