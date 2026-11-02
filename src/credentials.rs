//! Saved networks and preferences, so connecting is one click next time.
//!
//! Everything lives in one tab-separated file under
//! `~/Library/Application Support/mt7601u-macos/`, created `0600`. A passphrase
//! is a secret, so it never reaches a `LogLine`, a `Command` or an `Event`, and
//! the file's permissions are checked before it is trusted.
//!
//! The format is line oriented, so one damaged line costs one saved network
//! rather than the whole file (`<TAB>` is a literal tab, and tabs, newlines and
//! backslashes inside a field are escaped):
//!
//! ```text
//! # mt7601u saved networks — keep this file private
//! auto_connect<TAB>true
//! last_ssid<TAB>HaLePo
//! passphrase<TAB>HaLePo<TAB>correct horse battery staple
//! ```

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::commands::Addressing;

/// Saved networks, preferences and tunnel addressing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Reconnect to [`Self::last_ssid`] automatically once it is in range.
    pub auto_connect: bool,
    /// The network to prefer when reconnecting automatically.
    pub last_ssid: Option<String>,
    /// How the tunnel is addressed (DHCP or a manual address).
    pub addressing: Addressing,
    passphrases: BTreeMap<String, String>,
}

impl Default for Credentials {
    fn default() -> Self {
        Self {
            // The app is meant to come up connected without being asked.
            auto_connect: true,
            last_ssid: None,
            addressing: Addressing::default(),
            passphrases: BTreeMap::new(),
        }
    }
}

impl Credentials {
    /// Read saved networks, or defaults when there is nothing stored yet.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Self::parse(&text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    /// Write saved networks, forcing owner-only permissions.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.render())?;
        // `write` keeps an existing file's mode, so set it explicitly rather
        // than relying on the umask at creation time.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }

    /// The passphrase for `ssid`, if one was saved.
    pub fn passphrase(&self, ssid: &str) -> Option<&str> {
        self.passphrases.get(ssid).map(String::as_str)
    }

    pub fn has_passphrase(&self, ssid: &str) -> bool {
        self.passphrases.contains_key(ssid)
    }

    /// Networks with a saved passphrase, in a stable order.
    pub fn known_ssids(&self) -> Vec<String> {
        self.passphrases.keys().cloned().collect()
    }

    /// Remember a passphrase for `ssid`.
    pub fn remember(&mut self, ssid: &str, passphrase: &str) {
        self.passphrases
            .insert(ssid.to_string(), passphrase.to_string());
    }

    /// Forget the passphrase for `ssid`. True when one was removed.
    pub fn forget(&mut self, ssid: &str) -> bool {
        self.passphrases.remove(ssid).is_some()
    }

    /// Record the network we just joined, so it can be reconnected later.
    pub fn mark_connected(&mut self, ssid: &str) {
        self.last_ssid = Some(ssid.to_string());
    }

    /// Parse the stored format. Unknown keys are ignored so an older build can
    /// still read a file written by a newer one.
    pub fn parse(text: &str) -> Self {
        let mut credentials = Self::default();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t');
            match fields.next() {
                Some("auto_connect") => {
                    if let Some(value) = fields.next() {
                        credentials.auto_connect = value == "true";
                    }
                }
                Some("last_ssid") => {
                    credentials.last_ssid =
                        fields.next().map(unescape).filter(|ssid| !ssid.is_empty());
                }
                Some("passphrase") => {
                    if let (Some(ssid), Some(passphrase)) = (fields.next(), fields.next()) {
                        let ssid = unescape(ssid);
                        if !ssid.is_empty() {
                            credentials.passphrases.insert(ssid, unescape(passphrase));
                        }
                    }
                }
                Some("addressing") => {
                    if fields.next() == Some("manual") {
                        if let (Some(address), Some(gateway)) = (fields.next(), fields.next()) {
                            if let (Ok(address), Ok(gateway)) = (address.parse(), gateway.parse()) {
                                let dns = fields
                                    .next()
                                    .map(|list| {
                                        list.split(',')
                                            .filter_map(|server| server.parse().ok())
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                credentials.addressing = Addressing::Manual {
                                    address,
                                    gateway,
                                    dns,
                                };
                            }
                        }
                    } else {
                        credentials.addressing = Addressing::Dhcp;
                    }
                }
                _ => {}
            }
        }
        credentials
    }

    /// Render the stored format.
    pub fn render(&self) -> String {
        let mut out = String::from("# mt7601u saved networks — keep this file private\n");
        out.push_str(&format!("auto_connect\t{}\n", self.auto_connect));
        if let Some(ssid) = &self.last_ssid {
            out.push_str(&format!("last_ssid\t{}\n", escape(ssid)));
        }
        match &self.addressing {
            Addressing::Dhcp => out.push_str("addressing\tdhcp\n"),
            Addressing::Manual {
                address,
                gateway,
                dns,
            } => out.push_str(&format!(
                "addressing\tmanual\t{address}\t{gateway}\t{}\n",
                dns.iter()
                    .map(|server| server.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )),
        }
        for (ssid, passphrase) in &self.passphrases {
            out.push_str(&format!(
                "passphrase\t{}\t{}\n",
                escape(ssid),
                escape(passphrase)
            ));
        }
        out
    }
}

/// True when the file is readable only by its owner. A missing file counts.
pub fn is_private(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|meta| meta.permissions().mode() & 0o077 == 0)
        .unwrap_or(true)
}

fn escape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    for ch in field.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            // An unknown escape is kept verbatim rather than dropped, so a
            // hand-edited file never silently loses characters.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    #[test]
    fn tunnel_addressing_round_trips_and_defaults_to_dhcp() {
        let credentials = Credentials::default();
        assert_eq!(credentials.addressing, Addressing::Dhcp);
        assert_eq!(Credentials::parse(&credentials.render()), credentials);

        let credentials = Credentials {
            addressing: Addressing::Manual {
                address: Ipv4Addr::new(192, 168, 43, 5),
                gateway: Ipv4Addr::new(192, 168, 43, 1),
                dns: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)],
            },
            ..Credentials::default()
        };
        assert_eq!(Credentials::parse(&credentials.render()), credentials);
    }

    #[test]
    fn a_damaged_addressing_line_falls_back_to_dhcp() {
        let credentials = Credentials::parse("addressing\tmanual\tnot-an-ip\t1.1.1.1\t\n");
        assert_eq!(credentials.addressing, Addressing::Dhcp);
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mt7601u-credentials-test-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn defaults_reconnect_to_the_last_network() {
        let credentials = Credentials::default();
        assert!(credentials.auto_connect);
        assert_eq!(credentials.last_ssid, None);
        assert!(credentials.known_ssids().is_empty());
    }

    #[test]
    fn round_trips_through_the_stored_format() {
        let mut credentials = Credentials::default();
        credentials.remember("HaLePo", "correct horse battery staple");
        credentials.remember("Cafe\tCorner", "p\\ss\\word\nnewline");
        credentials.mark_connected("HaLePo");
        credentials.auto_connect = false;

        let restored = Credentials::parse(&credentials.render());
        assert_eq!(restored, credentials);
        assert_eq!(
            restored.passphrase("Cafe\tCorner"),
            Some("p\\ss\\word\nnewline")
        );
    }

    #[test]
    fn handles_an_empty_passphrase_and_unicode_ssid() {
        let mut credentials = Credentials::default();
        credentials.remember("Zee 🔐", "");
        let restored = Credentials::parse(&credentials.render());
        assert_eq!(restored.passphrase("Zee 🔐"), Some(""));
        assert!(restored.has_passphrase("Zee 🔐"));
    }

    #[test]
    fn skips_comments_unknown_keys_and_damaged_lines() {
        let credentials = Credentials::parse(
            "# comment\n\
             something_new\t1\n\
             auto_connect\tfalse\n\
             passphrase\tonly-an-ssid\n\
             passphrase\tCafe\thunter2\n\
             \n",
        );
        assert!(!credentials.auto_connect);
        assert_eq!(credentials.passphrase("Cafe"), Some("hunter2"));
        assert_eq!(credentials.known_ssids().len(), 1);
    }

    #[test]
    fn unknown_keys_do_not_reset_preferences() {
        let credentials = Credentials::parse("auto_connect\ttrue\nfuture_key\twhatever\n");
        assert!(credentials.auto_connect);
    }

    #[test]
    fn forget_removes_only_the_named_network() {
        let mut credentials = Credentials::default();
        credentials.remember("a", "1");
        credentials.remember("b", "2");
        assert!(credentials.forget("a"));
        assert!(!credentials.forget("a"));
        assert!(!credentials.has_passphrase("a"));
        assert!(credentials.has_passphrase("b"));
    }

    #[test]
    fn loading_a_missing_file_yields_defaults() {
        let path = temp_path("missing");
        let _ = std::fs::remove_file(&path);
        assert_eq!(Credentials::load(&path).unwrap(), Credentials::default());
    }

    #[test]
    fn saves_owner_only_and_loads_back() {
        let path = temp_path("save-load");
        let _ = std::fs::remove_file(&path);

        let mut credentials = Credentials::default();
        credentials.remember("HaLePo", "hunter2");
        credentials.mark_connected("HaLePo");
        credentials.save(&path).expect("save");

        assert!(is_private(&path), "saved credentials must be 0600");
        assert_eq!(Credentials::load(&path).unwrap(), credentials);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn saving_tightens_permissions_on_a_pre_existing_file() {
        let path = temp_path("loose");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "auto_connect\ttrue\n").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(!is_private(&path));

        Credentials::default().save(&path).expect("save");
        assert!(is_private(&path));

        let _ = std::fs::remove_file(&path);
    }
}
