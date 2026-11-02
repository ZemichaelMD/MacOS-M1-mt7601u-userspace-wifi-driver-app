//! WPA2-PSK 4-way handshake, supplicant side (IEEE 802.11i §8.5.6.3).
//!
//! Pure state machine: it is fed EAPOL-Key frames (already de-encapsulated from
//! the 802.11 data path) and returns the reply to transmit. Key installation
//! into the hardware is done by the caller once the handshake completes.

use super::eapol::{self, EapolKey, Gtk};
use super::rsn;
use super::wpa::{self, Ptk, NONCE_LEN};

/// A handshake failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The frame was not an EAPOL-Key frame.
    NotAnEapolKey,
    /// An unexpected handshake message number.
    UnexpectedMessage(u8),
    /// The message's MIC did not verify against the KCK.
    MicMismatch,
    /// The replay counter did not advance.
    StaleReplay,
    /// The wrapped key data failed its integrity check.
    KeyUnwrap,
    /// Message 3 did not carry a GTK.
    NoGtk,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::NotAnEapolKey => write!(f, "not an EAPOL-Key frame"),
            HandshakeError::UnexpectedMessage(number) => {
                write!(f, "unexpected handshake message {number}")
            }
            HandshakeError::MicMismatch => write!(f, "EAPOL-Key MIC did not verify"),
            HandshakeError::StaleReplay => write!(f, "stale replay counter"),
            HandshakeError::KeyUnwrap => write!(f, "key data failed to unwrap"),
            HandshakeError::NoGtk => write!(f, "message 3 carried no GTK"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Which handshake flavor (and key hierarchy) is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpaMode {
    /// WPA1-PSK with TKIP: descriptor 254, MD5 MIC, RC4 key data, and a
    /// separate group-key handshake after the 4-way.
    Wpa1Psk,
    /// WPA2-PSK with CCMP: descriptor 2, SHA1 MIC, AES key wrap.
    Wpa2Psk,
    /// WPA3 SAE with CCMP: the PMK comes from the SAE exchange (not the
    /// passphrase), descriptor version 0, CMAC MIC, AES key wrap.
    Wpa3Sae,
}

/// The supplicant's WPA 4-way handshake (plus the WPA1 group-key handshake).
///
/// Key material is deliberately not printable.
pub struct WpaHandshake {
    mode: WpaMode,
    pmk: [u8; wpa::PMK_LEN],
    authenticator: [u8; 6],
    supplicant: [u8; 6],
    snonce: [u8; NONCE_LEN],
    /// The association IE to echo in message 2: WPA1 vendor IE or RSN IE.
    ie: Vec<u8>,
    anonce: [u8; NONCE_LEN],
    replay: u64,
    ptk: Option<Ptk>,
    gtk: Option<Gtk>,
    /// A GTK received in the WPA1 group handshake that is not installed yet.
    pending_gtk: bool,
    /// The 4-way handshake is done (message 4 built).
    complete: bool,
    /// The group-key handshake is done (or was not needed).
    group_done: bool,
}

impl std::fmt::Debug for WpaHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WpaHandshake")
            .field("mode", &self.mode)
            .field("authenticator", &self.authenticator)
            .field("supplicant", &self.supplicant)
            .field("replay", &self.replay)
            .field("complete", &self.complete)
            .field("group_done", &self.group_done)
            .field("key material", &"<redacted>")
            .finish()
    }
}

impl WpaHandshake {
    /// Start a WPA2-PSK handshake: derive the PMK from the passphrase and SSID.
    pub fn new(
        passphrase: &[u8],
        ssid: &[u8],
        authenticator: [u8; 6],
        supplicant: [u8; 6],
        snonce: [u8; NONCE_LEN],
    ) -> Self {
        Self::new_with(
            WpaMode::Wpa2Psk,
            wpa::pmk(passphrase, ssid),
            rsn::build_psk_ccmp(),
            authenticator,
            supplicant,
            snonce,
        )
    }

    /// Start a WPA1-PSK (TKIP) handshake. The PMK is the same PBKDF2 output as
    /// for WPA2; only the ciphers, MIC and message framing differ.
    pub fn new_wpa1(
        passphrase: &[u8],
        ssid: &[u8],
        authenticator: [u8; 6],
        supplicant: [u8; 6],
        snonce: [u8; NONCE_LEN],
    ) -> Self {
        Self::new_with(
            WpaMode::Wpa1Psk,
            wpa::pmk(passphrase, ssid),
            rsn::build_wpa1_psk_tkip(),
            authenticator,
            supplicant,
            snonce,
        )
    }

    /// Start a WPA3-SAE handshake from an already derived PMK.
    pub fn new_sae(
        pmk: [u8; wpa::PMK_LEN],
        authenticator: [u8; 6],
        supplicant: [u8; 6],
        snonce: [u8; NONCE_LEN],
    ) -> Self {
        Self::new_with(
            WpaMode::Wpa3Sae,
            pmk,
            rsn::build_sae_ccmp(),
            authenticator,
            supplicant,
            snonce,
        )
    }

    fn new_with(
        mode: WpaMode,
        pmk: [u8; wpa::PMK_LEN],
        ie: Vec<u8>,
        authenticator: [u8; 6],
        supplicant: [u8; 6],
        snonce: [u8; NONCE_LEN],
    ) -> Self {
        Self {
            mode,
            pmk,
            authenticator,
            supplicant,
            snonce,
            ie,
            anonce: [0u8; NONCE_LEN],
            replay: 0,
            ptk: None,
            gtk: None,
            pending_gtk: false,
            complete: false,
            group_done: false,
        }
    }

    /// The handshake flavor in use.
    pub fn mode(&self) -> WpaMode {
        self.mode
    }

    /// The derived PTK, once message 1 has been processed.
    pub fn ptk(&self) -> Option<&Ptk> {
        self.ptk.as_ref()
    }

    /// The group key, once it is known (message 3, or the group 1/2 message).
    pub fn gtk(&self) -> Option<&Gtk> {
        self.gtk.as_ref()
    }

    /// Whether the 4-way handshake has completed (message 4 built).
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Whether everything this mode expects has been received: the 4-way, and
    /// for WPA1 also the group-key handshake (unless the AP sent the GTK in
    /// message 3, which WPA1 APs normally do not).
    pub fn is_fully_complete(&self) -> bool {
        self.complete && (self.mode != WpaMode::Wpa1Psk || self.group_done)
    }

    /// A GTK from the WPA1 group handshake that still needs installing.
    ///
    /// wpa_supplicant installs the GTK *before* sending 2/2
    /// (`wpa_supplicant_process_1_of_2`: `install_gtk(...) || send_2_of_2(...)`),
    /// so the caller installs it when this is true and then clears the flag.
    pub fn pending_group_key(&self) -> bool {
        self.pending_gtk
    }

    /// Record that the pending group key has been installed into the hardware.
    pub fn mark_group_key_installed(&mut self) {
        self.pending_gtk = false;
    }

    /// Feed one EAPOL-Key frame; returns the reply to transmit, if any.
    ///
    /// Dispatch mirrors `wpa_sm_rx_eapol`: the AP always sets ACK, a pairwise
    /// frame with MIC/key-data-encrypted is message 3, a pairwise frame without
    /// either is message 1, and a non-pairwise frame with MIC is the group-key
    /// message 1.
    pub fn on_frame(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, HandshakeError> {
        let message = EapolKey::parse(frame).ok_or(HandshakeError::NotAnEapolKey)?;
        if !message.is_ack() {
            return Ok(None);
        }

        if message.is_pairwise() {
            if message.has_mic() || message.key_data_encrypted() {
                self.on_message_3(&message)
            } else {
                self.on_message_1(&message)
            }
        } else if message.has_mic() || message.key_data_encrypted() {
            self.on_group_message_1(&message)
        } else {
            Ok(None)
        }
    }

    /// Message 1/4: extract the ANonce, derive the PTK and reply with 2/4.
    fn on_message_1(&mut self, message: &EapolKey<'_>) -> Result<Option<Vec<u8>>, HandshakeError> {
        if self.ptk.is_some() {
            return Ok(None); // already answered; ignore a retransmission
        }
        self.anonce.copy_from_slice(&message.nonce);
        self.replay = message.replay;

        let mut derived = match self.mode {
            WpaMode::Wpa1Psk => wpa::ptk_tkip(
                &self.pmk,
                &self.authenticator,
                &self.supplicant,
                &self.anonce,
                &self.snonce,
            ),
            WpaMode::Wpa2Psk => wpa::ptk(
                &self.pmk,
                &self.authenticator,
                &self.supplicant,
                &self.anonce,
                &self.snonce,
            ),
            WpaMode::Wpa3Sae => wpa::ptk_sae(
                &self.pmk,
                &self.authenticator,
                &self.supplicant,
                &self.anonce,
                &self.snonce,
            ),
        };
        // wpa_supplicant swaps the TKIP MIC halves right after deriving the
        // PTK (`wpa_supplicant_process_1_of_4`), so what reaches the driver is
        // the swapped order.
        if self.mode == WpaMode::Wpa1Psk {
            wpa::tkip_swap_mic_keys(&mut derived.tk);
        }

        let reply = match self.mode {
            WpaMode::Wpa1Psk => eapol::build_message2_wpa1(
                self.replay,
                &self.snonce,
                &self.ie,
                message.key_length,
                &derived.kck,
            ),
            WpaMode::Wpa2Psk => {
                eapol::build_message2(self.replay, &self.snonce, &self.ie, &derived.kck)
            }
            WpaMode::Wpa3Sae => eapol::build_message2_with_version(
                message.descriptor_version(),
                self.replay,
                &self.snonce,
                &self.ie,
                &derived.kck,
            ),
        };
        self.ptk = Some(derived);
        Ok(Some(reply))
    }

    /// Message 3/4: verify the MIC, recover the GTK and reply with 4/4.
    fn on_message_3(&mut self, message: &EapolKey<'_>) -> Result<Option<Vec<u8>>, HandshakeError> {
        let derived = self.ptk.ok_or(HandshakeError::StaleReplay)?;
        if message.replay <= self.replay {
            return Err(HandshakeError::StaleReplay);
        }
        if !message.verify_mic(&derived.kck) {
            return Err(HandshakeError::MicMismatch);
        }

        let key_data = if message.key_data_encrypted() {
            match self.mode {
                WpaMode::Wpa1Psk => {
                    // WPA1 wraps key data with RC4 (key_iv ‖ KEK, 256 skipped).
                    let mut ek = [0u8; 32];
                    ek[..16].copy_from_slice(&message.key_iv);
                    ek[16..].copy_from_slice(&derived.kek);
                    wpa::rc4_skip(&ek, 256, message.key_data)
                }
                _ => wpa::unwrap_key(&derived.kek, message.key_data)
                    .ok_or(HandshakeError::KeyUnwrap)?,
            }
        } else {
            message.key_data.to_vec()
        };

        // WPA2/WPA3 message 3 must carry the GTK; WPA1 normally defers it to
        // the group-key handshake, but tolerate a nonstandard GTK KDE.
        let gtk = eapol::parse_gtk_kde(&key_data);
        if gtk.is_none() && self.mode != WpaMode::Wpa1Psk {
            return Err(HandshakeError::NoGtk);
        }

        let reply = match self.mode {
            WpaMode::Wpa1Psk => eapol::build_message4_wpa1(
                message.replay,
                &message.nonce,
                message.key_length,
                message.is_secure(),
                &derived.kck,
            ),
            WpaMode::Wpa2Psk => eapol::build_message4(message.replay, &message.nonce, &derived.kck),
            WpaMode::Wpa3Sae => eapol::build_message4_with_version(
                message.descriptor_version(),
                message.replay,
                &message.nonce,
                &derived.kck,
            ),
        };
        self.gtk = gtk;
        self.replay = message.replay;
        self.complete = true;
        if self.mode == WpaMode::Wpa1Psk {
            // A WPA1 AP that sent a GTK KDE here does not run a group handshake.
            self.group_done = self.gtk.is_some();
        }
        Ok(Some(reply))
    }

    /// Group-key message 1/2: verify the MIC, decrypt the raw GTK and reply
    /// with 2/2 (WPA1 only; WPA2/WPA3 rekeys arrive as message 3/4-style GTK
    /// updates and are not handled).
    fn on_group_message_1(
        &mut self,
        message: &EapolKey<'_>,
    ) -> Result<Option<Vec<u8>>, HandshakeError> {
        if self.mode != WpaMode::Wpa1Psk || !self.complete {
            return Ok(None);
        }
        let derived = self.ptk.ok_or(HandshakeError::StaleReplay)?;
        if message.replay <= self.replay {
            return Err(HandshakeError::StaleReplay);
        }
        if !message.verify_mic(&derived.kck) {
            return Err(HandshakeError::MicMismatch);
        }

        // WPA1 always RC4-encrypts this key data (hostap encrypts with
        // `encr=1` but only sets ENCR_KEY_DATA for WPA2), with the raw GTK as
        // the payload and the key length in the header.
        let mut ek = [0u8; 32];
        ek[..16].copy_from_slice(&message.key_iv);
        ek[16..].copy_from_slice(&derived.kek);
        let decrypted = wpa::rc4_skip(&ek, 256, message.key_data);

        let gtk_len = usize::from(message.key_length);
        if gtk_len == 0 || gtk_len > decrypted.len() {
            return Err(HandshakeError::KeyUnwrap);
        }

        let reply = eapol::build_group_message2_wpa1(
            message.key_info,
            message.replay,
            message.key_length,
            &derived.kck,
        );
        self.gtk = Some(Gtk {
            key_id: message.key_index(),
            key: decrypted[..gtk_len].to_vec(),
        });
        self.pending_gtk = true;
        self.replay = message.replay;
        self.group_done = true;
        Ok(Some(reply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AA: [u8; 6] = [0x00, 0x0f, 0xb5, 0xfd, 0xfb, 0xc2];
    const SPA: [u8; 6] = [0x00, 0x0f, 0xb5, 0xfd, 0xfb, 0xc1];
    const ANONCE: [u8; NONCE_LEN] = [
        0x7e, 0xf8, 0x3a, 0xa0, 0x63, 0xcb, 0xcf, 0xd4, 0xf6, 0x5f, 0x85, 0x32, 0x42, 0x3a, 0x11,
        0x2f, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
        0x01, 0x23,
    ];
    const SNONCE: [u8; NONCE_LEN] = [
        0x0e, 0x1f, 0x22, 0x45, 0x6d, 0x4e, 0x1a, 0x0f, 0xf4, 0x12, 0x27, 0x5a, 0x1d, 0x1f, 0x2e,
        0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x01, 0x23,
    ];

    fn handshake() -> WpaHandshake {
        WpaHandshake::new(b"password", b"IEEE", AA, SPA, SNONCE)
    }

    fn handshake_wpa1() -> WpaHandshake {
        WpaHandshake::new_wpa1(b"password", b"IEEE", AA, SPA, SNONCE)
    }

    /// Message 1/4 from the AP.
    fn message1(replay: u64) -> Vec<u8> {
        eapol::build(
            eapol::KEY_INFO_VERSION2 | eapol::KEY_INFO_PAIRWISE | eapol::KEY_INFO_ACK,
            replay,
            &ANONCE,
            &[],
            None,
        )
    }

    /// WPA1 message 1/4 from the AP (descriptor 254, version 1, TKIP length).
    fn message1_wpa1(replay: u64) -> Vec<u8> {
        eapol::build_key(
            &eapol::EapolKeyFrame {
                descriptor: eapol::DESCRIPTOR_WPA,
                key_info: eapol::KEY_INFO_VERSION1 | eapol::KEY_INFO_PAIRWISE | eapol::KEY_INFO_ACK,
                key_length: 32,
                replay,
                nonce: &ANONCE,
                key_iv: &[0u8; 16],
                key_data: &[],
            },
            None,
        )
    }

    /// WPA1 message 3/4 from the AP: the WPA IE as key data, no GTK.
    ///
    /// hostapd sends WPA1 message 3 with SECURE clear (unless the supplicant
    /// set it first), so `secure` is a parameter.
    fn message3_wpa1(replay: u64, kck: &[u8; 16], secure: bool) -> Vec<u8> {
        let mut key_info = eapol::KEY_INFO_VERSION1
            | eapol::KEY_INFO_PAIRWISE
            | eapol::KEY_INFO_ACK
            | eapol::KEY_INFO_MIC
            | eapol::KEY_INFO_INSTALL;
        if secure {
            key_info |= eapol::KEY_INFO_SECURE;
        }
        eapol::build_key(
            &eapol::EapolKeyFrame {
                descriptor: eapol::DESCRIPTOR_WPA,
                key_info,
                key_length: 32,
                replay,
                nonce: &ANONCE,
                key_iv: &[0u8; 16],
                key_data: &rsn::build_wpa1_psk_tkip(),
            },
            Some(kck),
        )
    }

    /// WPA1 group-key message 1/2: the raw GTK as RC4-encrypted key data.
    fn group_message1_wpa1(
        replay: u64,
        kck: &[u8; 16],
        kek: &[u8; 16],
        key_iv: &[u8; 16],
        gtk: &[u8],
    ) -> Vec<u8> {
        let mut ek = [0u8; 32];
        ek[..16].copy_from_slice(key_iv);
        ek[16..].copy_from_slice(kek);
        let encrypted = wpa::rc4_skip(&ek, 256, gtk);
        eapol::build_key(
            &eapol::EapolKeyFrame {
                descriptor: eapol::DESCRIPTOR_WPA,
                key_info: eapol::KEY_INFO_VERSION1
                    | eapol::KEY_INFO_ACK
                    | eapol::KEY_INFO_MIC
                    | eapol::KEY_INFO_SECURE
                    | eapol::KEY_INFO_INSTALL
                    | (1 << 4),
                key_length: gtk.len() as u16,
                replay,
                nonce: &[0u8; 32],
                key_iv,
                key_data: &encrypted,
            },
            Some(kck),
        )
    }

    /// A GTK key-data encapsulation.
    fn gtk_kde() -> Vec<u8> {
        let mut data = vec![0xdd, 0x0e, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00];
        data.extend_from_slice(&[0xab; 8]);
        data
    }

    /// RFC 3394 AES key wrap (test-only; the supplicant only ever unwraps).
    fn wrap(kek: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
        use aes::Aes128;

        assert!(plain.len() >= 16 && plain.len().is_multiple_of(8));
        let cipher = Aes128::new_from_slice(kek).unwrap();
        let n = plain.len() / 8;
        let mut a: u64 = 0xa6a6_a6a6_a6a6_a6a6;
        let mut blocks: Vec<[u8; 8]> = (0..n)
            .map(|i| {
                let mut block = [0u8; 8];
                block.copy_from_slice(&plain[i * 8..i * 8 + 8]);
                block
            })
            .collect();

        for j in 0..6u64 {
            for i in 1..=n {
                let mut block = [0u8; 16];
                block[..8].copy_from_slice(&a.to_be_bytes());
                block[8..].copy_from_slice(&blocks[i - 1]);
                cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
                a = u64::from_be_bytes(block[..8].try_into().unwrap()) ^ (n as u64 * j + i as u64);
                blocks[i - 1].copy_from_slice(&block[8..]);
            }
        }

        let mut out = a.to_be_bytes().to_vec();
        for block in blocks {
            out.extend_from_slice(&block);
        }
        out
    }

    #[test]
    fn message1_derives_the_reference_ptk_and_produces_message2() {
        let mut hs = handshake();
        let reply = hs.on_frame(&message1(1)).unwrap().expect("reply");

        let ptk = hs.ptk().unwrap();
        assert_eq!(
            ptk.kck,
            [
                0xbf, 0xcd, 0xca, 0x8b, 0xfa, 0xca, 0x3d, 0xa5, 0x64, 0xca, 0x3c, 0x20, 0x01, 0xc8,
                0x80, 0x9e
            ]
        );

        // Message 2 carries our SNonce, the RSN IE and a valid MIC.
        let parsed = EapolKey::parse(&reply).unwrap();
        assert_eq!(parsed.message_number(), Some(2));
        assert_eq!(parsed.nonce, SNONCE);
        assert!(rsn::parse(parsed.key_data).unwrap().supports_psk_ccmp());
        assert!(parsed.verify_mic(&ptk.kck));
        assert!(!hs.is_complete());
    }

    #[test]
    fn message3_completes_the_handshake_and_unwraps_the_gtk() {
        let mut hs = handshake();
        hs.on_frame(&message1(1)).unwrap();
        let ptk = *hs.ptk().unwrap();

        // Wrap the GTK with the handshake's real KEK; the handshake must
        // unwrap it and finish.
        let wrapped = wrap(&ptk.kek, &gtk_kde());
        let frame = eapol::build(
            eapol::KEY_INFO_VERSION2
                | eapol::KEY_INFO_PAIRWISE
                | eapol::KEY_INFO_INSTALL
                | eapol::KEY_INFO_ACK
                | eapol::KEY_INFO_MIC
                | eapol::KEY_INFO_SECURE
                | eapol::KEY_INFO_ENCRYPTED,
            2,
            &ANONCE,
            &wrapped,
            Some(&ptk.kck),
        );

        let reply = hs.on_frame(&frame).unwrap().expect("reply");
        assert!(hs.is_complete());
        assert_eq!(hs.gtk().unwrap().key, vec![0xab; 8]);
        assert_eq!(EapolKey::parse(&reply).unwrap().message_number(), Some(4));
        assert!(EapolKey::parse(&reply).unwrap().verify_mic(&ptk.kck));
    }

    #[test]
    fn message3_with_a_bad_mic_is_rejected() {
        let mut hs = handshake();
        hs.on_frame(&message1(1)).unwrap();
        let frame = eapol::build(
            eapol::KEY_INFO_VERSION2
                | eapol::KEY_INFO_PAIRWISE
                | eapol::KEY_INFO_ACK
                | eapol::KEY_INFO_MIC
                | eapol::KEY_INFO_SECURE,
            2,
            &ANONCE,
            &[],
            Some(&[0u8; 16]), // wrong KCK
        );
        assert_eq!(hs.on_frame(&frame), Err(HandshakeError::MicMismatch));
    }

    #[test]
    fn stale_replay_counter_is_rejected() {
        let mut hs = handshake();
        hs.on_frame(&message1(5)).unwrap();
        let ptk = *hs.ptk().unwrap();
        let frame = eapol::build(
            eapol::KEY_INFO_VERSION2
                | eapol::KEY_INFO_PAIRWISE
                | eapol::KEY_INFO_ACK
                | eapol::KEY_INFO_MIC
                | eapol::KEY_INFO_SECURE,
            5, // not greater than message 1's counter
            &ANONCE,
            &[],
            Some(&ptk.kck),
        );
        assert_eq!(hs.on_frame(&frame), Err(HandshakeError::StaleReplay));
    }

    #[test]
    fn message1_retransmission_is_ignored_after_the_ptk_exists() {
        let mut hs = handshake();
        hs.on_frame(&message1(1)).unwrap();
        assert_eq!(hs.on_frame(&message1(1)).unwrap(), None);
    }

    #[test]
    fn non_pairwise_and_garbage_frames_are_ignored() {
        let mut hs = handshake();
        assert_eq!(hs.on_frame(&[0u8; 8]), Err(HandshakeError::NotAnEapolKey));
        let group = eapol::build(
            eapol::KEY_INFO_VERSION2 | eapol::KEY_INFO_ACK,
            1,
            &[0u8; 32],
            &[],
            None,
        );
        assert_eq!(hs.on_frame(&group).unwrap(), None);
        // The AP always sets ACK; a frame without it is not addressed to us.
        let no_ack = eapol::build(
            eapol::KEY_INFO_VERSION2 | eapol::KEY_INFO_PAIRWISE,
            1,
            &ANONCE,
            &[],
            None,
        );
        assert_eq!(hs.on_frame(&no_ack).unwrap(), None);
    }

    #[test]
    fn wpa1_message1_derives_a_swapped_tkip_ptk_and_replies_with_version1() {
        let mut hs = handshake_wpa1();
        let reply = hs.on_frame(&message1_wpa1(1)).unwrap().expect("reply");

        // The stored TK has swapped MIC halves, exactly like wpa_supplicant's
        // TKIP post-processing before the key reaches the driver.
        let ptk = hs.ptk().unwrap();
        let raw = wpa::ptk_tkip(&wpa::pmk(b"password", b"IEEE"), &AA, &SPA, &ANONCE, &SNONCE);
        assert_eq!(&ptk.tk[..16], &raw.tk[..16]);
        assert_eq!(&ptk.tk[16..24], &raw.tk[24..32]);
        assert_eq!(&ptk.tk[24..32], &raw.tk[16..24]);
        assert_eq!(ptk.tk_len, 32);

        let parsed = EapolKey::parse(&reply).unwrap();
        assert_eq!(parsed.descriptor, eapol::DESCRIPTOR_WPA);
        assert_eq!(parsed.descriptor_version(), eapol::KEY_INFO_VERSION1);
        assert_eq!(parsed.key_length, 32);
        assert_eq!(parsed.nonce, SNONCE);
        let ie = rsn::parse_wpa1(parsed.key_data).unwrap();
        assert_eq!(ie.group_cipher, rsn::SUITE_TKIP);
        assert_eq!(ie.pairwise, vec![rsn::SUITE_TKIP]);
        assert_eq!(ie.akm, vec![rsn::SUITE_PSK]);
        assert!(parsed.verify_mic(&ptk.kck));
    }

    #[test]
    fn wpa1_message3_without_gtk_completes_the_four_way() {
        let mut hs = handshake_wpa1();
        hs.on_frame(&message1_wpa1(1)).unwrap();
        let ptk = *hs.ptk().unwrap();

        let reply = hs
            .on_frame(&message3_wpa1(2, &ptk.kck, false))
            .unwrap()
            .expect("reply");

        assert!(hs.is_complete());
        assert!(!hs.is_fully_complete()); // the group key is still to come
        assert!(hs.gtk().is_none());

        let parsed = EapolKey::parse(&reply).unwrap();
        // A WPA1 message 4 with SECURE clear (hostapd sets it only if the
        // supplicant did) looks like a message 2 to `message_number`, so the
        // bits are checked directly.
        assert!(parsed.is_pairwise());
        assert!(parsed.has_mic());
        assert!(!parsed.is_secure()); // copied from message 3
        assert!(parsed.key_data.is_empty());
        assert_eq!(parsed.replay, 2);
        assert_eq!(parsed.descriptor, eapol::DESCRIPTOR_WPA);
        assert_eq!(parsed.descriptor_version(), eapol::KEY_INFO_VERSION1);
        assert_eq!(parsed.key_length, 32);
        assert_eq!(parsed.nonce, ANONCE);
        assert!(parsed.verify_mic(&ptk.kck));
    }

    #[test]
    fn wpa1_message3_with_a_bad_mic_is_rejected() {
        let mut hs = handshake_wpa1();
        hs.on_frame(&message1_wpa1(1)).unwrap();
        let frame = message3_wpa1(2, &[0u8; 16], false);
        assert_eq!(hs.on_frame(&frame), Err(HandshakeError::MicMismatch));
    }

    #[test]
    fn wpa1_group_message1_decrypts_the_gtk_and_replies_with_2_of_2() {
        let mut hs = handshake_wpa1();
        hs.on_frame(&message1_wpa1(1)).unwrap();
        let ptk = *hs.ptk().unwrap();
        hs.on_frame(&message3_wpa1(2, &ptk.kck, true)).unwrap();

        let gtk = [0x77u8; 32];
        let frame = group_message1_wpa1(3, &ptk.kck, &ptk.kek, &[0x5a; 16], &gtk);
        let reply = hs.on_frame(&frame).unwrap().expect("reply");

        assert!(hs.is_fully_complete());
        assert!(hs.pending_group_key());
        let received = hs.gtk().unwrap();
        assert_eq!(received.key_id, 1);
        assert_eq!(received.key, gtk.to_vec());

        let parsed = EapolKey::parse(&reply).unwrap();
        assert_eq!(parsed.descriptor, eapol::DESCRIPTOR_WPA);
        assert_eq!(parsed.descriptor_version(), eapol::KEY_INFO_VERSION1);
        assert_eq!(parsed.key_index(), 1);
        assert!(parsed.is_secure());
        assert!(parsed.has_mic());
        assert!(!parsed.is_ack());
        assert_eq!(parsed.replay, 3);
        assert!(parsed.key_data.is_empty());
        assert!(parsed.verify_mic(&ptk.kck));

        hs.mark_group_key_installed();
        assert!(!hs.pending_group_key());
    }

    #[test]
    fn wpa1_group_message_before_message3_is_ignored() {
        let mut hs = handshake_wpa1();
        hs.on_frame(&message1_wpa1(1)).unwrap();
        let ptk = *hs.ptk().unwrap();
        let frame = group_message1_wpa1(2, &ptk.kck, &ptk.kek, &[0u8; 16], &[0x11; 32]);
        assert_eq!(hs.on_frame(&frame).unwrap(), None);
    }

    #[test]
    fn wpa2_ignores_group_key_messages() {
        // The WPA2 GTK arrives in message 3; a group 1/2 message (e.g. from a
        // legacy AP) is not part of that flow.
        let mut hs = handshake();
        hs.on_frame(&message1(1)).unwrap();
        let ptk = *hs.ptk().unwrap();
        let frame = group_message1_wpa1(2, &ptk.kck, &ptk.kek, &[0u8; 16], &[0x11; 32]);
        assert_eq!(hs.on_frame(&frame).unwrap(), None);
        assert!(hs.gtk().is_none());
    }

    #[test]
    fn debug_redacts_key_material() {
        let hs = handshake();
        let rendered = format!("{hs:?}");
        assert!(rendered.contains("redacted"));
    }
}
