//! EAPOL-Key frames — the 4-way handshake messages (IEEE 802.1X /
//! IEEE 802.11i §8.5.2).
//!
//! The MIC is computed over the whole EAPOL frame with the MIC field zeroed;
//! its algorithm follows the key descriptor version — HMAC-MD5-128 for WPA1
//! (version 1), HMAC-SHA1-128 for WPA2 (version 2), AES-128-CMAC for WPA3 SAE
//! (version 0, "AKM-defined") and SHA-256 AKMs (version 3). Message 3's key
//! data (the GTK) is wrapped with the KEK using RFC 3394, or with RC4 for WPA1.
//!
//! The WPA1 descriptor type is 254 instead of the RSN type 2; the rest of the
//! frame layout is the same.

use super::wpa;

/// EAPOL protocol version we emit.
pub const EAPOL_VERSION: u8 = 2;
/// EAPOL packet type: EAPOL-Key.
pub const TYPE_EAPOL_KEY: u8 = 3;
/// Key descriptor type: RSN (WPA2/WPA3).
pub const DESCRIPTOR_RSN: u8 = 2;
/// Key descriptor type: WPA1 (vendor-specific).
pub const DESCRIPTOR_WPA: u8 = 254;
/// EtherType for EAPOL.
pub const ETHERTYPE_EAPOL: u16 = 0x888e;

/// Mask for the key descriptor version bits.
pub const KEY_INFO_VERSION_MASK: u16 = 0x0007;
/// Key descriptor version 0: AKM-defined — AES-128-CMAC (SAE).
pub const KEY_INFO_VERSION_AKM_DEFINED: u16 = 0;
/// Key descriptor version 1: HMAC-MD5-128 with RC4 (WPA1/TKIP).
pub const KEY_INFO_VERSION1: u16 = 1;
/// Key descriptor version 2: HMAC-SHA1-128 with AES (WPA2/CCMP).
pub const KEY_INFO_VERSION2: u16 = 2;
/// Key descriptor version 3: AES-128-CMAC (WPA2-SHA256, WPA3).
pub const KEY_INFO_VERSION3: u16 = 3;
/// Pairwise key.
pub const KEY_INFO_PAIRWISE: u16 = 0x0008;
/// The key-index bits (bits 4–5), used by group-key messages.
pub const KEY_INFO_KEY_INDEX_MASK: u16 = 0x0030;
/// Install the key.
pub const KEY_INFO_INSTALL: u16 = 0x0040;
/// The AP expects a reply.
pub const KEY_INFO_ACK: u16 = 0x0080;
/// The frame carries a MIC.
pub const KEY_INFO_MIC: u16 = 0x0100;
/// The handshake is complete / the key is in use.
pub const KEY_INFO_SECURE: u16 = 0x0200;
/// Key data is wrapped with the KEK.
pub const KEY_INFO_ENCRYPTED: u16 = 0x1000;

/// Length of the EAPOL header.
const EAPOL_HEADER_LEN: usize = 4;
/// Offset of the key-length field within an EAPOL-Key frame.
const KEY_LENGTH_OFFSET: usize = 7;
/// Offset of the key-IV field within an EAPOL-Key frame.
const KEY_IV_OFFSET: usize = 49;
/// Offset of the MIC field within an EAPOL-Key frame.
const MIC_OFFSET: usize = 81;
/// Offset of the key-data-length field.
const KEY_DATA_LEN_OFFSET: usize = 97;
/// EAPOL header plus the fixed EAPOL-Key fields (key data follows).
const FIXED_LEN: usize = 99;
/// The fixed EAPOL-Key body length (without the EAPOL header).
const KEY_BODY_LEN: usize = FIXED_LEN - EAPOL_HEADER_LEN;

/// Select the MIC algorithm from the key descriptor version.
///
/// Version 0 is "AKM-defined": for SAE (RSN descriptors) that is
/// AES-128-CMAC, matching hostap's `wpa_eapol_key_mic`/`wpa_verify_key_mic`.
fn mic_for(descriptor: u8, key_info: u16, kck: &[u8; 16], frame: &[u8]) -> [u8; wpa::MIC_LEN] {
    match key_info & KEY_INFO_VERSION_MASK {
        KEY_INFO_VERSION1 => wpa::mic_md5(kck, frame),
        KEY_INFO_VERSION3 => wpa::mic_cmac(kck, frame),
        KEY_INFO_VERSION_AKM_DEFINED if descriptor == DESCRIPTOR_RSN => wpa::mic_cmac(kck, frame),
        _ => wpa::mic(kck, frame),
    }
}

/// A parsed EAPOL-Key frame.
#[derive(Debug, Clone)]
pub struct EapolKey<'a> {
    /// The whole EAPOL PDU (the MIC is computed over this).
    pub frame: &'a [u8],
    /// Descriptor type: 2 (RSN) or 254 (WPA1).
    pub descriptor: u8,
    pub key_info: u16,
    /// Key length field: 16 (CCMP) or 32 (TKIP); meaningful for WPA1.
    pub key_length: u16,
    pub replay: u64,
    pub nonce: [u8; 32],
    /// Key IV — the WPA1 RC4 decryption prefix for encrypted key data.
    pub key_iv: [u8; 16],
    pub mic: [u8; 16],
    /// Raw key data (still wrapped when `key_data_encrypted`).
    pub key_data: &'a [u8],
}

impl<'a> EapolKey<'a> {
    /// Parse an EAPOL-Key frame.
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        if frame.len() < FIXED_LEN || frame[1] != TYPE_EAPOL_KEY {
            return None;
        }
        let descriptor = frame[4];
        if descriptor != DESCRIPTOR_RSN && descriptor != DESCRIPTOR_WPA {
            return None;
        }

        let key_info = u16::from_be_bytes([frame[5], frame[6]]);
        let key_length =
            u16::from_be_bytes([frame[KEY_LENGTH_OFFSET], frame[KEY_LENGTH_OFFSET + 1]]);
        let replay = u64::from_be_bytes(frame[9..17].try_into().ok()?);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&frame[17..49]);
        let mut key_iv = [0u8; 16];
        key_iv.copy_from_slice(&frame[KEY_IV_OFFSET..KEY_IV_OFFSET + 16]);
        let mut mic = [0u8; 16];
        mic.copy_from_slice(&frame[MIC_OFFSET..MIC_OFFSET + 16]);

        let key_data_len = usize::from(u16::from_be_bytes([
            frame[KEY_DATA_LEN_OFFSET],
            frame[KEY_DATA_LEN_OFFSET + 1],
        ]));
        let end = FIXED_LEN.checked_add(key_data_len)?;
        if end > frame.len() {
            return None;
        }

        Some(Self {
            frame,
            descriptor,
            key_info,
            key_length,
            replay,
            nonce,
            key_iv,
            mic,
            key_data: &frame[FIXED_LEN..end],
        })
    }

    /// The key descriptor version (`key_info & 0x7`).
    pub fn descriptor_version(&self) -> u16 {
        self.key_info & KEY_INFO_VERSION_MASK
    }

    /// The group key index (bits 4–5); meaningful for group-key messages.
    pub fn key_index(&self) -> u8 {
        ((self.key_info & KEY_INFO_KEY_INDEX_MASK) >> 4) as u8
    }

    /// True for a pairwise (not group) key message.
    pub fn is_pairwise(&self) -> bool {
        self.key_info & KEY_INFO_PAIRWISE != 0
    }
    pub fn has_mic(&self) -> bool {
        self.key_info & KEY_INFO_MIC != 0
    }
    pub fn is_ack(&self) -> bool {
        self.key_info & KEY_INFO_ACK != 0
    }
    pub fn is_secure(&self) -> bool {
        self.key_info & KEY_INFO_SECURE != 0
    }
    pub fn key_data_encrypted(&self) -> bool {
        self.key_info & KEY_INFO_ENCRYPTED != 0
    }

    /// Which 4-way handshake message this is, from the ACK/MIC/Secure bits.
    pub fn message_number(&self) -> Option<u8> {
        match (self.is_ack(), self.has_mic(), self.is_secure()) {
            (true, false, false) => Some(1),
            (false, true, false) => Some(2),
            (true, true, true) => Some(3),
            (false, true, true) => Some(4),
            _ => None,
        }
    }

    /// The MIC this frame *should* carry, given the KCK.
    pub fn compute_mic(&self, kck: &[u8; 16]) -> [u8; 16] {
        let mut copy = self.frame.to_vec();
        copy[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
        mic_for(self.descriptor, self.key_info, kck, &copy)
    }

    /// Verify the frame's MIC against the KCK.
    pub fn verify_mic(&self, kck: &[u8; 16]) -> bool {
        self.compute_mic(kck) == self.mic
    }
}

/// The variable parts of an EAPOL-Key frame, for [`build_key`].
#[derive(Debug, Clone)]
pub struct EapolKeyFrame<'a> {
    /// Descriptor type: `DESCRIPTOR_RSN` (2) or `DESCRIPTOR_WPA` (254).
    pub descriptor: u8,
    pub key_info: u16,
    /// Key length: 16 for CCMP, 32 for TKIP.
    pub key_length: u16,
    pub replay: u64,
    pub nonce: &'a [u8; 32],
    /// Key IV; also the RC4 prefix for WPA1's encrypted key data.
    pub key_iv: &'a [u8; 16],
    pub key_data: &'a [u8],
}

/// Build an EAPOL-Key frame; when `kck` is given, a MIC is computed and set.
pub fn build_key(params: &EapolKeyFrame<'_>, kck: Option<&[u8; 16]>) -> Vec<u8> {
    let mut frame = vec![0u8; FIXED_LEN];
    frame[0] = EAPOL_VERSION;
    frame[1] = TYPE_EAPOL_KEY;
    frame[2..4].copy_from_slice(&((KEY_BODY_LEN + params.key_data.len()) as u16).to_be_bytes());
    frame[4] = params.descriptor;
    frame[5..7].copy_from_slice(&params.key_info.to_be_bytes());
    frame[KEY_LENGTH_OFFSET..KEY_LENGTH_OFFSET + 2]
        .copy_from_slice(&params.key_length.to_be_bytes());
    frame[9..17].copy_from_slice(&params.replay.to_be_bytes());
    frame[17..49].copy_from_slice(params.nonce);
    frame[KEY_IV_OFFSET..KEY_IV_OFFSET + 16].copy_from_slice(params.key_iv);
    frame[KEY_DATA_LEN_OFFSET..KEY_DATA_LEN_OFFSET + 2]
        .copy_from_slice(&(params.key_data.len() as u16).to_be_bytes());
    frame.extend_from_slice(params.key_data);

    if let Some(kck) = kck {
        let mut payload = frame.clone();
        payload[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
        let digest = mic_for(params.descriptor, params.key_info, kck, &payload);
        frame[MIC_OFFSET..MIC_OFFSET + 16].copy_from_slice(&digest);
    }
    frame
}

/// Build an EAPOL-Key frame with the WPA2 defaults: RSN descriptor, key length
/// 16, zero key IV.
pub fn build(
    key_info: u16,
    replay: u64,
    nonce: &[u8; 32],
    key_data: &[u8],
    kck: Option<&[u8; 16]>,
) -> Vec<u8> {
    build_key(
        &EapolKeyFrame {
            descriptor: DESCRIPTOR_RSN,
            key_info,
            key_length: 16,
            replay,
            nonce,
            key_iv: &[0u8; 16],
            key_data,
        },
        kck,
    )
}

/// Build our message 2/4: SNonce plus the RSN IE, MIC'd with the KCK.
pub fn build_message2(replay: u64, snonce: &[u8; 32], rsn_ie: &[u8], kck: &[u8; 16]) -> Vec<u8> {
    build_message2_with_version(KEY_INFO_VERSION2, replay, snonce, rsn_ie, kck)
}

/// Build our message 2/4 with an explicit descriptor version.
///
/// wpa_supplicant echoes the version of the AP's message 1 (`ver` from the key
/// info); for SAE that is version 0 ("AKM-defined", CMAC MIC).
pub fn build_message2_with_version(
    version: u16,
    replay: u64,
    snonce: &[u8; 32],
    ie: &[u8],
    kck: &[u8; 16],
) -> Vec<u8> {
    build(
        version | KEY_INFO_PAIRWISE | KEY_INFO_MIC,
        replay,
        snonce,
        ie,
        Some(kck),
    )
}

/// Build our message 4/4: an acknowledgement with no key data.
///
/// `nonce` must be the Key Nonce from message 3. wpa_supplicant copies it into
/// 4/4 (`wpa_supplicant_send_4_of_4`: `os_memcpy(reply->key_nonce,
/// key->key_nonce, WPA_NONCE_LEN)`), and an authenticator may compare it; sending
/// an all-zero nonce leaves the handshake stuck at 3/4.
pub fn build_message4(replay: u64, nonce: &[u8; 32], kck: &[u8; 16]) -> Vec<u8> {
    build_message4_with_version(KEY_INFO_VERSION2, replay, nonce, kck)
}

/// Build our message 4/4 with an explicit descriptor version (SAE uses 0).
pub fn build_message4_with_version(
    version: u16,
    replay: u64,
    nonce: &[u8; 32],
    kck: &[u8; 16],
) -> Vec<u8> {
    build(
        version | KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE,
        replay,
        nonce,
        &[],
        Some(kck),
    )
}

/// Build our WPA1 message 2/4: descriptor 254, version 1, WPA IE as key data.
///
/// `key_length` is copied from the AP's message 1 (32 for TKIP), as
/// `wpa_supplicant_send_2_of_4` does for the WPA proto.
pub fn build_message2_wpa1(
    replay: u64,
    snonce: &[u8; 32],
    wpa_ie: &[u8],
    key_length: u16,
    kck: &[u8; 16],
) -> Vec<u8> {
    build_key(
        &EapolKeyFrame {
            descriptor: DESCRIPTOR_WPA,
            key_info: KEY_INFO_VERSION1 | KEY_INFO_PAIRWISE | KEY_INFO_MIC,
            key_length,
            replay,
            nonce: snonce,
            key_iv: &[0u8; 16],
            key_data: wpa_ie,
        },
        Some(kck),
    )
}

/// Build our WPA1 message 4/4.
///
/// wpa_supplicant takes the SECURE bit from the AP's message 3 (hostapd sends
/// WPA1 message 3 with SECURE clear), keeps the key length and echoes the Key
/// Nonce.
pub fn build_message4_wpa1(
    replay: u64,
    nonce: &[u8; 32],
    key_length: u16,
    secure: bool,
    kck: &[u8; 16],
) -> Vec<u8> {
    let mut key_info = KEY_INFO_VERSION1 | KEY_INFO_PAIRWISE | KEY_INFO_MIC;
    if secure {
        key_info |= KEY_INFO_SECURE;
    }
    build_key(
        &EapolKeyFrame {
            descriptor: DESCRIPTOR_WPA,
            key_info,
            key_length,
            replay,
            nonce,
            key_iv: &[0u8; 16],
            key_data: &[],
        },
        Some(kck),
    )
}

/// Build our WPA1 group-key message 2/2 (the reply to 1/2).
///
/// `wpa_supplicant_send_2_of_2` keeps only the key-index bits from the received
/// key info, sets version 1, SECURE and MIC, copies the key length and replay
/// counter, and carries no key data (the nonce stays zero).
pub fn build_group_message2_wpa1(
    received_key_info: u16,
    replay: u64,
    key_length: u16,
    kck: &[u8; 16],
) -> Vec<u8> {
    build_key(
        &EapolKeyFrame {
            descriptor: DESCRIPTOR_WPA,
            key_info: (received_key_info & KEY_INFO_KEY_INDEX_MASK)
                | KEY_INFO_VERSION1
                | KEY_INFO_SECURE
                | KEY_INFO_MIC,
            key_length,
            replay,
            nonce: &[0u8; 32],
            key_iv: &[0u8; 16],
            key_data: &[],
        },
        Some(kck),
    )
}

/// A GTK extracted from message 3's key data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtk {
    pub key_id: u8,
    pub key: Vec<u8>,
}

/// Parse a GTK key-data encapsulation: `dd <len> 00 0f ac 01 <keyid> <rsvd> <gtk>`.
pub fn parse_gtk_kde(data: &[u8]) -> Option<Gtk> {
    let mut cursor = 0;
    while cursor + 2 <= data.len() {
        let element_id = data[cursor];
        let length = usize::from(data[cursor + 1]);
        let body_start = cursor + 2;
        let end = body_start + length;
        if end > data.len() {
            return None;
        }
        let body = &data[body_start..end];
        // 0xdd = vendor-specific; OUI 00:0f:ac with type 1 = GTK.
        if element_id == 0xdd && body.len() >= 6 && body[..4] == [0x00, 0x0f, 0xac, 0x01] {
            let key_id = body[4] & 0x03;
            let key = body[6..].to_vec();
            if !key.is_empty() {
                return Some(Gtk { key_id, key });
            }
        }
        cursor = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const KCK: [u8; 16] = [
        0xbf, 0xcd, 0xca, 0x8b, 0xfa, 0xca, 0x3d, 0xa5, 0x64, 0xca, 0x3c, 0x20, 0x01, 0xc8, 0x80,
        0x9e,
    ];

    #[test]
    fn message2_round_trips_and_verifies() {
        let snonce = [0x11u8; 32];
        let rsn = vec![48u8, 20, 1, 0];
        let frame = build_message2(7, &snonce, &rsn, &KCK);

        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.message_number(), Some(2));
        assert_eq!(parsed.replay, 7);
        assert_eq!(parsed.nonce, snonce);
        assert_eq!(parsed.key_data, rsn.as_slice());
        assert!(parsed.verify_mic(&KCK));
    }

    #[test]
    fn message4_has_no_key_data_and_verifies() {
        let anonce = [0x5au8; 32];
        let frame = build_message4(9, &anonce, &KCK);
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.message_number(), Some(4));
        // 4/4 echoes the Key Nonce from 3/4; an AP may compare it.
        assert_eq!(parsed.nonce, anonce);
        assert!(parsed.key_data.is_empty());
        assert!(parsed.verify_mic(&KCK));
    }

    #[test]
    fn tampering_with_the_mic_is_detected() {
        let mut frame = build_message2(1, &[0u8; 32], &[], &KCK);
        let mut parsed = EapolKey::parse(&frame).unwrap();
        assert!(parsed.verify_mic(&KCK));
        frame[17] ^= 0xff; // change the nonce
        parsed = EapolKey::parse(&frame).unwrap();
        assert!(!parsed.verify_mic(&KCK));
    }

    #[test]
    fn message1_is_recognised() {
        let frame = build(
            KEY_INFO_VERSION2 | KEY_INFO_PAIRWISE | KEY_INFO_ACK,
            3,
            &[0xaa; 32],
            &[],
            None,
        );
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.message_number(), Some(1));
    }

    #[test]
    fn rejects_non_eapol_and_truncated_frames() {
        assert!(EapolKey::parse(&[0u8; 10]).is_none());
        let mut frame = build_message2(1, &[0u8; 32], &[], &KCK);
        frame[1] = 0; // not EAPOL-Key
        assert!(EapolKey::parse(&frame).is_none());
        let mut frame = build_message2(1, &[0u8; 32], &[], &KCK);
        frame[4] = 3; // neither RSN (2) nor WPA (254)
        assert!(EapolKey::parse(&frame).is_none());
    }

    #[test]
    fn wpa1_frame_round_trips_with_md5_mic() {
        let frame = build_key(
            &EapolKeyFrame {
                descriptor: DESCRIPTOR_WPA,
                key_info: KEY_INFO_VERSION1 | KEY_INFO_PAIRWISE | KEY_INFO_MIC,
                key_length: 32, // TKIP
                replay: 5,
                nonce: &[0x22; 32],
                key_iv: &[0x11; 16],
                key_data: &[],
            },
            Some(&KCK),
        );
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.descriptor, DESCRIPTOR_WPA);
        assert_eq!(parsed.descriptor_version(), KEY_INFO_VERSION1);
        assert_eq!(parsed.key_length, 32);
        assert_eq!(parsed.key_iv, [0x11; 16]);
        assert!(parsed.verify_mic(&KCK));

        // Version 1 really selects HMAC-MD5-128.
        let mut payload = parsed.frame.to_vec();
        payload[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
        assert_eq!(wpa::mic_md5(&KCK, &payload), parsed.mic);
    }

    #[test]
    fn sae_frame_uses_cmac_mic() {
        let frame = build_key(
            &EapolKeyFrame {
                descriptor: DESCRIPTOR_RSN,
                key_info: KEY_INFO_VERSION_AKM_DEFINED | KEY_INFO_PAIRWISE | KEY_INFO_MIC,
                key_length: 16,
                replay: 6,
                nonce: &[0x33; 32],
                key_iv: &[0; 16],
                key_data: &[],
            },
            Some(&KCK),
        );
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.descriptor_version(), KEY_INFO_VERSION_AKM_DEFINED);
        assert!(parsed.verify_mic(&KCK));

        // Version 0 ("AKM-defined", SAE) really selects AES-128-CMAC.
        let mut payload = parsed.frame.to_vec();
        payload[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
        assert_eq!(wpa::mic_cmac(&KCK, &payload), parsed.mic);
        assert_ne!(wpa::mic(&KCK, &payload), parsed.mic);
    }

    #[test]
    fn build_wrapper_stays_on_the_wpa2_defaults() {
        let frame = build(
            KEY_INFO_VERSION2 | KEY_INFO_PAIRWISE | KEY_INFO_MIC,
            1,
            &[0u8; 32],
            &[],
            Some(&KCK),
        );
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.descriptor, DESCRIPTOR_RSN);
        assert_eq!(parsed.key_length, 16);
        assert_eq!(parsed.key_iv, [0u8; 16]);
        assert_eq!(parsed.descriptor_version(), KEY_INFO_VERSION2);
    }

    #[test]
    fn parses_a_gtk_kde() {
        // dd 0e 00 0f ac 01 <keyid> 00 <gtk 8 bytes>
        let mut data = vec![0xdd, 0x0e, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00];
        data.extend_from_slice(&[0xaa; 8]);
        let gtk = parse_gtk_kde(&data).unwrap();
        assert_eq!(gtk.key_id, 1);
        assert_eq!(gtk.key, vec![0xaa; 8]);
    }

    #[test]
    fn ignores_key_data_without_a_gtk() {
        assert!(parse_gtk_kde(&[]).is_none());
        assert!(parse_gtk_kde(&[0xdd, 0x04, 0x00, 0x0f, 0xac, 0x04]).is_none());
    }

    #[test]
    fn message2_wpa1_round_trips_with_the_msg1_key_length() {
        let wpa_ie = vec![0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00];
        let frame = build_message2_wpa1(4, &[0x33; 32], &wpa_ie, 32, &KCK);
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.descriptor, DESCRIPTOR_WPA);
        assert_eq!(parsed.descriptor_version(), KEY_INFO_VERSION1);
        assert_eq!(parsed.key_length, 32);
        assert!(parsed.is_pairwise());
        assert!(parsed.has_mic());
        assert!(!parsed.is_secure());
        assert_eq!(parsed.replay, 4);
        assert_eq!(parsed.nonce, [0x33; 32]);
        assert_eq!(parsed.key_data, wpa_ie.as_slice());
        assert!(parsed.verify_mic(&KCK));
    }

    #[test]
    fn message4_wpa1_copies_the_secure_bit_and_key_length() {
        let frame = build_message4_wpa1(7, &[0x44; 32], 32, false, &KCK);
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.descriptor, DESCRIPTOR_WPA);
        assert_eq!(parsed.descriptor_version(), KEY_INFO_VERSION1);
        assert_eq!(parsed.key_length, 32);
        assert!(!parsed.is_secure()); // hostapd sends WPA1 message 3 without SECURE
        assert!(parsed.key_data.is_empty());
        assert!(parsed.verify_mic(&KCK));

        let secure_frame = build_message4_wpa1(7, &[0x44; 32], 32, true, &KCK);
        let secure = EapolKey::parse(&secure_frame).unwrap();
        assert!(secure.is_secure());
    }

    #[test]
    fn group_message2_wpa1_keeps_only_the_key_index() {
        let received = KEY_INFO_VERSION1
            | KEY_INFO_ACK
            | KEY_INFO_MIC
            | KEY_INFO_SECURE
            | KEY_INFO_INSTALL
            | (2 << 4);
        let frame = build_group_message2_wpa1(received, 9, 32, &KCK);
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.descriptor, DESCRIPTOR_WPA);
        assert_eq!(parsed.descriptor_version(), KEY_INFO_VERSION1);
        assert_eq!(parsed.key_index(), 2);
        assert_eq!(
            parsed.key_info,
            KEY_INFO_VERSION1 | KEY_INFO_SECURE | KEY_INFO_MIC | (2 << 4)
        );
        assert!(!parsed.is_pairwise());
        assert!(!parsed.is_ack());
        assert_eq!(parsed.replay, 9);
        assert_eq!(parsed.key_length, 32);
        assert_eq!(parsed.nonce, [0u8; 32]);
        assert!(parsed.key_data.is_empty());
        assert!(parsed.verify_mic(&KCK));
    }

    #[test]
    fn message2_with_version_selects_the_sae_mic() {
        let frame =
            build_message2_with_version(KEY_INFO_VERSION_AKM_DEFINED, 1, &[0x55; 32], &[], &KCK);
        let parsed = EapolKey::parse(&frame).unwrap();
        assert_eq!(parsed.descriptor_version(), KEY_INFO_VERSION_AKM_DEFINED);
        let mut payload = parsed.frame.to_vec();
        payload[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
        assert_eq!(wpa::mic_cmac(&KCK, &payload), parsed.mic);
    }

    #[test]
    fn key_index_reads_bits_4_and_5() {
        let frame = build(
            KEY_INFO_VERSION2 | KEY_INFO_PAIRWISE | KEY_INFO_ACK | (3 << 4),
            1,
            &[0u8; 32],
            &[],
            None,
        );
        assert_eq!(EapolKey::parse(&frame).unwrap().key_index(), 3);
    }
}
