//! RSN (Robust Security Network) information element — the WPA2 IE
//! (IEEE 802.11i §8.4.2.27).
//!
//! A WPA2-only AP rejects an association request that does not carry an RSN IE,
//! so this is required before the 4-way handshake can even begin.

/// Information element id for RSN.
pub const IE_ID_RSN: u8 = 48;
/// Information element id for vendor-specific elements (WPA1 lives here).
pub const IE_ID_VENDOR_SPECIFIC: u8 = 221;
/// The IEEE 802.11 OUI used for RSN cipher/AKM suites.
pub const OUI_80211: [u8; 3] = [0x00, 0x0f, 0xac];
/// The Microsoft OUI used for WPA1 (vendor-specific) cipher/AKM suites.
pub const OUI_WPA: [u8; 3] = [0x00, 0x50, 0xf2];
/// The vendor-specific OUI type of the WPA1 IE.
pub const WPA1_OUI_TYPE: u8 = 1;
/// Cipher suite: AES-CCMP.
pub const SUITE_CCMP: u8 = 4;
/// Cipher suite: TKIP (2 in both RSN and WPA1 selectors; 5 would be WEP104).
pub const SUITE_TKIP: u8 = 2;
/// AKM suite: PSK.
pub const SUITE_PSK: u8 = 2;
/// AKM suite: SAE (WPA3-Personal).
pub const SUITE_SAE: u8 = 8;

/// The RSN IE we advertise for WPA2-PSK with CCMP.
pub fn build_psk_ccmp() -> Vec<u8> {
    rsn_ie(SUITE_PSK, SUITE_CCMP, 0x0000)
}

/// The RSN IE we advertise for WPA3 SAE with CCMP.
///
/// RSN capabilities advertise MFPC | MFPR (management-frame protection
/// capable/required, 0x00c0); the driver does not actually implement 802.11w,
/// but SAE APs commonly require these bits in the association request.
pub fn build_sae_ccmp() -> Vec<u8> {
    rsn_ie(SUITE_SAE, SUITE_CCMP, 0x00c0)
}

/// Build an RSN IE from one AKM suite, one pairwise cipher and capability bits.
fn rsn_ie(akm: u8, cipher: u8, capabilities: u16) -> Vec<u8> {
    let mut ie = Vec::with_capacity(22);
    ie.push(IE_ID_RSN);
    ie.push(20); // body length
    ie.extend_from_slice(&1u16.to_le_bytes()); // version 1
    ie.extend_from_slice(&OUI_80211);
    ie.push(cipher); // group cipher
    ie.extend_from_slice(&1u16.to_le_bytes()); // pairwise count
    ie.extend_from_slice(&OUI_80211);
    ie.push(cipher);
    ie.extend_from_slice(&1u16.to_le_bytes()); // AKM count
    ie.extend_from_slice(&OUI_80211);
    ie.push(akm);
    ie.extend_from_slice(&capabilities.to_le_bytes()); // RSN capabilities
    ie
}

/// The WPA1 vendor IE we advertise for WPA-PSK with TKIP.
///
/// `dd 16 00 50 f2 01 | 01 00 | 00 50 f2 02 | 01 00 | 00 50 f2 02 |
/// 01 00 | 00 50 f2 02`: vendor OUI + type, version 1, group cipher TKIP, one
/// pairwise cipher TKIP, one AKM PSK. WPA1 has no capability field.
pub fn build_wpa1_psk_tkip() -> Vec<u8> {
    let mut ie = Vec::with_capacity(24);
    ie.push(IE_ID_VENDOR_SPECIFIC);
    ie.push(22); // body length
    ie.extend_from_slice(&OUI_WPA);
    ie.push(WPA1_OUI_TYPE);
    ie.extend_from_slice(&1u16.to_le_bytes()); // version 1
    ie.extend_from_slice(&OUI_WPA);
    ie.push(SUITE_TKIP); // group cipher
    ie.extend_from_slice(&1u16.to_le_bytes()); // pairwise count
    ie.extend_from_slice(&OUI_WPA);
    ie.push(SUITE_TKIP);
    ie.extend_from_slice(&1u16.to_le_bytes()); // AKM count
    ie.extend_from_slice(&OUI_WPA);
    ie.push(SUITE_PSK);
    ie
}

/// What an AP's RSN IE advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsnInfo {
    pub group_cipher: u8,
    pub pairwise: Vec<u8>,
    pub akm: Vec<u8>,
    pub capabilities: u16,
}

impl RsnInfo {
    /// True when PSK authentication with CCMP is on offer.
    pub fn supports_psk_ccmp(&self) -> bool {
        self.pairwise.contains(&SUITE_CCMP) && self.akm.contains(&SUITE_PSK)
    }

    /// True when SAE authentication with CCMP is on offer (WPA3).
    pub fn supports_sae_ccmp(&self) -> bool {
        self.pairwise.contains(&SUITE_CCMP) && self.akm.contains(&SUITE_SAE)
    }

    /// True when the AP requires pre-authentication (unsupported).
    pub fn requires_preauthentication(&self) -> bool {
        self.capabilities & 0x0004 != 0
    }
}

/// Parse an RSN IE, starting at the element id byte.
pub fn parse(ie: &[u8]) -> Option<RsnInfo> {
    if ie.len() < 2 || ie[0] != IE_ID_RSN {
        return None;
    }
    let length = usize::from(ie[1]);
    let body = ie.get(2..2 + length)?;
    parse_body(body, OUI_80211)
}

/// Parse a WPA1 vendor-specific IE, starting at the element id byte.
///
/// The layout matches the RSN IE, except that a 4-byte OUI + type
/// (`00 50 f2 01`) replaces nothing but itself: the fields after the length
/// byte are the WPA OUI/type, then version, group cipher, pairwise list and
/// AKM list, with every suite selector prefixed by the WPA OUI.
pub fn parse_wpa1(ie: &[u8]) -> Option<RsnInfo> {
    if ie.len() < 6 || ie[0] != IE_ID_VENDOR_SPECIFIC || ie[5] != WPA1_OUI_TYPE {
        return None;
    }
    if ie[2..5] != OUI_WPA {
        return None;
    }
    let length = usize::from(ie[1]);
    let body = ie.get(6..2 + length)?;
    parse_body(body, OUI_WPA)
}

/// Parse the shared RSN/WPA1 body layout (version, group cipher, pairwise and
/// AKM suite lists, optional capabilities).
fn parse_body(body: &[u8], oui: [u8; 3]) -> Option<RsnInfo> {
    if body.len() < 6 {
        return None;
    }

    let group_cipher = *body.get(5)?;
    let mut cursor = 6;

    let pairwise_count = usize::from(u16::from_le_bytes([
        *body.get(cursor)?,
        *body.get(cursor + 1)?,
    ]));
    cursor += 2;
    let mut pairwise = Vec::with_capacity(pairwise_count);
    for _ in 0..pairwise_count {
        let suite = body.get(cursor..cursor + 4)?;
        if suite[..3] != oui {
            return None;
        }
        pairwise.push(suite[3]);
        cursor += 4;
    }

    let akm_count = usize::from(u16::from_le_bytes([
        *body.get(cursor)?,
        *body.get(cursor + 1)?,
    ]));
    cursor += 2;
    let mut akm = Vec::with_capacity(akm_count);
    for _ in 0..akm_count {
        let suite = body.get(cursor..cursor + 4)?;
        if suite[..3] != oui {
            return None;
        }
        akm.push(suite[3]);
        cursor += 4;
    }

    let capabilities = if cursor + 2 <= body.len() {
        u16::from_le_bytes([body[cursor], body[cursor + 1]])
    } else {
        0
    };

    Some(RsnInfo {
        group_cipher,
        pairwise,
        akm,
        capabilities,
    })
}

/// Find information element `id` in an IE list starting at `start`.
///
/// Returns the element slice beginning at its id byte. The first match wins,
/// which also guards against the zero padding at the end of a receive segment.
pub fn find_ie(payload: &[u8], start: usize, id: u8) -> Option<&[u8]> {
    let mut cursor = start;
    while cursor + 2 <= payload.len() {
        let element_id = payload[cursor];
        let length = usize::from(payload[cursor + 1]);
        let end = cursor + 2 + length;
        if end > payload.len() {
            break;
        }
        if element_id == id {
            return Some(&payload[cursor..end]);
        }
        cursor = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_round_trips_psk_ccmp() {
        let ie = build_psk_ccmp();
        assert_eq!(ie.len(), 22);
        assert_eq!(ie[0], IE_ID_RSN);
        assert_eq!(ie[1], 20);
        let parsed = parse(&ie).unwrap();
        assert_eq!(parsed.group_cipher, SUITE_CCMP);
        assert_eq!(parsed.pairwise, vec![SUITE_CCMP]);
        assert_eq!(parsed.akm, vec![SUITE_PSK]);
        assert!(parsed.supports_psk_ccmp());
        assert!(!parsed.requires_preauthentication());
    }

    #[test]
    fn rejects_a_non_rsn_element() {
        assert!(parse(&[0, 4, 1, 2, 3, 4]).is_none());
        assert!(parse(&[IE_ID_RSN]).is_none());
    }

    #[test]
    fn finds_the_rsn_ie_after_other_elements() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0, 4, b't', b'e', b's', b't']); // SSID
        payload.extend_from_slice(&[3, 1, 6]); // channel
        payload.extend_from_slice(&build_psk_ccmp());
        let found = find_ie(&payload, 0, IE_ID_RSN).expect("RSN IE");
        assert!(parse(found).unwrap().supports_psk_ccmp());
    }

    #[test]
    fn find_stops_at_truncated_elements() {
        let payload = [0u8, 200, 1, 2];
        assert!(find_ie(&payload, 0, IE_ID_RSN).is_none());
    }

    #[test]
    fn build_sae_round_trips_sae_ccmp() {
        let ie = build_sae_ccmp();
        assert_eq!(ie.len(), 22);
        let parsed = parse(&ie).unwrap();
        assert_eq!(parsed.group_cipher, SUITE_CCMP);
        assert_eq!(parsed.pairwise, vec![SUITE_CCMP]);
        assert_eq!(parsed.akm, vec![SUITE_SAE]);
        assert_eq!(parsed.capabilities, 0x00c0); // MFPC | MFPR
        assert!(parsed.supports_sae_ccmp());
        assert!(!parsed.supports_psk_ccmp());
    }

    #[test]
    fn build_wpa1_matches_the_reference_ie() {
        // Byte-exact WPA1 PSK/TKIP IE (hostap `wpa_ie.c` layout).
        let ie = build_wpa1_psk_tkip();
        assert_eq!(
            ie,
            [
                0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00,
                0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02,
            ]
        );
        let parsed = parse_wpa1(&ie).unwrap();
        assert_eq!(parsed.group_cipher, SUITE_TKIP);
        assert_eq!(parsed.pairwise, vec![SUITE_TKIP]);
        assert_eq!(parsed.akm, vec![SUITE_PSK]);
        assert_eq!(parsed.capabilities, 0);
    }

    #[test]
    fn parse_wpa1_rejects_other_vendor_elements() {
        // Right OUI, wrong OUI type.
        let mut ie = build_wpa1_psk_tkip();
        ie[5] = 2;
        assert!(parse_wpa1(&ie).is_none());
        // Wrong OUI (Intel).
        let mut ie = build_wpa1_psk_tkip();
        ie[2..5].copy_from_slice(&[0x00, 0x17, 0xf2]);
        assert!(parse_wpa1(&ie).is_none());
        // Not a vendor element at all.
        assert!(parse_wpa1(&build_psk_ccmp()).is_none());
    }

    #[test]
    fn parse_and_parse_wpa1_are_disjoint() {
        let ie = build_wpa1_psk_tkip();
        assert!(parse(&ie).is_none());
        assert!(parse_wpa1(&build_psk_ccmp()).is_none());
    }
}
