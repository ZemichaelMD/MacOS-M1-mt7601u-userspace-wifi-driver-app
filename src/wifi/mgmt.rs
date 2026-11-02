//! 802.11 management frame parsing for the association state machine.
//!
//! mac80211 is not available here, so the authentication and association
//! responses that mac80211's MLME would normally decode are parsed directly.
//! Only the fixed fields needed by the open-system station state machine are
//! decoded; the information elements are left to the caller.

/// `WLAN_STATUS_SUCCESS`.
pub const STATUS_SUCCESS: u16 = 0;
/// `WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ`: the SAE commit must be replayed with
/// the token appended.
pub const STATUS_ANTI_CLOGGING_TOKEN_REQ: u16 = 76;
/// `WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED`.
pub const STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED: u16 = 77;

/// Open-system authentication algorithm number.
pub const AUTH_ALG_OPEN: u16 = 0;
/// SAE authentication algorithm number.
pub const AUTH_ALG_SAE: u16 = 3;
/// SAE commit transaction sequence (and the token retry, which is the same
/// commit message).
pub const AUTH_SEQ_SAE_COMMIT: u16 = 1;
/// SAE confirm transaction sequence.
pub const AUTH_SEQ_SAE_CONFIRM: u16 = 2;
/// Authentication transaction sequence of the response to our request
/// (request = 1, response = 2).
pub const AUTH_SEQ_RESPONSE: u16 = 2;

/// Management subtype numbers (`IEEE80211_FTYPE_MGMT`).
const SUBTYPE_ASSOC_RESPONSE: u8 = 1;
const SUBTYPE_AUTH: u8 = 11;

/// `MT_RXWI`-independent management frame type check: returns the subtype for a
/// management frame (type 0), or `None` for any other type.
fn management_subtype(frame: &[u8]) -> Option<u8> {
    if frame.len() < 2 {
        return None;
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    if (frame_control >> 2) & 0x3 != 0 {
        return None;
    }
    Some(((frame_control >> 4) & 0xf) as u8)
}

/// The destination, source and BSSID of a management frame (24-byte header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addrs {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub bssid: [u8; 6],
}

/// Decode the three addresses of a management frame.
pub fn addresses(frame: &[u8]) -> Option<Addrs> {
    if frame.len() < 24 {
        return None;
    }
    let mut destination = [0u8; 6];
    let mut source = [0u8; 6];
    let mut bssid = [0u8; 6];
    destination.copy_from_slice(&frame[4..10]);
    source.copy_from_slice(&frame[10..16]);
    bssid.copy_from_slice(&frame[16..22]);
    Some(Addrs {
        destination,
        source,
        bssid,
    })
}

/// Open-system authentication response fixed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthResponse {
    pub algorithm: u16,
    pub sequence: u16,
    pub status: u16,
}

impl AuthResponse {
    pub fn is_success(&self) -> bool {
        self.status == STATUS_SUCCESS
    }
}

/// Parse an authentication frame (subtype 11).
pub fn parse_auth(frame: &[u8]) -> Option<AuthResponse> {
    if management_subtype(frame)? != SUBTYPE_AUTH || frame.len() < 30 {
        return None;
    }
    Some(AuthResponse {
        algorithm: u16::from_le_bytes([frame[24], frame[25]]),
        sequence: u16::from_le_bytes([frame[26], frame[27]]),
        status: u16::from_le_bytes([frame[28], frame[29]]),
    })
}

/// An authentication frame with its variable-length body.
///
/// SAE carries its commit, anti-clogging token and confirm in the body after
/// the three fixed fields; [`AuthResponse`] only decodes the fixed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFrame<'a> {
    pub algorithm: u16,
    pub sequence: u16,
    pub status: u16,
    pub body: &'a [u8],
}

/// Like [`parse_auth`], but also returning the body bytes after the status.
pub fn parse_auth_body(frame: &[u8]) -> Option<AuthFrame<'_>> {
    let response = parse_auth(frame)?;
    Some(AuthFrame {
        algorithm: response.algorithm,
        sequence: response.sequence,
        status: response.status,
        body: &frame[30..],
    })
}

/// Association response fixed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssocResponse {
    pub capability: u16,
    pub status: u16,
    /// Association id (low 14 bits of the AID field).
    pub aid: u16,
}

impl AssocResponse {
    pub fn is_success(&self) -> bool {
        self.status == STATUS_SUCCESS
    }
}

/// Parse an association response (subtype 1).
pub fn parse_assoc_response(frame: &[u8]) -> Option<AssocResponse> {
    if management_subtype(frame)? != SUBTYPE_ASSOC_RESPONSE || frame.len() < 30 {
        return None;
    }
    let aid = u16::from_le_bytes([frame[28], frame[29]]) & 0x3fff;
    Some(AssocResponse {
        capability: u16::from_le_bytes([frame[24], frame[25]]),
        status: u16::from_le_bytes([frame[26], frame[27]]),
        aid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgmt(subtype: u8, body: &[u8]) -> Vec<u8> {
        let frame_control = u16::from(subtype) << 4;
        let mut frame = vec![0u8; 24];
        frame[0..2].copy_from_slice(&frame_control.to_le_bytes());
        frame[4..10].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame[10..16].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        frame[16..22].copy_from_slice(&[0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01]);
        frame.extend_from_slice(body);
        frame
    }

    #[test]
    fn parses_a_successful_auth_response() {
        let frame = mgmt(SUBTYPE_AUTH, &[0, 0, 2, 0, 0, 0]);
        let response = parse_auth(&frame).expect("auth parsed");
        assert_eq!(response.algorithm, AUTH_ALG_OPEN);
        assert_eq!(response.sequence, AUTH_SEQ_RESPONSE);
        assert!(response.is_success());
    }

    #[test]
    fn auth_failure_status_is_reported() {
        // Status 1: unspecified failure.
        let frame = mgmt(SUBTYPE_AUTH, &[0, 0, 2, 0, 1, 0]);
        let response = parse_auth(&frame).unwrap();
        assert!(!response.is_success());
        assert_eq!(response.status, 1);
    }

    #[test]
    fn auth_body_carries_the_sae_commit() {
        let mut body = vec![3, 0, 1, 0, 0, 0];
        body.extend_from_slice(&[0xab; 98]);
        let frame = mgmt(SUBTYPE_AUTH, &body);
        let parsed = parse_auth_body(&frame).expect("SAE auth parsed");
        assert_eq!(parsed.algorithm, AUTH_ALG_SAE);
        assert_eq!(parsed.sequence, AUTH_SEQ_SAE_COMMIT);
        assert!(parsed.status == STATUS_SUCCESS);
        assert_eq!(parsed.body.len(), 98);
    }

    #[test]
    fn auth_body_carries_the_anti_clogging_token() {
        let frame = mgmt(SUBTYPE_AUTH, &[3, 0, 1, 0, 76, 0, 0x13]);
        let parsed = parse_auth_body(&frame).unwrap();
        assert_eq!(parsed.status, STATUS_ANTI_CLOGGING_TOKEN_REQ);
        assert_eq!(parsed.body, &[0x13]);
    }

    #[test]
    fn parses_an_assoc_response_and_masks_the_aid() {
        // Capability ESS, status 0, AID 0xc001 (the two high bits are ignored).
        let frame = mgmt(
            SUBTYPE_ASSOC_RESPONSE,
            &[0x01, 0x00, 0x00, 0x00, 0x01, 0xc0],
        );
        let response = parse_assoc_response(&frame).unwrap();
        assert_eq!(response.capability, 0x0001);
        assert!(response.is_success());
        assert_eq!(response.aid, 0x0001);
    }

    #[test]
    fn rejects_the_wrong_subtype() {
        let beacon = mgmt(8, &[0; 12]);
        assert!(parse_auth(&beacon).is_none());
        assert!(parse_assoc_response(&beacon).is_none());
    }

    #[test]
    fn rejects_short_and_non_management_frames() {
        assert!(parse_auth(&[0x00, 0x00]).is_none());
        let mut data = mgmt(SUBTYPE_AUTH, &[0; 6]);
        data[0] = 0x08; // data frame
        assert!(parse_auth(&data).is_none());
    }

    #[test]
    fn decodes_management_addresses() {
        let frame = mgmt(SUBTYPE_AUTH, &[0; 6]);
        let addrs = addresses(&frame).unwrap();
        assert_eq!(addrs.destination, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(addrs.source, [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        assert_eq!(addrs.bssid, [0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01]);
    }
}
