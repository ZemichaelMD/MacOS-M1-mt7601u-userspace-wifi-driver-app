//! SAE (WPA3) with group 19 (NIST P-256): PWE derivation, the commit/confirm
//! exchange and the KCK/PMK/PMKID derivation.
//!
//! Everything here happens in software (the MT7601U has no SAE offload). The
//! wire format of a commit body is `group (LE16) || scalar (BE32) || x (BE32) ||
//! y (BE32)`, and of a confirm body `send-confirm (LE16) || confirm (32)`. The
//! derivation follows hostap's `sae_derive_pwe_ecc`, `sae_derive_commit`,
//! `sae_derive_k_ecc`, `sae_derive_keys` and `sae_cn_confirm` (hunting-and-
//! pecking, no hash-to-element), and the values are checked against
//! `scripts/gen-crypto-vectors.py`, an independent Python implementation.

use std::fmt;

use hmac::{Hmac, Mac};
use p256::elliptic_curve::point::DecompressPoint;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::subtle::Choice;
use p256::elliptic_curve::{Group, PrimeField};
use p256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::Sha256;

use super::wpa;

type HmacSha256 = Hmac<Sha256>;

/// The only SAE group this driver implements: 19 (NIST P-256).
pub const GROUP: u16 = 19;
/// Length of a commit body: group + scalar + the two coordinates.
pub const COMMIT_LEN: usize = 2 + 32 + 64;
/// Length of a confirm body: send-confirm + the HMAC.
pub const CONFIRM_LEN: usize = 2 + 32;
/// SAE KCK length (SHA-256 output).
pub const KCK_LEN: usize = 32;
/// PMK length (the second SHA-256-PRF block of "SAE KCK and PMK").
pub const PMK_LEN: usize = 32;
/// PMKID length (IEEE 802.11 uses the first 128 bits of the scalar sum).
pub const PMKID_LEN: usize = 16;

/// P-256's field prime, big-endian (the `p` of `y² = x³ - 3x + b (mod p)`).
const PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
/// How many hunting-and-pecking iterations the standard allows.
const MAX_PWE_ITERATIONS: u8 = 200;

/// Why an SAE exchange could not proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaeError {
    /// No counter yielded a valid PWE (a wrong or malformed password).
    Pwe,
    /// A scalar was zero, one or not below the group order.
    Scalar,
    /// The commit body was malformed, for another group, or off-curve.
    Commit,
    /// The peer echoed our own commit back (a reflection attack).
    Reflection,
    /// The shared point came out as the identity (a degenerate exchange).
    SharedPoint,
}

impl fmt::Display for SaeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SaeError::Pwe => write!(f, "the password yielded no valid PWE"),
            SaeError::Scalar => write!(f, "invalid SAE scalar"),
            SaeError::Commit => write!(f, "invalid SAE commit"),
            SaeError::Reflection => write!(f, "SAE commit reflected back"),
            SaeError::SharedPoint => write!(f, "SAE shared point is the identity"),
        }
    }
}

impl std::error::Error for SaeError {}

/// Decode a 32-byte big-endian scalar, rejecting zero, one and anything at or
/// above the group order — `sae_parse_commit_scalar`'s range checks.
fn decode_scalar(bytes: &[u8]) -> Option<Scalar> {
    let array: [u8; 32] = bytes.try_into().ok()?;
    let scalar = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::clone_from_slice(&array)))?;
    if scalar == Scalar::ZERO || scalar == Scalar::ONE {
        None
    } else {
        Some(scalar)
    }
}

/// Derive the PWE with hunting-and-pecking (`sae_derive_pwe_ecc`, the
/// non-hash-to-element method).
///
/// `pwd-seed = HMAC-SHA256(MAX(addr)‖MIN(addr), password‖counter)` and
/// `pwd-value = SHA256-PRF(pwd-seed, "SAE Hunting and Pecking", p)`. The first
/// in-range x that lies on the curve wins, with the y sign taken from the LSB
/// of pwd-seed.
pub fn derive_pwe(
    password: &[u8],
    own_mac: &[u8; 6],
    peer_mac: &[u8; 6],
) -> Result<AffinePoint, SaeError> {
    let mut key = [0u8; 12];
    if own_mac > peer_mac {
        key[..6].copy_from_slice(own_mac);
        key[6..].copy_from_slice(peer_mac);
    } else {
        key[..6].copy_from_slice(peer_mac);
        key[6..].copy_from_slice(own_mac);
    }

    for counter in 1..=MAX_PWE_ITERATIONS {
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(password);
        mac.update(&[counter]);
        let pwd_seed: [u8; 32] = mac.finalize().into_bytes().into();

        let mut pwd_value = [0u8; 32];
        wpa::sha256_prf(
            &pwd_seed,
            b"SAE Hunting and Pecking",
            &PRIME,
            &mut pwd_value,
        );
        // The algorithm only accepts an x below the field prime.
        if pwd_value >= PRIME {
            continue;
        }

        let x = FieldBytes::clone_from_slice(&pwd_value);
        let y_is_odd = Choice::from(pwd_seed[31] & 1);
        if let Some(point) = Option::<AffinePoint>::from(AffinePoint::decompress(&x, y_is_odd)) {
            return Ok(point);
        }
    }
    Err(SaeError::Pwe)
}

/// One side of an SAE commit/confirm exchange, fixed to group 19.
///
/// The two random scalars come from the caller (the station's `/dev/urandom`
/// helper) so the flow stays deterministic in tests.
#[derive(Debug)]
pub struct SaeExchange {
    pwe: AffinePoint,
    rand: Scalar,
    own_scalar: Scalar,
    own_element: AffinePoint,
    peer_scalar: Option<Scalar>,
    peer_element: Option<AffinePoint>,
    keys: Option<([u8; KCK_LEN], [u8; PMK_LEN], [u8; PMKID_LEN])>,
}

impl SaeExchange {
    /// Derive the PWE and build our commit from `rand` and `mask`
    /// (`sae_derive_commit`: `scalar = rand + mask`, `element = -(mask · PWE)`).
    ///
    /// The scalars must be in [2, r-1]; the probability that random bytes fail
    /// that check is negligible, and the caller can simply draw again.
    pub fn new(
        password: &[u8],
        own_mac: [u8; 6],
        peer_mac: [u8; 6],
        rand: [u8; 32],
        mask: [u8; 32],
    ) -> Result<Self, SaeError> {
        let pwe = derive_pwe(password, &own_mac, &peer_mac)?;
        let rand = decode_scalar(&rand).ok_or(SaeError::Scalar)?;
        let mask = decode_scalar(&mask).ok_or(SaeError::Scalar)?;
        let own_scalar = rand + mask;
        if own_scalar == Scalar::ZERO || own_scalar == Scalar::ONE {
            return Err(SaeError::Scalar);
        }
        let own_element = AffinePoint::from(-(ProjectivePoint::from(pwe) * mask));
        Ok(Self {
            pwe,
            rand,
            own_scalar,
            own_element,
            peer_scalar: None,
            peer_element: None,
            keys: None,
        })
    }

    /// Our commit body: `group ‖ scalar ‖ x ‖ y`.
    pub fn commit_body(&self) -> [u8; COMMIT_LEN] {
        let mut body = [0u8; COMMIT_LEN];
        body[..2].copy_from_slice(&GROUP.to_le_bytes());
        body[2..34].copy_from_slice(&self.own_scalar.to_bytes());
        let element = self.own_element.to_encoded_point(false);
        let element = element.as_bytes();
        body[34..66].copy_from_slice(&element[1..33]);
        body[66..98].copy_from_slice(&element[33..65]);
        body
    }

    /// Process the peer's commit: validate it and derive k, KCK, PMK and PMKID
    /// (`sae_parse_commit` + `sae_derive_k_ecc` + `sae_derive_keys`).
    pub fn process_commit(&mut self, body: &[u8]) -> Result<(), SaeError> {
        if body.len() < COMMIT_LEN {
            return Err(SaeError::Commit);
        }
        if u16::from_le_bytes([body[0], body[1]]) != GROUP {
            return Err(SaeError::Commit);
        }
        let peer_scalar = decode_scalar(&body[2..34]).ok_or(SaeError::Scalar)?;

        let mut element = [0u8; 65];
        element[0] = 0x04;
        element[1..].copy_from_slice(&body[34..98]);
        let element = EncodedPoint::from_bytes(element).map_err(|_| SaeError::Commit)?;
        let peer_element = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&element))
            .ok_or(SaeError::Commit)?;

        // A peer that echoes our commit is reflecting our own frame back: drop
        // it silently (the shared point would be useless anyway).
        if peer_scalar == self.own_scalar || element == self.own_element.to_encoded_point(false) {
            return Err(SaeError::Reflection);
        }

        // K = rand · (peer_scalar · PWE + PEER-ELEMENT); k = x(K). The identity
        // is rejected, as in `sae_derive_k_ecc`.
        let shared = (ProjectivePoint::from(self.pwe) * peer_scalar
            + ProjectivePoint::from(peer_element))
            * self.rand;
        if bool::from(shared.is_identity()) {
            return Err(SaeError::SharedPoint);
        }
        let shared = AffinePoint::from(shared).to_encoded_point(false);

        // keyseed = HMAC-SHA256(zeros, k); KCK ‖ PMK = SHA256-PRF(keyseed,
        // "SAE KCK and PMK", (own + peer) mod r); PMKID = val[..16].
        let mut mac = HmacSha256::new_from_slice(&[0u8; 32]).expect("HMAC accepts any key length");
        mac.update(&shared.as_bytes()[1..33]);
        let keyseed: [u8; 32] = mac.finalize().into_bytes().into();

        let val = (self.own_scalar + peer_scalar).to_bytes();
        let mut keys = [0u8; KCK_LEN + PMK_LEN];
        wpa::sha256_prf(&keyseed, b"SAE KCK and PMK", &val, &mut keys);

        let mut kck = [0u8; KCK_LEN];
        kck.copy_from_slice(&keys[..KCK_LEN]);
        let mut pmk = [0u8; PMK_LEN];
        pmk.copy_from_slice(&keys[KCK_LEN..]);
        let mut pmkid = [0u8; PMKID_LEN];
        pmkid.copy_from_slice(&val[..PMKID_LEN]);

        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);
        self.keys = Some((kck, pmk, pmkid));
        Ok(())
    }

    /// The confirm body to send: `send-confirm = 1` and
    /// `confirm = CN(KCK, 1, own-scalar, own-element, peer-scalar, peer-element)`.
    ///
    /// Only valid once the peer's commit has been processed.
    pub fn confirm_body(&self) -> Result<[u8; CONFIRM_LEN], SaeError> {
        let (kck, _, _) = self.keys.ok_or(SaeError::Commit)?;
        let peer_scalar = self.peer_scalar.as_ref().ok_or(SaeError::Commit)?;
        let peer_element = self.peer_element.as_ref().ok_or(SaeError::Commit)?;
        let confirm = cn(
            &kck,
            &1u16.to_le_bytes(),
            &self.own_scalar,
            &self.own_element,
            peer_scalar,
            peer_element,
        );
        let mut body = [0u8; CONFIRM_LEN];
        body[..2].copy_from_slice(&1u16.to_le_bytes());
        body[2..].copy_from_slice(&confirm);
        Ok(body)
    }

    /// Verify the peer's confirm (`sae_check_confirm`): the received
    /// send-confirm is part of the HMAC, with the scalar/element arguments in
    /// the peer's order.
    pub fn verify_confirm(&self, body: &[u8]) -> bool {
        let (Some((kck, _, _)), Some(peer_scalar), Some(peer_element)) = (
            self.keys,
            self.peer_scalar.as_ref(),
            self.peer_element.as_ref(),
        ) else {
            return false;
        };
        if body.len() < CONFIRM_LEN {
            return false;
        }
        let expected = cn(
            &kck,
            &body[..2],
            peer_scalar,
            peer_element,
            &self.own_scalar,
            &self.own_element,
        );
        body[2..CONFIRM_LEN] == expected
    }

    /// The PMK for the 4-way handshake, once the peer's commit was processed.
    pub fn pmk(&self) -> Option<[u8; PMK_LEN]> {
        self.keys.map(|(_, pmk, _)| pmk)
    }

    /// The PMKID, for the RSN IE (once the peer's commit was processed).
    pub fn pmkid(&self) -> Option<[u8; PMKID_LEN]> {
        self.keys.map(|(_, _, pmkid)| pmkid)
    }
}

/// `CN(key, X, Y, Z, ...) = HMAC-SHA256(key, D2OS(X) ‖ D2OS(Y) ‖ …)` over the
/// send-confirm and the two scalar/element pairs (`sae_cn_confirm_ecc`).
fn cn(
    kck: &[u8; KCK_LEN],
    send_confirm: &[u8],
    scalar1: &Scalar,
    element1: &AffinePoint,
    scalar2: &Scalar,
    element2: &AffinePoint,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(kck).expect("HMAC accepts any key length");
    mac.update(send_confirm);
    mac.update(&scalar1.to_bytes());
    // D2OS of a point is x ‖ y; the SEC1 0x04 tag is not part of it.
    mac.update(&element1.to_encoded_point(false).as_bytes()[1..]);
    mac.update(&scalar2.to_bytes());
    mac.update(&element2.to_encoded_point(false).as_bytes()[1..]);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const PEER: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const PASSWORD: &[u8] = b"12345678";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn unhex32(text: &str) -> [u8; 32] {
        hex(text).try_into().unwrap()
    }

    /// The reference exchange from `scripts/gen-crypto-vectors.py` (section 5).
    const PWE_X: &str = "d455adad562cccfa09cd26016ca9287a1b0000c2338d5fac2a8abb0b75b39f1c";
    const PWE_Y: &str = "07d13debbccd531aaaa1753ab1e47a137939ebc7b7b17e2574a40cf44132f815";
    const COMMIT_A: &str = concat!(
        "130033557799bbde0022446688aaccedff1133557799bbde0022446688aaccedff11",
        "ce662c18e8baf76e9d6a4542a6512f9b316d85d1632bf4ca9abbe1bfd8964d1086",
        "2a5e0e73abe8a108f671db95280f989d309b29d0f02f2368cd21ec4aeed9f4",
    );
    const COMMIT_B: &str = concat!(
        "13007799bbde0022446688aaccedff1133557799bbde0022446688aaccedff113355",
        "2e4cc505b20800344578cf8c0aeeba903ca5a3477a19eab7ac741d5b2f70e3bdbe",
        "d361bdac6f22aa84a8863f34b1b52625740e4231381e106ac6394dcbf8fbaf",
    );
    const KCK: &str = "f96c81c83d11259d637ee2dc83a08f066e7caa37890f115a4b329a459f3d5ebb";
    const PMK: &str = "e6639d987e33ba2d595a9af23f3432b894e252598f2433788296c4204a80b39f";
    const PMKID: &str = "aaef3377bc004488cd115598cbff3266";
    const CONFIRM_A: &str = "a1ece670198866159b921c1761b6ff865744901ff677918cf66ad9ae6ef04bbb";
    const CONFIRM_B: &str = "86a5120e3bad6cde585baeb8295529cb21e1076857c44107d7ad1e9c6a834043";

    const RAND_A: &str = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";
    const MASK_A: &str = "2233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011";

    fn exchange() -> SaeExchange {
        SaeExchange::new(PASSWORD, OWN, PEER, unhex32(RAND_A), unhex32(MASK_A)).unwrap()
    }

    #[test]
    fn pwe_matches_the_reference_vector() {
        let pwe = derive_pwe(PASSWORD, &OWN, &PEER).unwrap();
        let encoded = pwe.to_encoded_point(false);
        assert_eq!(&encoded.as_bytes()[1..33], &hex(PWE_X)[..]);
        assert_eq!(&encoded.as_bytes()[33..65], &hex(PWE_Y)[..]);
    }

    #[test]
    fn pwe_is_symmetric_in_the_address_order() {
        assert_eq!(
            derive_pwe(PASSWORD, &OWN, &PEER).unwrap(),
            derive_pwe(PASSWORD, &PEER, &OWN).unwrap()
        );
    }

    #[test]
    fn commit_body_matches_the_reference_exchange() {
        assert_eq!(exchange().commit_body().as_slice(), &hex(COMMIT_A)[..]);
    }

    #[test]
    fn processing_the_peer_commit_derives_the_reference_keys() {
        let mut exchange = exchange();
        exchange.process_commit(&hex(COMMIT_B)).unwrap();
        assert_eq!(exchange.keys.unwrap().0, unhex32(KCK));
        assert_eq!(exchange.pmk().unwrap(), unhex32(PMK));
        let pmkid: [u8; PMKID_LEN] = hex(PMKID).try_into().unwrap();
        assert_eq!(exchange.pmkid().unwrap(), pmkid);

        let body = exchange.confirm_body().unwrap();
        assert_eq!(&body[..2], &1u16.to_le_bytes()[..]);
        assert_eq!(&body[2..], &hex(CONFIRM_A)[..]);
    }

    #[test]
    fn the_peer_confirm_verifies_with_the_peer_send_confirm() {
        let mut exchange = exchange();
        exchange.process_commit(&hex(COMMIT_B)).unwrap();

        let mut peer_confirm = 2u16.to_le_bytes().to_vec();
        peer_confirm.extend_from_slice(&hex(CONFIRM_B));
        assert!(exchange.verify_confirm(&peer_confirm));

        peer_confirm[10] ^= 1;
        assert!(!exchange.verify_confirm(&peer_confirm));

        let mut own_confirm = 1u16.to_le_bytes().to_vec();
        own_confirm.extend_from_slice(&hex(CONFIRM_A));
        // Our own confirm is not a valid peer confirm: the scalar order differs.
        assert!(!exchange.verify_confirm(&own_confirm));
    }

    #[test]
    fn a_confirm_before_the_commit_is_rejected() {
        assert!(!exchange().verify_confirm(&hex(CONFIRM_B)));
    }

    #[test]
    fn a_commit_for_another_group_is_rejected() {
        let mut commit = hex(COMMIT_B);
        commit[..2].copy_from_slice(&20u16.to_le_bytes());
        assert_eq!(exchange().process_commit(&commit), Err(SaeError::Commit));
    }

    #[test]
    fn an_off_curve_commit_is_rejected() {
        let mut commit = hex(COMMIT_B);
        let last = commit.len() - 1;
        commit[last] ^= 1;
        assert_eq!(exchange().process_commit(&commit), Err(SaeError::Commit));
    }

    #[test]
    fn a_zero_scalar_commit_is_rejected() {
        let mut commit = hex(COMMIT_B);
        commit[2..34].fill(0);
        assert_eq!(exchange().process_commit(&commit), Err(SaeError::Scalar));
    }

    #[test]
    fn a_short_commit_is_rejected() {
        let commit = hex(COMMIT_B);
        assert_eq!(
            exchange().process_commit(&commit[..97]),
            Err(SaeError::Commit)
        );
    }

    #[test]
    fn our_own_commit_reflected_back_is_rejected() {
        // The peer echoing our commit is the reflection attack `sae_parse_commit`
        // drops silently.
        let mut exchange = exchange();
        let own_commit = exchange.commit_body();
        assert_eq!(
            exchange.process_commit(&own_commit),
            Err(SaeError::Reflection)
        );
    }
}
