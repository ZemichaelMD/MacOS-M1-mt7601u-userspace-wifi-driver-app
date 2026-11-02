//! WPA/WPA2/WPA3-Personal key derivation (IEEE 802.11i): the PMK from the
//! passphrase, the PTK from the 4-way handshake nonces, the EAPOL-Key MIC
//! (HMAC-MD5-128 for WPA, HMAC-SHA1-128 for WPA2, AES-128-CMAC for WPA3) and
//! RFC 3394 key unwrapping for the GTK.
//!
//! CCMP/TKIP encryption itself is done by the MT7601U hardware, so no cipher is
//! implemented here — only the key schedule, the MICs and the key-wrap (plus
//! RC4 for WPA1's key data, which the standard encrypts differently).

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

/// PMK (PSK) length.
pub const PMK_LEN: usize = 32;
/// Nonce length (ANonce/SNonce are 32 octets, IEEE 802.11i §8.5.1.1).
pub const NONCE_LEN: usize = 32;
/// PTK length for CCMP (KCK ‖ KEK ‖ TK-16).
pub const PTK_LEN: usize = 48;
/// EAPOL-Key MIC length (the same 16 octets for all three MIC algorithms).
pub const MIC_LEN: usize = 16;
/// `PBKDF2` iteration count for WPA/WPA2-PSK.
pub const PBKDF2_ITERATIONS: u32 = 4096;
/// TKIP temporary-key length: the 128-bit key plus TX/RX Michael MIC keys.
pub const TKIP_TK_LEN: usize = 32;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacMd5 = Hmac<Md5>;

/// `PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256)` — the WPA/WPA2 PSK.
pub fn pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; PMK_LEN] {
    let mut out = [0u8; PMK_LEN];
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase, ssid, PBKDF2_ITERATIONS, &mut out);
    out
}

/// The WPA2 PRF (IEEE 802.11i §8.5.1.1): `HMAC-SHA1` in counter mode, i.e.
/// `HMAC-SHA1(key, label ‖ 0x00 ‖ data ‖ counter)` concatenated over counters
/// starting at 0.
pub fn prf(key: &[u8], label: &[u8], data: &[u8], out: &mut [u8]) {
    let mut counter: u8 = 0;
    let mut offset = 0usize;
    while offset < out.len() {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(label);
        mac.update(&[0x00]);
        mac.update(data);
        mac.update(&[counter]);
        let digest = mac.finalize().into_bytes();
        let take = (out.len() - offset).min(digest.len());
        out[offset..offset + take].copy_from_slice(&digest[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

/// The SHA-256 KDF from IEEE 802.11-2020 §12.7.1.8.2 (`sha256_prf_bits` in
/// hostap's `src/crypto/sha256-prf.c`):
/// `HMAC-SHA256(key, LE16(counter) ‖ label ‖ data ‖ LE16(bits))`, counters
/// starting at 1. Used by SAE and by the PTK derivation of SHA-256 AKMs
/// (WPA3 SAE, WPA2-PSK-SHA256) and WPA3's 4-way handshake.
///
/// Only whole-byte outputs are requested here, so the bit-mask step of the
/// hostap helper is not needed.
pub fn sha256_prf(key: &[u8], label: &[u8], data: &[u8], out: &mut [u8]) {
    let bits = (out.len() * 8) as u16;
    let mut counter: u16 = 1;
    let mut offset = 0usize;
    while offset < out.len() {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&counter.to_le_bytes());
        mac.update(label);
        mac.update(data);
        mac.update(&bits.to_le_bytes());
        let digest = mac.finalize().into_bytes();
        let take = (out.len() - offset).min(digest.len());
        out[offset..offset + take].copy_from_slice(&digest[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

/// The pairwise transient key: key-confirmation key, key-encryption key and
/// temporary key.
///
/// `tk` is always 32 bytes so TKIP (whose TK is the 128-bit key plus the two
/// Michael MIC keys) fits; `tk_len` says how many bytes are valid — 16 for
/// CCMP, 32 for TKIP.
///
/// The derived key material is deliberately not printable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ptk {
    pub kck: [u8; 16],
    pub kek: [u8; 16],
    pub tk: [u8; 32],
    /// Valid bytes in `tk`: 16 (CCMP) or 32 (TKIP).
    pub tk_len: u8,
}

impl std::fmt::Debug for Ptk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ptk(<KCK/KEK/TK key material>)")
    }
}

/// The ordered PRF input: addresses and nonces, each pair lexicographic.
fn ptk_data(
    authenticator: &[u8; 6],
    supplicant: &[u8; 6],
    anonce: &[u8; NONCE_LEN],
    snonce: &[u8; NONCE_LEN],
) -> [u8; 6 + 6 + NONCE_LEN + NONCE_LEN] {
    let (addr_lo, addr_hi) = if authenticator <= supplicant {
        (*authenticator, *supplicant)
    } else {
        (*supplicant, *authenticator)
    };
    let (nonce_lo, nonce_hi) = if anonce <= snonce {
        (*anonce, *snonce)
    } else {
        (*snonce, *anonce)
    };

    let mut data = [0u8; 6 + 6 + NONCE_LEN + NONCE_LEN];
    data[0..6].copy_from_slice(&addr_lo);
    data[6..12].copy_from_slice(&addr_hi);
    data[12..12 + NONCE_LEN].copy_from_slice(&nonce_lo);
    data[12 + NONCE_LEN..].copy_from_slice(&nonce_hi);
    data
}

/// Split PRF output into KCK ‖ KEK ‖ TK.
fn split_ptk(out: &[u8], tk_len: u8) -> Ptk {
    let mut ptk = Ptk {
        kck: [0u8; 16],
        kek: [0u8; 16],
        tk: [0u8; 32],
        tk_len,
    };
    ptk.kck.copy_from_slice(&out[0..16]);
    ptk.kek.copy_from_slice(&out[16..32]);
    ptk.tk[..usize::from(tk_len)].copy_from_slice(&out[32..32 + usize::from(tk_len)]);
    ptk
}

/// Derive the PTK from the PMK and the handshake nonces (WPA2-PSK, CCMP).
///
/// The PRF input orders each address/nonce pair lexicographically, as the
/// standard requires.
pub fn ptk(
    pmk: &[u8; PMK_LEN],
    authenticator: &[u8; 6],
    supplicant: &[u8; 6],
    anonce: &[u8; NONCE_LEN],
    snonce: &[u8; NONCE_LEN],
) -> Ptk {
    let data = ptk_data(authenticator, supplicant, anonce, snonce);
    let mut out = [0u8; PTK_LEN];
    prf(pmk, b"Pairwise key expansion", &data, &mut out);
    split_ptk(&out, 16)
}

/// Derive the PTK for WPA-PSK with TKIP: the same HMAC-SHA1 PRF, but 512 bits
/// of output because the TK is 32 octets (IEEE 802.11i §8.5.1.1).
pub fn ptk_tkip(
    pmk: &[u8; PMK_LEN],
    authenticator: &[u8; 6],
    supplicant: &[u8; 6],
    anonce: &[u8; NONCE_LEN],
    snonce: &[u8; NONCE_LEN],
) -> Ptk {
    let data = ptk_data(authenticator, supplicant, anonce, snonce);
    let mut out = [0u8; PTK_LEN + 16];
    prf(pmk, b"Pairwise key expansion", &data, &mut out);
    split_ptk(&out, 32)
}

/// Swap the TX and RX Michael MIC keys of a TKIP key.
///
/// The TKIP TK is `TK ‖ MIC-a ‖ MIC-b`; the driver/hardware slot wants the
/// MIC halves the other way round. wpa_supplicant does exactly this swap for
/// the pairwise TK (`wpa_supplicant_process_1_of_4`: "Supplicant: swap tx/rx
/// Mic keys") and for the GTK before installing either into the driver
/// (`wpa_supplicant_install_gtk`), so repeating it here reproduces the key
/// bytes the Linux driver programs into the MT7601U.
pub fn tkip_swap_mic_keys(tk: &mut [u8; TKIP_TK_LEN]) {
    for i in 0..8 {
        tk.swap(16 + i, 24 + i);
    }
}

/// Derive the PTK for a SHA-256 AKM (WPA3 SAE): `sha256_prf` with the same
/// address/nonce layout (`wpa_pmk_to_ptk` in hostap's `wpa_common.c`).
pub fn ptk_sae(
    pmk: &[u8; PMK_LEN],
    authenticator: &[u8; 6],
    supplicant: &[u8; 6],
    anonce: &[u8; NONCE_LEN],
    snonce: &[u8; NONCE_LEN],
) -> Ptk {
    let data = ptk_data(authenticator, supplicant, anonce, snonce);
    let mut out = [0u8; PTK_LEN];
    sha256_prf(pmk, b"Pairwise key expansion", &data, &mut out);
    split_ptk(&out, 16)
}

/// The EAPOL-Key MIC: `HMAC-SHA1(KCK, frame)` truncated to 128 bits.
pub fn mic(kck: &[u8; 16], frame: &[u8]) -> [u8; MIC_LEN] {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(kck).expect("HMAC accepts any key length");
    mac.update(frame);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; MIC_LEN];
    out.copy_from_slice(&digest[..MIC_LEN]);
    out
}

/// The WPA1 EAPOL-Key MIC: `HMAC-MD5(KCK, frame)` (already 128 bits).
pub fn mic_md5(kck: &[u8; 16], frame: &[u8]) -> [u8; MIC_LEN] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(kck).expect("HMAC accepts any key length");
    mac.update(frame);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; MIC_LEN];
    out.copy_from_slice(&digest[..MIC_LEN]);
    out
}

/// The WPA3 EAPOL-Key MIC: `AES-128-CMAC(KCK, frame)`.
pub fn mic_cmac(kck: &[u8; 16], frame: &[u8]) -> [u8; MIC_LEN] {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(kck).expect("CMAC accepts 16-byte keys");
    mac.update(frame);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; MIC_LEN];
    out.copy_from_slice(&digest[..MIC_LEN]);
    out
}

/// `rc4_skip(key, skip, data)` as hostap implements it (`src/crypto/rc4.c`):
/// RC4 keyed with `key`, the first `skip` keystream bytes discarded, then the
/// data XORed with the keystream.
///
/// WPA1 encrypts message 3's key data with `key_iv ‖ KEK` and a 256-byte skip
/// (no AES key wrap), so this is needed for WPA1 only.
pub fn rc4_skip(key: &[u8], skip: usize, data: &[u8]) -> Vec<u8> {
    let mut state: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + usize::from(state[i]) + usize::from(key[i % key.len()])) & 0xff;
        state.swap(i, j);
    }

    let mut i = 0usize;
    let mut j = 0usize;
    let next_byte = |state: &mut [u8; 256], i: &mut usize, j: &mut usize| -> u8 {
        *i = (*i + 1) & 0xff;
        *j = (*j + usize::from(state[*i])) & 0xff;
        state.swap(*i, *j);
        state[(usize::from(state[*i]) + usize::from(state[*j])) & 0xff]
    };

    for _ in 0..skip {
        next_byte(&mut state, &mut i, &mut j);
    }
    data.iter()
        .map(|byte| byte ^ next_byte(&mut state, &mut i, &mut j))
        .collect()
}

/// Default initialisation vector.
const KEY_WRAP_IV: u64 = 0xa6a6_a6a6_a6a6_a6a6;

/// Unwrap key data with RFC 3394 AES key wrap.
///
/// Returns `None` for a malformed length or a failed integrity check.
pub fn unwrap_key(kek: &[u8; 16], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return None;
    }
    let cipher = Aes128::new_from_slice(kek).ok()?;
    let n = wrapped.len() / 8 - 1;

    let mut a = u64::from_be_bytes(wrapped[..8].try_into().ok()?);
    let mut blocks: Vec<[u8; 8]> = (0..n)
        .map(|i| {
            let start = 8 + i * 8;
            let mut block = [0u8; 8];
            block.copy_from_slice(&wrapped[start..start + 8]);
            block
        })
        .collect();

    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            let t = (n * j + i) as u64;
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&(a ^ t).to_be_bytes());
            block[8..].copy_from_slice(&blocks[i - 1]);
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
            a = u64::from_be_bytes(block[..8].try_into().ok()?);
            blocks[i - 1].copy_from_slice(&block[8..]);
        }
    }

    if a != KEY_WRAP_IV {
        return None;
    }

    let mut out = Vec::with_capacity(n * 8);
    for block in blocks {
        out.extend_from_slice(&block);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published IEEE 802.11i example (SSID "IEEE", passphrase "password").
    const IEEE_PMK: [u8; 32] = [
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f,
        0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10,
        0xa1, 0x2e,
    ];

    // The PTK/MIC values below come from an independent implementation of the
    // 802.11i PRF (cross-checked, not an official standard vector).
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

    #[test]
    fn pmk_matches_the_published_vector() {
        assert_eq!(pmk(b"password", b"IEEE"), IEEE_PMK);
    }

    #[test]
    fn ptk_matches_the_reference_derivation() {
        let derived = ptk(&IEEE_PMK, &AA, &SPA, &ANONCE, &SNONCE);
        assert_eq!(derived.kck, hex("bfcdca8bfaca3da564ca3c2001c8809e")[..]);
        assert_eq!(derived.kek, hex("eb3a3ecd3596bac487311e60c60ebf4d")[..]);
        assert_eq!(
            derived.tk[..16],
            hex("923f7f0fa8f99ac365a233a13b441bf6")[..]
        );
        assert_eq!(derived.tk_len, 16);
    }

    #[test]
    fn ptk_tkip_extends_the_same_prf_to_512_bits() {
        // Same PRF as the CCMP PTK, extended to 64 bytes so the TKIP TK
        // (16-byte key + TX/RX Michael MIC keys) fits. Cross-checked with the
        // independent Python reference in `scripts/gen-crypto-vectors.py`.
        let derived = ptk_tkip(&IEEE_PMK, &AA, &SPA, &ANONCE, &SNONCE);
        assert_eq!(derived.kck, hex("bfcdca8bfaca3da564ca3c2001c8809e")[..]);
        assert_eq!(derived.kek, hex("eb3a3ecd3596bac487311e60c60ebf4d")[..]);
        assert_eq!(
            derived.tk[..32],
            hex("923f7f0fa8f99ac365a233a13b441bf6c19d333059a99b4357dd7c29451bf830")[..]
        );
        assert_eq!(derived.tk_len, 32);
        // The 384-bit prefix is the same PRF stream as the CCMP PTK.
        assert_eq!(
            derived.tk[..16],
            ptk(&IEEE_PMK, &AA, &SPA, &ANONCE, &SNONCE).tk[..16]
        );
    }

    #[test]
    fn ptk_sae_uses_the_sha256_prf() {
        // SHA-256 KDF ("sha256_prf") with the same address/nonce layout;
        // cross-checked with `scripts/gen-crypto-vectors.py`.
        let derived = ptk_sae(&IEEE_PMK, &AA, &SPA, &ANONCE, &SNONCE);
        assert_eq!(derived.kck, hex("c6c332be6ca016ad144235b898d46b7a")[..]);
        assert_eq!(derived.kek, hex("a19faea924ac510fc482480e438e47ad")[..]);
        assert_eq!(
            derived.tk[..16],
            hex("50479db31e2aad02d500069f95fc3755")[..]
        );
        assert_eq!(derived.tk_len, 16);
    }

    #[test]
    fn sha256_prf_matches_the_reference_construction() {
        // hostap `sha256_prf_bits`: HMAC-SHA256(key, LE16(counter) ‖ label ‖
        // data ‖ LE16(bits)), counters from 1; cross-checked with
        // `scripts/gen-crypto-vectors.py`.
        let key: Vec<u8> = (0u8..16).collect();
        let data: Vec<u8> = (16u8..32).collect();
        let mut out = [0u8; 64];
        sha256_prf(&key, b"Pairwise key expansion", &data, &mut out);
        assert_eq!(
            out[..],
            hex(
                "c9c37c1dba0723d7f504bcb7257325202862e9acfcdf6ababa9dd755d495bab1\
                 91d66ce12b8a00db997c5fdefee232e2382f9cf144473b82518a473572d53e37"
            )[..]
        );
    }

    #[test]
    fn ptk_is_order_independent_for_addresses_and_nonces() {
        let a = ptk(&IEEE_PMK, &AA, &SPA, &ANONCE, &SNONCE);
        let b = ptk(&IEEE_PMK, &SPA, &AA, &SNONCE, &ANONCE);
        assert_eq!(a, b);
    }

    #[test]
    fn tkip_mic_swap_exchanges_the_two_michael_keys() {
        let mut tk = [0u8; TKIP_TK_LEN];
        for (i, byte) in tk.iter_mut().enumerate() {
            *byte = i as u8;
        }
        tkip_swap_mic_keys(&mut tk);
        assert_eq!(&tk[..16], &(0u8..16).collect::<Vec<u8>>());
        assert_eq!(&tk[16..24], &(24u8..32).collect::<Vec<u8>>());
        assert_eq!(&tk[24..32], &(16u8..24).collect::<Vec<u8>>());
        // Swapping twice restores the original order.
        tkip_swap_mic_keys(&mut tk);
        assert_eq!(tk, core::array::from_fn(|i| i as u8));
    }

    #[test]
    fn mic_matches_the_reference_value() {
        let derived = ptk(&IEEE_PMK, &AA, &SPA, &ANONCE, &SNONCE);
        assert_eq!(
            mic(&derived.kck, b"eapol-test-payload"),
            hex("160a0a169f16d1c19a89512e6f55175b")[..]
        );
    }

    #[test]
    fn mic_md5_matches_the_reference_value() {
        // WPA1 (descriptor version 1) uses HMAC-MD5-128. The frame pattern and
        // expected MIC come from `scripts/gen-crypto-vectors.py`.
        let mut frame: Vec<u8> = (0..99).map(|i| ((i * 7 + 3) % 251) as u8).collect();
        frame[81..97].fill(0);
        let derived = ptk_tkip(&IEEE_PMK, &AA, &SPA, &ANONCE, &SNONCE);
        assert_eq!(
            mic_md5(&derived.kck, &frame),
            hex("d52c99ae9422ab111f73793f0bc83161")[..]
        );
    }

    #[test]
    fn mic_cmac_matches_rfc4493() {
        // RFC 4493 §2.2/§2.4 AES-128-CMAC test vectors (WPA3 uses this MIC).
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        assert_eq!(
            mic_cmac(&key, &[]),
            hex("bb1d6929e95937287fa37d129b756746")[..]
        );
        let msg16 = hex("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(
            mic_cmac(&key, &msg16),
            hex("070a16b46b4d4144f79bdd9dd04a287c")[..]
        );
        let msg40 = hex("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411");
        assert_eq!(
            mic_cmac(&key, &msg40),
            hex("dfa66747de9ae63030ca32611497c827")[..]
        );
        let msg64 = hex("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710");
        assert_eq!(
            mic_cmac(&key, &msg64),
            hex("51f0bebf7e3b9d92fc49741779363cfe")[..]
        );
    }

    #[test]
    fn rc4_skip_matches_the_reference_value() {
        // WPA1 decrypts message 3's key data with RC4 (key = key-iv ‖ KEK, 256
        // keystream bytes skipped); cross-checked with
        // `scripts/gen-crypto-vectors.py`.
        let ek = hex("00112233445566778899aabbccddeefff0e1d2c3b4a5968778695a4b3c2d1e0f");
        let data: Vec<u8> = (0..64).collect();
        assert_eq!(
            rc4_skip(&ek, 256, &data),
            hex(
                "b5fd7c1c9a6fce7be737cc37cc1150e1ff6a64dd086cc22bee79fdd02475f180\
                 707f633cc1d853233447689aaf594b266676fbab6c5728ac7f7bd368ff6dab50"
            )
        );
    }

    #[test]
    fn unwraps_an_rfc3394_vector() {
        // RFC 3394 §4.1: 128-bit KEK, 128-bit key data.
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        let mut kek_arr = [0u8; 16];
        kek_arr.copy_from_slice(&kek);
        let wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        let unwrapped = unwrap_key(&kek_arr, &wrapped).expect("unwrap");
        assert_eq!(unwrapped, hex("00112233445566778899AABBCCDDEEFF"));
    }

    #[test]
    fn unwrap_rejects_a_corrupted_integrity_value() {
        let mut kek = [0u8; 16];
        kek.copy_from_slice(&hex("000102030405060708090A0B0C0D0E0F"));
        let mut wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        wrapped[0] ^= 0xff;
        assert!(unwrap_key(&kek, &wrapped).is_none());
    }

    #[test]
    fn ptk_debug_redacts_key_material() {
        let derived = ptk(&IEEE_PMK, &AA, &SPA, &ANONCE, &SNONCE);
        let rendered = format!("{derived:?}");
        assert!(!rendered.contains("4ae2"));
        assert!(rendered.contains("redacted") || rendered.contains("key material"));
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
}
