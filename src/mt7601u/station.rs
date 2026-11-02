//! Open-system association — Step 2 of `HANDOVER.md`.
//!
//! mac80211's MLME does not exist on macOS, so the authentication and
//! association exchange that turns a scan result into an associated station is
//! driven here by hand. [`associate`] performs the station register setup and
//! the auth/assoc exchange; the radio bring-up and channel selection are done
//! by the caller (see the `--connect` command).
//!
//! Only **open** networks are handled. WPA2 and the data path are later steps,
//! so a successful `associate` does **not** mean there is connectivity.

use std::time::{Duration, Instant};

use crate::usb::{Transport, UsbError};
use crate::wifi::{
    eapol, frames,
    handshake::{HandshakeError, WpaHandshake, WpaMode},
    mgmt, rsn, sae,
};

use super::data::StaLinkInfo;
use super::device::Mt7601u;
use super::eeprom::Eeprom;
use super::mac::{GROUP_WCID_0, OWN_WCID, STA_WCID};
use super::{dma, regs, rx, tx};

/// Read buffer for one bulk-IN transfer.
const RX_BUFFER_LEN: usize = 8192;

/// How long to wait for the authentication response.
pub const AUTH_TIMEOUT: Duration = Duration::from_millis(500);
/// How long to wait for the association response.
pub const ASSOC_TIMEOUT: Duration = Duration::from_millis(1000);
/// Listen interval advertised in the association request, in beacon intervals.
pub const LISTEN_INTERVAL: u16 = 10;
/// Capability information bit for an infrastructure (ESS) network.
pub const CAPABILITY_ESS: u16 = 0x0001;
/// Capability information bit for an ad-hoc (IBSS) network.
pub const CAPABILITY_IBSS: u16 = 0x0002;
/// Basic rate set for 1, 2, 5.5 and 11 Mbit/s (rate indices 0..3).
pub const BASIC_RATES_BG: u32 = 0x000f;
/// Beacon interval assumed when the beacon's value is unknown.
pub const DEFAULT_BEACON_INTERVAL: u16 = 100;
/// Slot time for a long-slot (802.11b/g) network.
pub const SLOT_TIME_LONG_US: u32 = 20;
/// Capability information bit for a protected (privacy) network. WPA2 requires
/// it in the association request.
pub const CAPABILITY_PRIVACY: u16 = 0x0010;
/// How long to wait for each EAPOL-Key message.
pub const EAPOL_TIMEOUT: Duration = Duration::from_millis(1500);
/// Poll timeout once the handshake has completed, while watching for the AP's
/// retransmitted 3/4 messages.
const EAPOL_POLL_TIMEOUT: Duration = Duration::from_millis(250);
/// How long to keep answering retransmitted 3/4 messages after we send 4/4.
const EAPOL_RETRY_GRACE: Duration = Duration::from_millis(1500);
/// How long to wait for the WPA1 group-key handshake after the 4-way.
const EAPOL_GROUP_TIMEOUT: Duration = Duration::from_millis(1500);
/// Maximum number of EAPOL frames processed before giving up.
const MAX_EAPOL_STEPS: u32 = 24;
/// How many times a SAE commit may be (re)sent, echoing anti-clogging tokens.
const SAE_MAX_COMMIT_ATTEMPTS: u32 = 4;

/// The access point to associate with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BssTarget {
    pub ssid: String,
    pub bssid: [u8; 6],
    /// Channel the radio must be tuned to.
    pub channel: u8,
    /// Capability information from the beacon.
    pub capability: u16,
    /// Basic rate set bitmap.
    pub basic_rates: u32,
    /// Beacon interval in time units.
    pub beacon_interval: u16,
}

impl BssTarget {
    /// An infrastructure target using the defaults for the rate set and
    /// beacon interval (a beacon's capability info is the only field that must
    /// come from the AP).
    pub fn infrastructure(ssid: String, bssid: [u8; 6], channel: u8, capability: u16) -> Self {
        Self {
            ssid,
            bssid,
            channel,
            capability: capability | CAPABILITY_ESS,
            basic_rates: BASIC_RATES_BG,
            beacon_interval: DEFAULT_BEACON_INTERVAL,
        }
    }

    /// True for an infrastructure BSS (ESS bit set, IBSS bit clear).
    pub fn is_infrastructure(&self) -> bool {
        self.capability & CAPABILITY_ESS != 0 && self.capability & CAPABILITY_IBSS == 0
    }
}

/// Result of a successful association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Association {
    /// Association id assigned by the AP.
    pub aid: u16,
    /// False when the AP kept retransmitting message 3/4 after we sent 4/4,
    /// which means it never accepted the handshake — the station is not
    /// registered with the AP and no traffic will be served.
    pub handshake_confirmed: bool,
}

/// Program the station state and exchange open-system auth + association with
/// `target`.
///
/// The caller must have already brought the radio up, tuned it to
/// `target.channel` and started the MAC (see [`connect`]).
pub fn associate<T: Transport>(
    chip: &Mt7601u<T>,
    eeprom: &Eeprom,
    target: &BssTarget,
) -> Result<Association, UsbError> {
    let aid = auth_and_associate(chip, eeprom, target, None)?;
    Ok(Association {
        aid,
        handshake_confirmed: true,
    })
}

/// The open-system authentication and association exchange shared by the open,
/// WPA1 and WPA2 join paths.
///
/// `ie` is the security IE to advertise in the association request (RSN or the
/// WPA1 vendor IE); `None` associates in the open.
fn auth_and_associate<T: Transport>(
    chip: &Mt7601u<T>,
    eeprom: &Eeprom,
    target: &BssTarget,
    ie: Option<&[u8]>,
) -> Result<u16, UsbError> {
    if target.ssid.len() > 32 {
        return Err(UsbError::Other(format!(
            "SSID is {} bytes (maximum 32)",
            target.ssid.len()
        )));
    }
    if !target.is_infrastructure() {
        return Err(UsbError::Other(
            "target is not an infrastructure (ESS) network".to_string(),
        ));
    }

    let our_addr = eeprom.mac_addr;
    program_station(chip, eeprom, target)?;

    // Open-system authentication (WPA1/WPA2 authenticate during the 4-way
    // handshake, not here).
    let auth = frames::auth_open(our_addr, target.bssid);
    transmit_management(chip, &auth)?;
    let response = wait_for_management(chip, AUTH_TIMEOUT, |frame| {
        match_auth(frame, &our_addr, &target.bssid)
    })?
    .ok_or_else(|| UsbError::Other("no authentication response from the AP".to_string()))?;
    if !response.is_success() {
        return Err(UsbError::Other(format!(
            "authentication rejected (status {})",
            response.status
        )));
    }

    associate_request(chip, target, our_addr, ie)
}

/// Send the association request (advertising `ie`, when there is one) and wait
/// for the response.
fn associate_request<T: Transport>(
    chip: &Mt7601u<T>,
    target: &BssTarget,
    our_addr: [u8; 6],
    ie: Option<&[u8]>,
) -> Result<u16, UsbError> {
    let assoc = match ie {
        Some(ie) => frames::assoc_request_with_ies(
            our_addr,
            target.bssid,
            target.ssid.as_bytes(),
            target.capability | CAPABILITY_PRIVACY,
            LISTEN_INTERVAL,
            ie,
        ),
        None => frames::assoc_request(
            our_addr,
            target.bssid,
            target.ssid.as_bytes(),
            target.capability,
            LISTEN_INTERVAL,
        ),
    };
    transmit_management(chip, &assoc)?;
    let response = wait_for_management(chip, ASSOC_TIMEOUT, |frame| {
        match_assoc(frame, &our_addr, &target.bssid)
    })?
    .ok_or_else(|| UsbError::Other("no association response from the AP".to_string()))?;
    if !response.is_success() {
        return Err(UsbError::Other(format!(
            "association rejected (status {})",
            response.status
        )));
    }
    Ok(response.aid)
}

/// Program the station registers common to open and WPA2 association
/// (`mac.c` / `main.c::bss_info_changed`).
fn program_station<T: Transport>(
    chip: &Mt7601u<T>,
    eeprom: &Eeprom,
    target: &BssTarget,
) -> Result<(), UsbError> {
    chip.set_macaddr(&eeprom.mac_addr)
        .map_err(context("set mac address"))?;
    // The AP's own WCID entry (unicast; holds the pairwise key) and the group
    // entry (broadcast/multicast; holds the group key).
    chip.mac_wcid_setup(STA_WCID, 0, Some(&target.bssid))
        .map_err(context("station wcid setup"))?;
    chip.mac_wcid_clear_drop(STA_WCID)
        .map_err(context("station wcid drop"))?;
    // A second entry holds our own address (and, once the handshake completes,
    // the pairwise key). The hardware looks a received frame's key up by matching
    // the frame's addresses against the WCID address table, so a unicast frame
    // addressed to us needs an entry that carries our address — otherwise there
    // is no key to decrypt an OFFER/ARP reply/echo reply with and it is dropped.
    chip.mac_wcid_setup(OWN_WCID, 0, Some(&eeprom.mac_addr))
        .map_err(context("own wcid setup"))?;
    chip.mac_wcid_clear_drop(OWN_WCID)
        .map_err(context("own wcid drop"))?;
    // The group entry keeps the **broadcast** address it is given by
    // `init_wcid_mem` (which fills every WCID address slot with
    // `ff:ff:ff:ff:ff:ff`). That is what makes the hardware match a
    // group-addressed receive frame to this WCID and decrypt it with the group
    // key (GTK). Programming the AP's BSSID here instead makes group-addressed
    // frames match the *station* WCID and decrypt with the pairwise key (TK),
    // so the hardware drops every broadcast/multicast reply — which is exactly
    // what broke DHCP. Linux never programs the group WCID's address.
    chip.mac_wcid_setup(GROUP_WCID_0, 0, Some(&frames::BROADCAST))
        .map_err(context("wcid setup"))?;
    chip.mac_wcid_clear_drop(GROUP_WCID_0)
        .map_err(context("group wcid drop"))?;
    chip.set_bssid(&target.bssid)
        .map_err(context("set bssid"))?;
    chip.mac_set_basic_rates(target.basic_rates)
        .map_err(context("basic rates"))?;
    chip.mac_set_short_preamble(false)
        .map_err(context("short preamble"))?;
    chip.mac_set_slot_time(SLOT_TIME_LONG_US)
        .map_err(context("slot time"))?;
    chip.mac_config_tsf(true, target.beacon_interval)
        .map_err(context("tsf"))?;
    Ok(())
}

/// Associate with a WPA2-PSK (CCMP) network and run the 4-way handshake.
///
/// On success the pairwise (TK) and group (GTK) keys are installed into the
/// hardware, so subsequent data frames are CCMP-protected by the chip.
pub fn associate_wpa2<T: Transport>(
    chip: &Mt7601u<T>,
    eeprom: &Eeprom,
    target: &BssTarget,
    passphrase: &[u8],
    snonce: [u8; 32],
) -> Result<Association, UsbError> {
    let aid = auth_and_associate(chip, eeprom, target, Some(&rsn::build_psk_ccmp()))?;
    let handshake = WpaHandshake::new(
        passphrase,
        target.ssid.as_bytes(),
        target.bssid,
        eeprom.mac_addr,
        snonce,
    );
    let handshake_confirmed = run_wpa_handshake(chip, eeprom, target, handshake)?;
    Ok(Association {
        aid,
        handshake_confirmed,
    })
}

/// Associate with a WPA1-PSK (TKIP) network and run the 4-way handshake plus
/// the group-key handshake that follows it.
///
/// On success the TK and GTK are installed into the hardware, so subsequent
/// data frames are TKIP-protected by the chip. Unlike CCMP, TKIP needs the two
/// Michael MIC halves of both keys swapped before installation, exactly as
/// wpa_supplicant does before it hands them to the driver.
pub fn associate_wpa1<T: Transport>(
    chip: &Mt7601u<T>,
    eeprom: &Eeprom,
    target: &BssTarget,
    passphrase: &[u8],
    snonce: [u8; 32],
) -> Result<Association, UsbError> {
    let aid = auth_and_associate(chip, eeprom, target, Some(&rsn::build_wpa1_psk_tkip()))?;
    let handshake = WpaHandshake::new_wpa1(
        passphrase,
        target.ssid.as_bytes(),
        target.bssid,
        eeprom.mac_addr,
        snonce,
    );
    let handshake_confirmed = run_wpa_handshake(chip, eeprom, target, handshake)?;
    Ok(Association {
        aid,
        handshake_confirmed,
    })
}

/// Associate with a WPA3 (SAE) network and run the 4-way handshake.
///
/// SAE derives the PMK from a dragonfly exchange before association; the
/// 4-way handshake then only confirms it and distributes the GTK. `rand` and
/// `mask` are the two scalars the commit is built from — random in production,
/// fixed by the caller in tests.
pub fn associate_sae<T: Transport>(
    chip: &Mt7601u<T>,
    eeprom: &Eeprom,
    target: &BssTarget,
    passphrase: &[u8],
    snonce: [u8; 32],
    rand: [u8; 32],
    mask: [u8; 32],
) -> Result<Association, UsbError> {
    if target.ssid.len() > 32 {
        return Err(UsbError::Other(format!(
            "SSID is {} bytes (maximum 32)",
            target.ssid.len()
        )));
    }
    if !target.is_infrastructure() {
        return Err(UsbError::Other(
            "target is not an infrastructure (ESS) network".to_string(),
        ));
    }

    let our_addr = eeprom.mac_addr;
    program_station(chip, eeprom, target)?;

    let mut exchange = sae::SaeExchange::new(passphrase, our_addr, target.bssid, rand, mask)
        .map_err(|error| UsbError::Other(format!("SAE: {error}")))?;
    run_sae_auth(chip, target, our_addr, &mut exchange)?;

    let aid = associate_request(chip, target, our_addr, Some(&rsn::build_sae_ccmp()))?;
    let pmk = exchange
        .pmk()
        .ok_or_else(|| UsbError::Other("SAE: no PMK after the exchange".to_string()))?;
    let handshake = WpaHandshake::new_sae(pmk, target.bssid, our_addr, snonce);
    let handshake_confirmed = run_wpa_handshake(chip, eeprom, target, handshake)?;
    Ok(Association {
        aid,
        handshake_confirmed,
    })
}

/// The SAE authentication exchange: commit, optional anti-clogging-token
/// retries, then confirm.
///
/// The token request (status 76) means the AP wants the *same* commit replayed
/// with the token appended at the end of the body; the token changes nothing
/// else about the exchange.
fn run_sae_auth<T: Transport>(
    chip: &Mt7601u<T>,
    target: &BssTarget,
    our_addr: [u8; 6],
    exchange: &mut sae::SaeExchange,
) -> Result<(), UsbError> {
    let commit = exchange.commit_body();
    let mut transaction = mgmt::AUTH_SEQ_SAE_COMMIT;
    let mut body = commit.to_vec();

    let mut attempt = 0;
    loop {
        attempt += 1;
        if attempt > SAE_MAX_COMMIT_ATTEMPTS {
            return Err(UsbError::Other(format!(
                "SAE: the AP kept requesting anti-clogging tokens ({SAE_MAX_COMMIT_ATTEMPTS} attempts)"
            )));
        }

        let auth = frames::auth_sae(our_addr, target.bssid, transaction, 0, &body);
        transmit_management(chip, &auth)?;
        let (sequence, status, response_body) = wait_for_management(chip, AUTH_TIMEOUT, |frame| {
            match_sae_auth(frame, &our_addr, &target.bssid)
        })?
        .ok_or_else(|| UsbError::Other("no SAE authentication response from the AP".to_string()))?;

        match status {
            mgmt::STATUS_SUCCESS => {
                if sequence == mgmt::AUTH_SEQ_SAE_COMMIT {
                    // The commit is answered by a (status 0) commit.
                    exchange
                        .process_commit(&response_body)
                        .map_err(|error| UsbError::Other(format!("SAE: {error}")))?;
                    transaction = mgmt::AUTH_SEQ_SAE_CONFIRM;
                    body = exchange
                        .confirm_body()
                        .map_err(|error| UsbError::Other(format!("SAE: {error}")))?
                        .to_vec();
                } else if sequence == mgmt::AUTH_SEQ_SAE_CONFIRM {
                    if !exchange.verify_confirm(&response_body) {
                        return Err(UsbError::Other(
                            "SAE: the AP's confirm did not verify".to_string(),
                        ));
                    }
                    return Ok(());
                } else {
                    return Err(UsbError::Other(format!(
                        "SAE: unexpected authentication sequence {sequence}"
                    )));
                }
            }
            mgmt::STATUS_ANTI_CLOGGING_TOKEN_REQ => {
                if transaction != mgmt::AUTH_SEQ_SAE_COMMIT {
                    return Err(UsbError::Other(
                        "SAE: anti-clogging token requested after the commit".to_string(),
                    ));
                }
                // Replay the same commit with the token at the end of the body.
                body = commit.to_vec();
                body.extend_from_slice(&response_body);
            }
            mgmt::STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED => {
                return Err(UsbError::Other(
                    "SAE: the AP does not support the P-256 group".to_string(),
                ));
            }
            status => {
                return Err(UsbError::Other(format!(
                    "SAE authentication rejected (status {status})"
                )));
            }
        }
    }
}

/// Match a SAE authentication frame from the target AP, returning the message
/// number, status and body (the body is owned because the frame borrow ends).
fn match_sae_auth(
    frame: &[u8],
    our_addr: &[u8; 6],
    bssid: &[u8; 6],
) -> Option<(u16, u16, Vec<u8>)> {
    if frame.len() < 10 || frame[4..10] != *our_addr {
        return None;
    }
    let parsed = mgmt::parse_auth_body(frame)?;
    if parsed.algorithm != mgmt::AUTH_ALG_SAE {
        return None;
    }
    (frame[10..16] == *bssid).then(|| (parsed.sequence, parsed.status, parsed.body.to_vec()))
}

/// Drive the 4-way handshake (and, for WPA1, the group-key handshake),
/// installing the derived keys as they become available.
///
/// Returns whether the AP confirmed the handshake: if it keeps retransmitting
/// 3/4 after our 4/4, it never accepted it, and the station is not registered
/// with the AP (it will not appear in the AP's client list, and nothing is
/// bridged for it).
fn run_wpa_handshake<T: Transport>(
    chip: &Mt7601u<T>,
    eeprom: &Eeprom,
    target: &BssTarget,
    mut handshake: WpaHandshake,
) -> Result<bool, UsbError> {
    // Every EAPOL-Key frame of the handshake is exchanged **unencrypted**, and
    // the keys are installed only *after* our 4/4 goes out. The AP installs its
    // own copy of the PTK for RX when it accepts 4/4, so it cannot decrypt a
    // protected 4/4: it drops the frame, never registers the station, and keeps
    // retransmitting 3/4. This is also the order wpa_supplicant uses — it sends
    // 4/4 before the PTK reaches the driver. The data path is encrypted by the
    // caller once this returns.
    let info = StaLinkInfo::new(eeprom.mac_addr, target.bssid, false);
    let mut keys_installed = false;
    // Keep answering the AP after we send 4/4: an authenticator retransmits 3/4
    // (with a new replay counter) until it receives a 4/4 that matches, and a
    // supplicant that sends 4/4 once and stops listening leaves the handshake
    // half-finished — which is what makes the AP withhold the link.
    //
    // The handshake is *confirmed* only when the AP goes quiet for a whole grace
    // window after our 4/4. A single 3/4 that merely crossed our reply in flight
    // just restarts the window and is not read as a failure; an AP that keeps
    // retransmitting until the step budget runs out never accepted the reply, so
    // it never registered the station.
    let mut replied_at: Option<Instant> = None;
    // For WPA1 the group-key handshake follows the 4-way; if the AP never
    // starts it, the link still works for unicast traffic, so give up on the
    // GTK after this deadline rather than hanging.
    let mut group_deadline: Option<Instant> = None;
    let mut quiet = false;

    for step in 0..MAX_EAPOL_STEPS {
        if let Some(at) = replied_at {
            if handshake.is_fully_complete() {
                if at.elapsed() >= EAPOL_RETRY_GRACE {
                    quiet = true;
                    break;
                }
            } else if group_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                tracing::info!(
                    "the AP never ran the group-key handshake; continuing without a GTK"
                );
                quiet = true;
                break;
            }
        }
        let timeout = if handshake.is_complete() {
            EAPOL_POLL_TIMEOUT
        } else {
            EAPOL_TIMEOUT
        };
        let Some(payload) = chip.recv_payload(&info, timeout, eapol::ETHERTYPE_EAPOL) else {
            if handshake.is_complete() {
                // Nothing this poll; the grace timer above decides when to stop.
                continue;
            }
            return Err(UsbError::Other(format!(
                "no EAPOL-Key message (step {step} of the 4-way handshake)"
            )));
        };
        let reply = match handshake.on_frame(&payload.payload) {
            Ok(reply) => reply,
            // A duplicated 3/4 (same replay counter) is not an error, but the AP
            // is clearly still retransmitting, so restart the grace window.
            Err(HandshakeError::StaleReplay) if handshake.is_complete() => {
                replied_at = Some(Instant::now());
                continue;
            }
            Err(error) => return Err(UsbError::Other(format!("4-way handshake: {error}"))),
        };

        // `wpa_supplicant_process_1_of_2` installs a group-handshake GTK
        // *before* sending 2/2, and only then answers the group message.
        if handshake.pending_group_key() {
            let gtk = handshake
                .gtk()
                .cloned()
                .ok_or_else(|| UsbError::Other("group key pending without a GTK".to_string()))?;
            install_gtk(chip, &gtk, group_cipher(&handshake))?;
            handshake.mark_group_key_installed();
        }

        // Send the reply (2/4, 4/4 or the group 2/2) while the link is still
        // unencrypted, and install the keys only afterwards: the AP can only
        // decrypt our 4/4 once it has accepted it and installed its own copy of
        // the PTK.
        if let Some(reply) = reply {
            chip.tx_payload(&info, eapol::ETHERTYPE_EAPOL, &reply)?;
            if handshake.is_complete() {
                replied_at = Some(Instant::now());
                if !handshake.is_fully_complete() {
                    group_deadline = Some(Instant::now() + EAPOL_GROUP_TIMEOUT);
                }
            }
        }

        if handshake.is_complete() && !keys_installed {
            install_keys(chip, &handshake)?;
            keys_installed = true;
        }
    }

    if !handshake.is_complete() {
        return Err(UsbError::Other(
            "the 4-way handshake did not complete".to_string(),
        ));
    }
    if !keys_installed {
        install_keys(chip, &handshake)?;
    }

    Ok(quiet)
}

/// The group cipher implied by the handshake mode (WPA1 is TKIP, the RSN modes
/// use CCMP).
fn group_cipher(handshake: &WpaHandshake) -> u8 {
    match handshake.mode() {
        WpaMode::Wpa1Psk => regs::MT_CIPHER_TKIP,
        WpaMode::Wpa2Psk | WpaMode::Wpa3Sae => regs::MT_CIPHER_AES_CCMP,
    }
}

/// Program the pairwise (TK) and group (GTK) keys into the hardware, so
/// subsequent data frames use the hardware cipher.
fn install_keys<T: Transport>(chip: &Mt7601u<T>, handshake: &WpaHandshake) -> Result<(), UsbError> {
    let derived = *handshake
        .ptk()
        .ok_or_else(|| UsbError::Other("handshake finished without a PTK".to_string()))?;
    let cipher = group_cipher(handshake);

    // Pairwise key (the TK) on the AP's station entry. Unicast data frames are
    // sent on this WCID, so this is the key the hardware encrypts them with.
    // For TKIP the handshake has already swapped the Michael MIC halves, so the
    // bytes here are exactly what wpa_supplicant hands the Linux driver.
    let mut pairwise_key = [0u8; 32];
    pairwise_key[..derived.tk.len()].copy_from_slice(&derived.tk);
    chip.mac_wcid_set_key(STA_WCID, &pairwise_key, cipher, 0, true)
        .map_err(context("install pairwise key"))?;

    // The same key on the entry that carries our own address, so a unicast frame
    // addressed to us (OFFER, ARP reply, echo reply) can be decrypted.
    chip.mac_wcid_set_key(OWN_WCID, &pairwise_key, cipher, 0, true)
        .map_err(context("install pairwise key for our own address"))?;

    // Group key (the GTK), if the handshake already knows it (the WPA2 message
    // 3, or the WPA1 group handshake).
    if let Some(gtk) = handshake.gtk() {
        install_gtk(chip, gtk, cipher)?;
    }

    Ok(())
}

/// Program one group key (GTK) into the group WCID and the shared-key table.
///
/// It is written in two places, exactly as `mt7601u_set_key` does for
/// `sta == NULL`: the group WCID is selected for broadcast/multicast TX and the
/// shared-key table decrypts group-addressed RX (DHCP OFFER/ACK, ARP).
fn install_gtk<T: Transport>(
    chip: &Mt7601u<T>,
    gtk: &eapol::Gtk,
    cipher: u8,
) -> Result<(), UsbError> {
    let mut group_key = [0u8; 32];
    let length = gtk.key.len().min(32);
    group_key[..length].copy_from_slice(&gtk.key[..length]);
    chip.mac_wcid_set_key(GROUP_WCID_0, &group_key, cipher, gtk.key_id, false)
        .map_err(context("install group key in the group wcid"))?;
    chip.mac_shared_key_setup(0, gtk.key_id, &group_key, cipher)
        .map_err(context("install group key in the shared table"))?;
    Ok(())
}

/// Read `N` random bytes from the system RNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], UsbError> {
    use std::io::Read;

    let mut buffer = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buffer))
        .map_err(|error| UsbError::Other(format!("could not read /dev/urandom: {error}")))?;
    Ok(buffer)
}

/// Match an authentication response addressed to us by the target AP.
fn match_auth(frame: &[u8], our: &[u8; 6], ap: &[u8; 6]) -> Option<mgmt::AuthResponse> {
    let addrs = mgmt::addresses(frame)?;
    if &addrs.destination != our || &addrs.bssid != ap {
        return None;
    }
    let response = mgmt::parse_auth(frame)?;
    (response.sequence == mgmt::AUTH_SEQ_RESPONSE).then_some(response)
}

/// Match an association response (subtype 1).
fn match_assoc(frame: &[u8], our: &[u8; 6], ap: &[u8; 6]) -> Option<mgmt::AssocResponse> {
    let addrs = mgmt::addresses(frame)?;
    if &addrs.destination != our || &addrs.bssid != ap {
        return None;
    }
    mgmt::parse_assoc_response(frame)
}

/// Transmit a management frame at the lowest CCK rate with a hardware-assigned
/// sequence number, the way mac80211's MLME sends auth/assoc.
fn transmit_management<T: Transport>(chip: &Mt7601u<T>, frame: &[u8]) -> Result<(), UsbError> {
    let rate = tx::rate_val(tx::PHY_TYPE_CCK, 0, false, false);
    let txwi = tx::build_txwi(frame.len(), GROUP_WCID_0, rate, true, true, false, 0);
    let endpoint = chip
        .ac_endpoint(tx::AC_BE)
        .map_err(context("tx endpoint"))?;
    chip.tx_frame(&txwi, frame, endpoint, dma::QSEL_EDCA, true)?;
    Ok(())
}

/// Read bulk-IN segments until `parse` matches a frame or `timeout` elapses.
fn wait_for_management<T, R, F>(
    chip: &Mt7601u<T>,
    timeout: Duration,
    mut parse: F,
) -> Result<Option<R>, UsbError>
where
    T: Transport,
    F: FnMut(&[u8]) -> Option<R>,
{
    let endpoint = chip.rx_endpoint()?;
    let mut buffer = vec![0u8; RX_BUFFER_LEN];
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        let Ok(len) = chip
            .transport()
            .bulk_in(endpoint, &mut buffer, Duration::from_millis(50))
        else {
            continue;
        };
        if len < 2 {
            continue;
        }
        for segment in rx::parse_segments(&buffer[..len]) {
            if segment.rxwi.is_crc_error() {
                continue;
            }
            if let Some(result) = parse(segment.payload) {
                return Ok(Some(result));
            }
        }
    }
    Ok(None)
}

fn context(step: &'static str) -> impl Fn(UsbError) -> UsbError {
    move |error| UsbError::Other(format!("{step}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::eeprom::{Eeprom, RatePower, EEPROM_SIZE};
    use crate::mt7601u::testing::{device_info, Call, MockTransport};

    const OUR: [u8; 6] = [0x88, 0x82, 0x79, 0x24, 0x0e, 0xc0];
    const AP: [u8; 6] = [0x14, 0xcb, 0x49, 0x0d, 0x94, 0xec];

    fn eeprom() -> Eeprom {
        Eeprom {
            raw: [0; EEPROM_SIZE],
            version_ee: 0,
            version_fae: 0,
            mac_addr: OUR,
            tssi_enabled: false,
            rf_freq_off: 0,
            rssi_offset: [0, 0],
            ref_temp: 0,
            lna_gain: 0,
            chan_pwr: [0; 14],
            power_rate_table: RatePower::default(),
            real_cck_bw20: [0, 0],
            channel_start: 1,
            channel_count: 13,
        }
    }

    fn target() -> BssTarget {
        BssTarget::infrastructure("test-net".to_string(), AP, 6, CAPABILITY_ESS)
    }

    /// Frame a management frame into a single DMA/RXWI segment.
    fn segment(payload: &[u8]) -> Vec<u8> {
        let dma_len = (rx::MIN_SEG_LEN + payload.len()).next_multiple_of(4);
        let mut seg = vec![0u8; dma::MT_DMA_HDRS + dma_len];
        seg[..2].copy_from_slice(&(dma_len as u16).to_le_bytes());
        seg[4 + rx::RXWI_LEN..4 + rx::RXWI_LEN + payload.len()].copy_from_slice(payload);
        seg
    }

    fn management(subtype: u8, to: [u8; 6], from: [u8; 6], bssid: [u8; 6], body: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 24];
        frame[0..2].copy_from_slice(&(u16::from(subtype) << 4).to_le_bytes());
        frame[4..10].copy_from_slice(&to);
        frame[10..16].copy_from_slice(&from);
        frame[16..22].copy_from_slice(&bssid);
        frame.extend_from_slice(body);
        frame
    }

    fn auth_response(status: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&mgmt::AUTH_ALG_OPEN.to_le_bytes());
        body.extend_from_slice(&mgmt::AUTH_SEQ_RESPONSE.to_le_bytes());
        body.extend_from_slice(&status.to_le_bytes());
        management(11, OUR, AP, AP, &body)
    }

    fn assoc_response(status: u16, aid: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&CAPABILITY_ESS.to_le_bytes());
        body.extend_from_slice(&status.to_le_bytes());
        body.extend_from_slice(&aid.to_le_bytes());
        management(1, OUR, AP, AP, &body)
    }

    fn bulk_out_endpoints(chip: &Mt7601u<MockTransport>) -> Vec<u8> {
        chip.transport()
            .bulk_writes
            .borrow()
            .iter()
            .map(|(endpoint, _)| *endpoint)
            .collect()
    }

    #[test]
    fn infrastructure_target_sets_the_ess_bit_and_defaults() {
        let target = BssTarget::infrastructure("x".into(), AP, 6, 0);
        assert!(target.is_infrastructure());
        assert_eq!(target.capability & CAPABILITY_ESS, CAPABILITY_ESS);
        assert_eq!(target.basic_rates, BASIC_RATES_BG);
        assert_eq!(target.beacon_interval, DEFAULT_BEACON_INTERVAL);
    }

    #[test]
    fn ibss_target_is_rejected() {
        assert!(!BssTarget::infrastructure("x".into(), AP, 6, CAPABILITY_IBSS).is_infrastructure());
    }

    #[test]
    fn associate_succeeds_and_transmits_auth_then_assoc() {
        let mock = MockTransport::default();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(0, 0x0042)));
        let chip = Mt7601u::new(mock, device_info());

        let result = associate(&chip, &eeprom(), &target()).unwrap();
        assert_eq!(result.aid, 0x0042);

        // Two management frames went out on the AC_BE bulk OUT endpoint.
        assert_eq!(bulk_out_endpoints(&chip), vec![0x05, 0x05]);
    }

    #[test]
    fn associate_programs_the_bssid_and_wcid() {
        let mock = MockTransport::default();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(0, 1)));
        let chip = Mt7601u::new(mock, device_info());
        associate(&chip, &eeprom(), &target()).unwrap();

        let calls = chip.transport().calls();
        let bssid_written = calls.iter().any(|call| {
            matches!(call, Call::Out { index, .. }
                if *index == crate::mt7601u::regs::MT_MAC_BSSID_DW0 as u16)
        });
        assert!(bssid_written, "BSSID register was not programmed");
        let wcid_attr = crate::mt7601u::regs::mt_wcid_attr(GROUP_WCID_0) as u16;
        assert!(
            calls
                .iter()
                .any(|call| matches!(call, Call::Out { index, .. } if *index == wcid_attr)),
            "group WCID attribute was not programmed"
        );
        let station_attr = crate::mt7601u::regs::mt_wcid_attr(STA_WCID) as u16;
        assert!(
            calls
                .iter()
                .any(|call| matches!(call, Call::Out { index, .. } if *index == station_attr)),
            "station WCID attribute was not programmed"
        );
        // Our own address goes into a WCID entry, so the hardware can find the
        // pairwise key for a unicast frame addressed to us.
        let own_addr = crate::mt7601u::regs::mt_wcid_addr(OWN_WCID) as u16;
        assert!(
            calls.iter().any(|call| matches!(
                call,
                Call::Out { value, index, .. } if *index == own_addr && *value == 0x8288
            )),
            "own-address WCID was not programmed with our MAC"
        );
    }

    #[test]
    fn associate_reports_authentication_failure() {
        let mock = MockTransport::default();
        mock.push_rx_frame(segment(&auth_response(1)));
        let chip = Mt7601u::new(mock, device_info());

        let error = associate(&chip, &eeprom(), &target()).unwrap_err();
        assert!(
            error.to_string().contains("authentication rejected"),
            "{error}"
        );
    }

    #[test]
    fn associate_reports_association_failure() {
        let mock = MockTransport::default();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(17, 0)));
        let chip = Mt7601u::new(mock, device_info());

        let error = associate(&chip, &eeprom(), &target()).unwrap_err();
        assert!(
            error.to_string().contains("association rejected"),
            "{error}"
        );
    }

    #[test]
    fn associate_ignores_frames_addressed_elsewhere() {
        let mock = MockTransport::default();
        // An auth response for a different station, then the correct one.
        mock.push_rx_frame(segment(&management(
            11,
            [0xaa; 6],
            AP,
            AP,
            &[0, 0, 2, 0, 0, 0],
        )));
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(0, 7)));
        let chip = Mt7601u::new(mock, device_info());

        let result = associate(&chip, &eeprom(), &target()).unwrap();
        assert_eq!(result.aid, 7);
    }

    #[test]
    fn associate_rejects_an_overlong_ssid() {
        let mock = MockTransport::default();
        let chip = Mt7601u::new(mock, device_info());
        let mut target = target();
        target.ssid = "x".repeat(33);

        let error = associate(&chip, &eeprom(), &target).unwrap_err();
        assert!(error.to_string().contains("maximum 32"), "{error}");
        // No hardware access happened.
        assert!(chip.transport().bulk_writes.borrow().is_empty());
    }

    #[test]
    fn associate_rejects_a_non_infrastructure_target() {
        let mock = MockTransport::default();
        let chip = Mt7601u::new(mock, device_info());
        let mut target = target();
        target.capability = CAPABILITY_IBSS;

        let error = associate(&chip, &eeprom(), &target).unwrap_err();
        assert!(error.to_string().contains("infrastructure"), "{error}");
    }

    // --- WPA2 ---

    const SNONCE: [u8; 32] = [
        0x0e, 0x1f, 0x22, 0x45, 0x6d, 0x4e, 0x1a, 0x0f, 0xf4, 0x12, 0x27, 0x5a, 0x1d, 0x1f, 0x2e,
        0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x01, 0x23,
    ];
    const ANONCE: [u8; 32] = [
        0x7e, 0xf8, 0x3a, 0xa0, 0x63, 0xcb, 0xcf, 0xd4, 0xf6, 0x5f, 0x85, 0x32, 0x42, 0x3a, 0x11,
        0x2f, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
        0x01, 0x23,
    ];
    const PASSPHRASE: &[u8] = b"password";

    /// An AP → station data frame wrapping `payload`.
    fn ap_data_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let frame_control: u16 = (2 << 2) | 0x0200; // type data, FromDS
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_control.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&OUR); // Address 1 (receiver)
        frame.extend_from_slice(&AP); // Address 2 (transmitter)
        frame.extend_from_slice(&AP); // Address 3 (source)
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// RFC 3394 AES key wrap (test-only).
    fn wrap(kek: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
        use aes::Aes128;

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
    fn associate_wpa2_runs_the_handshake_and_installs_keys() {
        let target = target();
        let pmk = crate::wifi::wpa::pmk(PASSPHRASE, target.ssid.as_bytes());
        let ptk = crate::wifi::wpa::ptk(&pmk, &AP, &OUR, &ANONCE, &SNONCE);

        let msg1 = crate::wifi::eapol::build(
            crate::wifi::eapol::KEY_INFO_VERSION2
                | crate::wifi::eapol::KEY_INFO_PAIRWISE
                | crate::wifi::eapol::KEY_INFO_ACK,
            1,
            &ANONCE,
            &[],
            None,
        );
        let mut gtk_kde = vec![0xdd, 0x0e, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00];
        gtk_kde.extend_from_slice(&[0xcd; 8]);
        let msg3 = crate::wifi::eapol::build(
            crate::wifi::eapol::KEY_INFO_VERSION2
                | crate::wifi::eapol::KEY_INFO_PAIRWISE
                | crate::wifi::eapol::KEY_INFO_INSTALL
                | crate::wifi::eapol::KEY_INFO_ACK
                | crate::wifi::eapol::KEY_INFO_MIC
                | crate::wifi::eapol::KEY_INFO_SECURE
                | crate::wifi::eapol::KEY_INFO_ENCRYPTED,
            2,
            &ANONCE,
            &wrap(&ptk.kek, &gtk_kde),
            Some(&ptk.kck),
        );

        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(0, 0x1234)));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg1,
        )));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg3,
        )));
        let chip = Mt7601u::new(mock, device_info());

        let result = associate_wpa2(&chip, &eeprom(), &target, PASSPHRASE, SNONCE).unwrap();
        assert_eq!(result.aid, 0x1234);

        // Both EAPOL replies (message 2 and 4) went out.
        let eapol_frames = chip
            .transport()
            .bulk_writes
            .borrow()
            .iter()
            .filter(|(_, buffer)| buffer.get(54..56) == Some(&[0x88, 0x8e][..]))
            .count();
        assert_eq!(eapol_frames, 2, "expected message 2 and message 4");

        // Every handshake EAPOL frame goes out unencrypted. The AP installs the
        // PTK for RX only once it accepts our 4/4, so it cannot decrypt a
        // Protected 4/4 — it would drop it and keep retransmitting 3/4, which
        // is exactly the "connected but never registered" failure.
        for (_, buffer) in chip.transport().bulk_writes.borrow().iter() {
            if buffer.get(54..56) == Some(&[0x88, 0x8e][..]) {
                let frame_control = u16::from_le_bytes([buffer[24], buffer[25]]);
                assert_eq!(
                    frame_control & 0x4000,
                    0,
                    "a 4-way handshake EAPOL frame must not be Protected"
                );
            }
        }

        // The pairwise key (TK) sits on the AP's station WCID with the PAIRWISE
        // flag, so unicast frames are encrypted with it.
        let regs = crate::mt7601u::regs::mt_wcid_attr as fn(u8) -> u32;
        let cipher = u32::from(crate::mt7601u::regs::MT_CIPHER_AES_CCMP)
            << crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE_SHIFT;
        let calls = chip.transport().calls();
        let attr_value = |index: u8| -> Option<u32> {
            calls.iter().rev().find_map(|call| match call {
                Call::Out {
                    value, index: at, ..
                } if *at == regs(index) as u16 => Some(u32::from(*value)),
                _ => None,
            })
        };

        let pairwise = attr_value(STA_WCID).expect("station WCID attribute");
        assert_ne!(pairwise & crate::mt7601u::regs::MT_WCID_ATTR_PAIRWISE, 0);
        assert_eq!(
            pairwise & crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE,
            cipher
        );

        // The same pairwise key sits on the entry that carries our own address,
        // so a unicast frame addressed to us can be decrypted.
        let own = attr_value(OWN_WCID).expect("own-address WCID attribute");
        assert_ne!(own & crate::mt7601u::regs::MT_WCID_ATTR_PAIRWISE, 0);
        assert_eq!(own & crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE, cipher);

        // The group key (GTK) sits on the group WCID *without* the PAIRWISE
        // flag, so broadcast/multicast frames are encrypted with it.
        let group = attr_value(GROUP_WCID_0).expect("group WCID attribute");
        assert_eq!(group & crate::mt7601u::regs::MT_WCID_ATTR_PAIRWISE, 0);
        assert_eq!(group & crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE, cipher);
    }

    #[test]
    fn associate_wpa1_runs_the_four_way_and_the_group_handshake() {
        let target = target();
        let pmk = crate::wifi::wpa::pmk(PASSPHRASE, target.ssid.as_bytes());
        let ptk = crate::wifi::wpa::ptk_tkip(&pmk, &AP, &OUR, &ANONCE, &SNONCE);

        let msg1 = crate::wifi::eapol::build_key(
            &crate::wifi::eapol::EapolKeyFrame {
                descriptor: crate::wifi::eapol::DESCRIPTOR_WPA,
                key_info: crate::wifi::eapol::KEY_INFO_VERSION1
                    | crate::wifi::eapol::KEY_INFO_PAIRWISE
                    | crate::wifi::eapol::KEY_INFO_ACK,
                key_length: 32,
                replay: 1,
                nonce: &ANONCE,
                key_iv: &[0u8; 16],
                key_data: &[],
            },
            None,
        );
        let msg3 = crate::wifi::eapol::build_key(
            &crate::wifi::eapol::EapolKeyFrame {
                descriptor: crate::wifi::eapol::DESCRIPTOR_WPA,
                key_info: crate::wifi::eapol::KEY_INFO_VERSION1
                    | crate::wifi::eapol::KEY_INFO_PAIRWISE
                    | crate::wifi::eapol::KEY_INFO_ACK
                    | crate::wifi::eapol::KEY_INFO_MIC
                    | crate::wifi::eapol::KEY_INFO_INSTALL,
                key_length: 32,
                replay: 2,
                nonce: &ANONCE,
                key_iv: &[0u8; 16],
                key_data: &crate::wifi::rsn::build_wpa1_psk_tkip(),
            },
            Some(&ptk.kck),
        );

        let gtk = [0xab; 32];
        let key_iv = [0x11; 16];
        let mut ek = [0u8; 32];
        ek[..16].copy_from_slice(&key_iv);
        ek[16..].copy_from_slice(&ptk.kek);
        let encrypted = crate::wifi::wpa::rc4_skip(&ek, 256, &gtk);
        let group1 = crate::wifi::eapol::build_key(
            &crate::wifi::eapol::EapolKeyFrame {
                descriptor: crate::wifi::eapol::DESCRIPTOR_WPA,
                key_info: crate::wifi::eapol::KEY_INFO_VERSION1
                    | crate::wifi::eapol::KEY_INFO_ACK
                    | crate::wifi::eapol::KEY_INFO_MIC
                    | crate::wifi::eapol::KEY_INFO_SECURE
                    | crate::wifi::eapol::KEY_INFO_INSTALL
                    | (1 << 4),
                key_length: 32,
                replay: 3,
                nonce: &[0u8; 32],
                key_iv: &key_iv,
                key_data: &encrypted,
            },
            Some(&ptk.kck),
        );

        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(0, 0x1234)));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg1,
        )));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg3,
        )));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &group1,
        )));
        let chip = Mt7601u::new(mock, device_info());

        let result = associate_wpa1(&chip, &eeprom(), &target, PASSPHRASE, SNONCE).unwrap();
        assert_eq!(result.aid, 0x1234);
        assert!(result.handshake_confirmed);

        // Message 2/4, message 4/4 and the group 2/2 went out.
        let eapol_frames = chip
            .transport()
            .bulk_writes
            .borrow()
            .iter()
            .filter(|(_, buffer)| buffer.get(54..56) == Some(&[0x88, 0x8e][..]))
            .count();
        assert_eq!(eapol_frames, 3, "expected message 2, message 4 and 2/2");

        // Both keys are TKIP: the pairwise TK on the AP's station WCID and the
        // group key on the group WCID.
        let regs = crate::mt7601u::regs::mt_wcid_attr as fn(u8) -> u32;
        let cipher = u32::from(crate::mt7601u::regs::MT_CIPHER_TKIP)
            << crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE_SHIFT;
        let calls = chip.transport().calls();
        let attr_value = |index: u8| -> Option<u32> {
            calls.iter().rev().find_map(|call| match call {
                Call::Out {
                    value, index: at, ..
                } if *at == regs(index) as u16 => Some(u32::from(*value)),
                _ => None,
            })
        };

        let pairwise = attr_value(STA_WCID).expect("station WCID attribute");
        assert_ne!(pairwise & crate::mt7601u::regs::MT_WCID_ATTR_PAIRWISE, 0);
        assert_eq!(
            pairwise & crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE,
            cipher
        );

        let group = attr_value(GROUP_WCID_0).expect("group WCID attribute");
        assert_eq!(group & crate::mt7601u::regs::MT_WCID_ATTR_PAIRWISE, 0);
        assert_eq!(group & crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE, cipher);
    }

    #[test]
    fn associate_wpa1_confirms_without_a_group_handshake() {
        // hostapd does not start the group handshake when the AP's GTK is
        // already known to the supplicant (e.g. it stayed set from a previous
        // association); the link is still usable for unicast traffic.
        let target = target();
        let pmk = crate::wifi::wpa::pmk(PASSPHRASE, target.ssid.as_bytes());
        let ptk = crate::wifi::wpa::ptk_tkip(&pmk, &AP, &OUR, &ANONCE, &SNONCE);

        let msg1 = crate::wifi::eapol::build_key(
            &crate::wifi::eapol::EapolKeyFrame {
                descriptor: crate::wifi::eapol::DESCRIPTOR_WPA,
                key_info: crate::wifi::eapol::KEY_INFO_VERSION1
                    | crate::wifi::eapol::KEY_INFO_PAIRWISE
                    | crate::wifi::eapol::KEY_INFO_ACK,
                key_length: 32,
                replay: 1,
                nonce: &ANONCE,
                key_iv: &[0u8; 16],
                key_data: &[],
            },
            None,
        );
        let msg3 = crate::wifi::eapol::build_key(
            &crate::wifi::eapol::EapolKeyFrame {
                descriptor: crate::wifi::eapol::DESCRIPTOR_WPA,
                key_info: crate::wifi::eapol::KEY_INFO_VERSION1
                    | crate::wifi::eapol::KEY_INFO_PAIRWISE
                    | crate::wifi::eapol::KEY_INFO_ACK
                    | crate::wifi::eapol::KEY_INFO_MIC
                    | crate::wifi::eapol::KEY_INFO_INSTALL,
                key_length: 32,
                replay: 2,
                nonce: &ANONCE,
                key_iv: &[0u8; 16],
                key_data: &crate::wifi::rsn::build_wpa1_psk_tkip(),
            },
            Some(&ptk.kck),
        );

        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(0, 1)));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg1,
        )));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg3,
        )));
        let chip = Mt7601u::new(mock, device_info());

        let result = associate_wpa1(&chip, &eeprom(), &target, PASSPHRASE, SNONCE).unwrap();
        assert!(result.handshake_confirmed);

        // The pairwise key was installed, but nothing was written to the group
        // WCID (there is no GTK to install).
        let regs = crate::mt7601u::regs::mt_wcid_attr as fn(u8) -> u32;
        let calls = chip.transport().calls();
        let attr_value = |index: u8| -> Option<u32> {
            calls.iter().rev().find_map(|call| match call {
                Call::Out {
                    value, index: at, ..
                } if *at == regs(index) as u16 => Some(u32::from(*value)),
                _ => None,
            })
        };
        let pairwise = attr_value(STA_WCID).expect("station WCID attribute");
        assert_ne!(pairwise & crate::mt7601u::regs::MT_WCID_ATTR_PAIRWISE, 0);

        // The group WCID attribute was (re)programmed during association, but
        // no cipher was ever installed there: PKEY_MODE is still NONE.
        let group_cipher = attr_value(GROUP_WCID_0).map_or(0, |value| {
            value & crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE
        });
        assert_eq!(group_cipher, 0, "no group key should be programmed");
    }

    #[test]
    fn associate_wpa2_reports_unconfirmed_when_the_ap_keeps_retransmitting() {
        // The AP answers every 4/4 with a fresh 3/4 (a new replay counter): it
        // never accepts our reply, so it never registers the station. This is
        // the failure the tunnel refusal is built on.
        let target = target();
        let pmk = crate::wifi::wpa::pmk(PASSPHRASE, target.ssid.as_bytes());
        let ptk = crate::wifi::wpa::ptk(&pmk, &AP, &OUR, &ANONCE, &SNONCE);

        let msg1 = crate::wifi::eapol::build(
            crate::wifi::eapol::KEY_INFO_VERSION2
                | crate::wifi::eapol::KEY_INFO_PAIRWISE
                | crate::wifi::eapol::KEY_INFO_ACK,
            1,
            &ANONCE,
            &[],
            None,
        );
        let mut gtk_kde = vec![0xdd, 0x0e, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00];
        gtk_kde.extend_from_slice(&[0xcd; 8]);
        let wrapped = wrap(&ptk.kek, &gtk_kde);

        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(0, 1)));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg1,
        )));
        for replay in 2..(u64::from(MAX_EAPOL_STEPS) + 4) {
            let msg3 = crate::wifi::eapol::build(
                crate::wifi::eapol::KEY_INFO_VERSION2
                    | crate::wifi::eapol::KEY_INFO_PAIRWISE
                    | crate::wifi::eapol::KEY_INFO_INSTALL
                    | crate::wifi::eapol::KEY_INFO_ACK
                    | crate::wifi::eapol::KEY_INFO_MIC
                    | crate::wifi::eapol::KEY_INFO_SECURE
                    | crate::wifi::eapol::KEY_INFO_ENCRYPTED,
                replay,
                &ANONCE,
                &wrapped,
                Some(&ptk.kck),
            );
            mock.push_rx_frame(segment(&ap_data_frame(
                crate::wifi::eapol::ETHERTYPE_EAPOL,
                &msg3,
            )));
        }
        let chip = Mt7601u::new(mock, device_info());

        let result = associate_wpa2(&chip, &eeprom(), &target, PASSPHRASE, SNONCE).unwrap();
        assert!(
            !result.handshake_confirmed,
            "an AP that never stops retransmitting 3/4 did not register the station"
        );
    }

    #[test]
    fn associate_wpa2_times_out_without_eapol() {
        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&assoc_response(0, 1)));
        let chip = Mt7601u::new(mock, device_info());

        let error = associate_wpa2(&chip, &eeprom(), &target(), PASSPHRASE, SNONCE)
            .expect_err("should time out");
        assert!(error.to_string().contains("EAPOL"), "{error}");
    }

    // --- WPA3 (SAE) ---

    const RAND_A: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00,
    ];
    const MASK_A: [u8; 32] = [
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11,
    ];
    const RAND_B: [u8; 32] = [0x55; 32];
    const MASK_B: [u8; 32] = [0x66; 32];

    /// The AP side of the SAE exchange, played by a `SaeExchange` with the
    /// roles swapped, precomputed against our (fixed) commit.
    fn ap_exchange() -> sae::SaeExchange {
        let sta = sae::SaeExchange::new(PASSPHRASE, OUR, AP, RAND_A, MASK_A).unwrap();
        let mut ap = sae::SaeExchange::new(PASSPHRASE, AP, OUR, RAND_B, MASK_B).unwrap();
        ap.process_commit(&sta.commit_body()).unwrap();
        ap
    }

    fn sae_auth_response(sequence: u16, status: u16, body: &[u8]) -> Vec<u8> {
        let mut frame_body = Vec::new();
        frame_body.extend_from_slice(&mgmt::AUTH_ALG_SAE.to_le_bytes());
        frame_body.extend_from_slice(&sequence.to_le_bytes());
        frame_body.extend_from_slice(&status.to_le_bytes());
        frame_body.extend_from_slice(body);
        management(11, OUR, AP, AP, &frame_body)
    }

    /// True when one of our bulk-OUT transfers contains `needle`.
    fn transmitted(chip: &Mt7601u<MockTransport>, needle: &[u8]) -> bool {
        chip.transport()
            .bulk_writes
            .borrow()
            .iter()
            .any(|(_, buffer)| buffer.windows(needle.len()).any(|window| window == needle))
    }

    #[test]
    fn associate_sae_runs_the_auth_exchange_and_installs_keys() {
        let target = target();
        let ap = ap_exchange();
        let ap_commit = ap.commit_body();
        let ap_confirm = ap.confirm_body().unwrap();

        // Our side, exactly as `associate_sae` will replay it.
        let mut sta = sae::SaeExchange::new(PASSPHRASE, OUR, AP, RAND_A, MASK_A).unwrap();
        let sta_commit = sta.commit_body();
        sta.process_commit(&ap_commit).unwrap();
        let sta_confirm = sta.confirm_body().unwrap();
        let pmk = sta.pmk().unwrap();
        assert_eq!(pmk, ap.pmk().unwrap().as_slice());

        let ptk = crate::wifi::wpa::ptk_sae(&pmk, &AP, &OUR, &ANONCE, &SNONCE);
        let msg1 = crate::wifi::eapol::build(
            crate::wifi::eapol::KEY_INFO_VERSION2
                | crate::wifi::eapol::KEY_INFO_PAIRWISE
                | crate::wifi::eapol::KEY_INFO_ACK,
            1,
            &ANONCE,
            &[],
            None,
        );
        let mut gtk_kde = vec![0xdd, 0x0e, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00];
        gtk_kde.extend_from_slice(&[0xcd; 8]);
        let msg3 = crate::wifi::eapol::build(
            crate::wifi::eapol::KEY_INFO_VERSION2
                | crate::wifi::eapol::KEY_INFO_PAIRWISE
                | crate::wifi::eapol::KEY_INFO_INSTALL
                | crate::wifi::eapol::KEY_INFO_ACK
                | crate::wifi::eapol::KEY_INFO_MIC
                | crate::wifi::eapol::KEY_INFO_SECURE
                | crate::wifi::eapol::KEY_INFO_ENCRYPTED,
            2,
            &ANONCE,
            &wrap(&ptk.kek, &gtk_kde),
            Some(&ptk.kck),
        );

        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&sae_auth_response(1, 0, &ap_commit)));
        mock.push_rx_frame(segment(&sae_auth_response(2, 0, &ap_confirm)));
        mock.push_rx_frame(segment(&assoc_response(0, 0x1234)));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg1,
        )));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg3,
        )));
        let chip = Mt7601u::new(mock, device_info());

        let result = associate_sae(
            &chip,
            &eeprom(),
            &target,
            PASSPHRASE,
            SNONCE,
            RAND_A,
            MASK_A,
        )
        .unwrap();
        assert_eq!(result.aid, 0x1234);
        assert!(result.handshake_confirmed);

        // Our commit and confirm went out on the air, the confirm matching the
        // HMAC over the exchange state.
        assert!(
            transmitted(&chip, &frames::auth_sae(OUR, AP, 1, 0, &sta_commit)),
            "the SAE commit was not transmitted"
        );
        assert!(
            transmitted(&chip, &frames::auth_sae(OUR, AP, 2, 0, &sta_confirm)),
            "the SAE confirm was not transmitted"
        );

        // The 4-way replies (2/4 and 4/4) went out.
        let eapol_frames = chip
            .transport()
            .bulk_writes
            .borrow()
            .iter()
            .filter(|(_, buffer)| buffer.get(54..56) == Some(&[0x88, 0x8e][..]))
            .count();
        assert_eq!(eapol_frames, 2, "expected message 2 and message 4");

        // The pairwise CCMP key sits on the AP's station WCID and the GTK on
        // the group WCID.
        let regs = crate::mt7601u::regs::mt_wcid_attr as fn(u8) -> u32;
        let cipher = u32::from(crate::mt7601u::regs::MT_CIPHER_AES_CCMP)
            << crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE_SHIFT;
        let calls = chip.transport().calls();
        let attr_value = |index: u8| -> Option<u32> {
            calls.iter().rev().find_map(|call| match call {
                Call::Out {
                    value, index: at, ..
                } if *at == regs(index) as u16 => Some(u32::from(*value)),
                _ => None,
            })
        };
        let pairwise = attr_value(STA_WCID).expect("station WCID attribute");
        assert_ne!(pairwise & crate::mt7601u::regs::MT_WCID_ATTR_PAIRWISE, 0);
        assert_eq!(
            pairwise & crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE,
            cipher
        );
        let group = attr_value(GROUP_WCID_0).expect("group WCID attribute");
        assert_eq!(group & crate::mt7601u::regs::MT_WCID_ATTR_PKEY_MODE, cipher);
    }

    #[test]
    fn associate_sae_echoes_the_anti_clogging_token() {
        // hostapd answers a commit with status 76 when it wants a token; the
        // same commit is replayed with the token appended at the end.
        let target = target();
        let ap = ap_exchange();
        let ap_commit = ap.commit_body();
        let ap_confirm = ap.confirm_body().unwrap();

        let mut sta = sae::SaeExchange::new(PASSPHRASE, OUR, AP, RAND_A, MASK_A).unwrap();
        sta.process_commit(&ap_commit).unwrap();
        let pmk = sta.pmk().unwrap();

        let ptk = crate::wifi::wpa::ptk_sae(&pmk, &AP, &OUR, &ANONCE, &SNONCE);
        let msg1 = crate::wifi::eapol::build(
            crate::wifi::eapol::KEY_INFO_VERSION2
                | crate::wifi::eapol::KEY_INFO_PAIRWISE
                | crate::wifi::eapol::KEY_INFO_ACK,
            1,
            &ANONCE,
            &[],
            None,
        );
        let mut gtk_kde = vec![0xdd, 0x0e, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00];
        gtk_kde.extend_from_slice(&[0xcd; 8]);
        let msg3 = crate::wifi::eapol::build(
            crate::wifi::eapol::KEY_INFO_VERSION2
                | crate::wifi::eapol::KEY_INFO_PAIRWISE
                | crate::wifi::eapol::KEY_INFO_INSTALL
                | crate::wifi::eapol::KEY_INFO_ACK
                | crate::wifi::eapol::KEY_INFO_MIC
                | crate::wifi::eapol::KEY_INFO_SECURE
                | crate::wifi::eapol::KEY_INFO_ENCRYPTED,
            2,
            &ANONCE,
            &wrap(&ptk.kek, &gtk_kde),
            Some(&ptk.kck),
        );

        let token = [0xd7; 12];
        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&sae_auth_response(
            1,
            mgmt::STATUS_ANTI_CLOGGING_TOKEN_REQ,
            &token,
        )));
        mock.push_rx_frame(segment(&sae_auth_response(1, 0, &ap_commit)));
        mock.push_rx_frame(segment(&sae_auth_response(2, 0, &ap_confirm)));
        mock.push_rx_frame(segment(&assoc_response(0, 0x1234)));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg1,
        )));
        mock.push_rx_frame(segment(&ap_data_frame(
            crate::wifi::eapol::ETHERTYPE_EAPOL,
            &msg3,
        )));
        let chip = Mt7601u::new(mock, device_info());

        let result = associate_sae(
            &chip,
            &eeprom(),
            &target,
            PASSPHRASE,
            SNONCE,
            RAND_A,
            MASK_A,
        )
        .unwrap();
        assert!(result.handshake_confirmed);

        // The retried commit carries the same commit bytes plus the token.
        let sta = sae::SaeExchange::new(PASSPHRASE, OUR, AP, RAND_A, MASK_A).unwrap();
        let mut retried = sta.commit_body().to_vec();
        retried.extend_from_slice(&token);
        assert!(
            transmitted(&chip, &frames::auth_sae(OUR, AP, 1, 0, &retried)),
            "the commit was not replayed with the anti-clogging token"
        );
    }

    #[test]
    fn associate_sae_reports_an_unsupported_group() {
        let mock = MockTransport::default();
        mock.ack_mcu_commands();
        mock.push_rx_frame(segment(&auth_response(0)));
        mock.push_rx_frame(segment(&sae_auth_response(
            1,
            mgmt::STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED,
            &[],
        )));
        let chip = Mt7601u::new(mock, device_info());

        let error = associate_sae(
            &chip,
            &eeprom(),
            &target(),
            PASSPHRASE,
            SNONCE,
            RAND_A,
            MASK_A,
        )
        .expect_err("group 19 is not supported by this AP");
        assert!(error.to_string().contains("P-256"), "{error}");
    }
}
