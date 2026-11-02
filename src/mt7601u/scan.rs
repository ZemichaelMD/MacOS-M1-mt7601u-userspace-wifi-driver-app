//! Bring-up + passive scan.
//!
//! The Linux driver uses `sw_scan`: mac80211 switches channels and the driver
//! only saves/restores AGC (`mt7601u_sw_scan` / `mt7601u_sw_scan_complete`).
//! Here the same effect is achieved by bringing the radio up, setting each
//! channel and reading bulk-IN segments for a short dwell.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::usb::{Transport, UsbError};
use crate::wifi::{rsn, Network, Security};

use super::device::Mt7601u;
use super::eeprom::Eeprom;
use super::radio::RadioState;
use super::rx;

/// Read buffer for one bulk-IN transfer (`MT_RX_URB_SIZE`, 16 KiB).
const RX_BUFFER_LEN: usize = 16384;

/// Default per-channel dwell for a scan.
pub const DEFAULT_DWELL: Duration = Duration::from_millis(200);

/// A recovery hint for errors that mean the MCU in-band command channel has
/// stopped responding.
///
/// This is the failure documented in `HANDOVER.md` §3: a wedged device (one
/// that `libusb_reset_device` was called on, or that another program is holding
/// open) leaves the MCU command path stuck. Plain control transfers still work,
/// so the USB layer looks healthy — only MCU commands time out, and only a
/// physical replug clears it.
///
/// Reopening the device is *not* one of these cases any more: `bringup` re-arms
/// the USB DMA path the MCU channel rides (see the non-fresh branch below), so
/// Stop → Start and a rescan work without a replug.
pub fn mcu_recovery_hint(error: &UsbError) -> Option<&'static str> {
    let text = error.to_string();
    let stuck = text.contains("MCU response")
        || text.contains("Operation timed out")
        || text.contains("timeout polling");
    stuck.then_some(
        "the MCU command channel is not responding. Unplug and replug the MT7601U, then \
         reopen it — and make sure no other program (another app or CLI run) has the device \
         open at the same time",
    )
}

/// Security derived from a beacon (`capability` privacy bit + RSN/WPA IEs).
///
/// An RSN IE that advertises SAE *without* PSK is WPA3 (SAE is the only way
/// in); one that advertises both (transition mode) is joined with the WPA2-PSK
/// path, which needs no SAE exchange.
pub fn security(bss: &rx::BssInfo) -> Security {
    if bss.has_rsn {
        let pure_sae = bss
            .rsn_ie
            .as_deref()
            .and_then(rsn::parse)
            .is_some_and(|info| info.supports_sae_ccmp() && !info.supports_psk_ccmp());
        if pure_sae {
            Security::Wpa3
        } else {
            Security::Wpa2
        }
    } else if bss.has_wpa {
        Security::Wpa
    } else if bss.capability & 0x0010 != 0 {
        // Privacy bit set but no RSN/WPA IE: legacy WEP or unknown.
        Security::Unknown
    } else {
        Security::Open
    }
}

fn to_network(bss: &rx::BssInfo) -> Network {
    Network {
        ssid: bss.ssid.clone(),
        bssid: Some(bss.bssid),
        signal_dbm: None,
        channel: bss.channel,
        security: security(bss),
    }
}

/// Hop every channel in the EEPROM's region and collect beacons/probe responses.
pub fn passive_scan<T: Transport>(
    chip: &Mt7601u<T>,
    eeprom: &Eeprom,
    state: &mut RadioState,
    per_channel: Duration,
) -> Result<Vec<Network>, UsbError> {
    let saved_agc = chip
        .agc_save()
        .map_err(|error| UsbError::Other(format!("agc save: {error}")))?;
    chip.mac_start()
        .map_err(|error| UsbError::Other(format!("mac start: {error}")))?;

    let endpoint = chip.rx_endpoint()?;
    let mut buffer = vec![0u8; RX_BUFFER_LEN];
    let mut found: BTreeMap<[u8; 6], rx::BssInfo> = BTreeMap::new();

    for channel in eeprom.channels() {
        chip.phy_set_channel(eeprom, state, channel)
            .map_err(|error| UsbError::Other(format!("set channel {channel}: {error}")))?;
        chip.agc_reset(eeprom.lna_gain)
            .map_err(|error| UsbError::Other(format!("agc reset on channel {channel}: {error}")))?;

        let deadline = Instant::now() + per_channel;
        while Instant::now() < deadline {
            match chip
                .transport()
                .bulk_in(endpoint, &mut buffer, Duration::from_millis(30))
            {
                Ok(len) if len >= 2 => {
                    for segment in rx::parse_segments(&buffer[..len]) {
                        if segment.rxwi.is_crc_error() {
                            continue;
                        }
                        if let Some(bss) = rx::parse_beacon(segment.payload) {
                            found.entry(bss.bssid).or_insert(bss);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    chip.agc_restore(saved_agc)
        .map_err(|error| UsbError::Other(format!("agc restore: {error}")))?;

    Ok(found.values().map(to_network).collect())
}

/// Bring the radio up: clock, firmware, post-firmware init, MAC/BBP initvals,
/// EEPROM and RF calibration.
///
/// Returns the EEPROM plus the mutable radio state needed for channel switching.
pub fn bringup<T: Transport>(
    chip: &Mt7601u<T>,
    firmware: Option<&Path>,
) -> Result<(Eeprom, RadioState), UsbError> {
    tracing::info!("enabling the WLAN clock");
    chip.chip_onoff(true, false)?;

    let fresh = !chip.firmware_running()?;

    if fresh {
        let path = firmware.ok_or_else(|| {
            UsbError::Other(
                "firmware not found (set MT7601U_FIRMWARE or place mt7601u.bin)".to_string(),
            )
        })?;
        let data = std::fs::read(path)
            .map_err(|error| UsbError::Other(format!("cannot read {}: {error}", path.display())))?;
        tracing::info!("uploading firmware from {}", path.display());
        chip.load_firmware(&data)?;
    } else {
        // The firmware is still running: a previous session left the device up
        // (an earlier `--scan`, or the GUI's Stop → Start). Everything below runs
        // on that device too, so that a reopen converges on the same fully
        // initialized state a fresh device gets — that is what makes Stop/Start
        // and rescans work without a replug.
        //
        // Only the upload is skipped: its `prepare_firmware_load` sends
        // `MT_VEND_DEV_MODE_RESET`, which is the boot-ROM hand-off and would kill
        // a running MCU. Linux draws the line in the same place — `mt7601u_mcu_init`
        // only loads an image when the firmware is not running, and everything
        // else in `init_hardware` runs on every init, including `resume`.
        tracing::info!("device already initialized; re-initializing the running device");
        chip.enable_usb_dma()?;
        chip.mac_stop();
    }

    tracing::info!("running post-firmware initialization");
    chip.init_after_firmware()?;
    tracing::info!("writing MAC/BBP initvals and memory tables");
    chip.init_radio_registers()?;

    let eeprom = chip.eeprom_init()?;
    tracing::info!("MAC address {}", eeprom.mac_string());

    let mut state = RadioState::default();
    tracing::info!("initializing the RF path");
    chip.phy_init(&eeprom, &mut state)?;
    chip.set_rx_path(0)?;
    chip.set_tx_dac(0)?;

    Ok((eeprom, state))
}

/// Bring the radio up and run a passive scan.
pub fn bringup_and_scan<T: Transport>(
    chip: &Mt7601u<T>,
    firmware: Option<&Path>,
    per_channel: Duration,
) -> Result<Vec<Network>, UsbError> {
    let (eeprom, mut state) = bringup(chip, firmware)?;

    let channels = eeprom.channels();
    tracing::info!(
        "dwelling on channels {}-{} for {} ms each",
        channels.start(),
        channels.end(),
        per_channel.as_millis()
    );
    let networks = passive_scan(chip, &eeprom, &mut state, per_channel)?;
    tracing::info!("scan complete: {} network(s)", networks.len());
    Ok(networks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{device_info, Call, MockTransport};
    use crate::mt7601u::{dma, mcu, regs};

    /// A transport whose firmware is already running, i.e. what an open, close
    /// and reopen of the same device leaves behind. The registers cover the whole
    /// init sequence the reopen now runs.
    fn reopened_device() -> Mt7601u<MockTransport> {
        let mut registers = vec![
            // `MT_MCU_COM_REG0 == 1`: the firmware survived the reopen.
            (regs::MT_MCU_COM_REG0, 1),
            // ASIC ready, both MAC engines idle, WPDMA idle, BBP version 0x05.
            (regs::MT_MAC_CSR0, 1),
            (regs::MT_MAC_STATUS, 0),
            (regs::MT_WPDMA_GLO_CFG, 0),
            (regs::MT_BBP_CSR_CFG, 0x05),
        ];
        // An all-ones eFuse reads as populated: the usage map has no zero bytes,
        // which is what `efuse_physical_size_check` needs to pass.
        for index in 0..4 {
            registers.push((regs::MT_EFUSE_DATA_BASE + index * 4, 0xffff_ffff));
        }

        let mock = MockTransport::with_registers(&registers);
        mock.ack_mcu_commands();
        Mt7601u::new(mock, device_info())
    }

    fn bss(rsn: bool, wpa: bool, capability: u16) -> rx::BssInfo {
        rx::BssInfo {
            bssid: [0; 6],
            ssid: "x".into(),
            channel: None,
            capability,
            beacon_interval: 100,
            has_rsn: rsn,
            has_wpa: wpa,
            rsn_ie: None,
        }
    }

    #[test]
    fn security_labels() {
        assert_eq!(security(&bss(true, false, 0)), Security::Wpa2);
        assert_eq!(security(&bss(false, true, 0)), Security::Wpa);
        assert_eq!(security(&bss(false, false, 0x0010)), Security::Unknown);
        assert_eq!(security(&bss(false, false, 0)), Security::Open);
    }

    #[test]
    fn an_sae_only_rsn_ie_is_wpa3() {
        let mut info = bss(true, false, 0);
        info.rsn_ie = Some(crate::wifi::rsn::build_sae_ccmp());
        assert_eq!(security(&info), Security::Wpa3);
    }

    #[test]
    fn an_sae_and_psk_rsn_ie_stays_wpa2() {
        // Transition mode: the WPA2-PSK path works without an SAE exchange.
        let mut info = bss(true, false, 0);
        let mut ie = crate::wifi::rsn::build_sae_ccmp();
        // Rewrite the AKM count/list to SAE + PSK (both one suite long).
        ie[1] = 24;
        ie[16..18].copy_from_slice(&2u16.to_le_bytes());
        let capabilities = ie.split_off(22);
        ie.extend_from_slice(&[0x00, 0x0f, 0xac, 0x02]);
        ie.extend_from_slice(&capabilities);
        info.rsn_ie = Some(ie);
        assert_eq!(security(&info), Security::Wpa2);
    }

    #[test]
    fn network_mapping_keeps_bssid_and_channel() {
        let mut info = bss(true, false, 0);
        info.bssid = [1, 2, 3, 4, 5, 6];
        info.channel = Some(6);
        let network = to_network(&info);
        assert_eq!(network.bssid, Some([1, 2, 3, 4, 5, 6]));
        assert_eq!(network.channel, Some(6));
        assert_eq!(network.security, Security::Wpa2);
        assert_eq!(network.signal_dbm, None);
    }

    #[test]
    fn reopen_rearms_the_usb_dma_the_mcu_channel_rides_on() {
        let chip = reopened_device();
        bringup(&chip, None).expect("bring-up on an already-running device");

        // The reopened device must get the same `MT_USB_DMA_CFG` the fresh path
        // programs: without it every MCU command times out.
        let expected = regs::MT_USB_AGGR_TIMEOUT
            | (regs::MT_USB_AGGR_SIZE_LIMIT << 8)
            | regs::MT_USB_DMA_CFG_RX_BULK_EN
            | regs::MT_USB_DMA_CFG_TX_BULK_EN
            | regs::MT_USB_DMA_CFG_RX_BULK_AGG_EN;
        let calls = chip.transport().calls();
        assert!(
            calls.iter().any(|call| matches!(
                call,
                Call::Out { value, index, .. }
                    if *index == regs::MT_USB_DMA_CFG as u16 && *value == expected as u16
            )),
            "the USB DMA must be enabled again on reopen"
        );
    }

    #[test]
    fn reopen_brings_the_mcu_channel_up_without_reuploading_firmware() {
        let chip = reopened_device();
        bringup(&chip, None).expect("bring-up on an already-running device");

        // The MCU channel is back: `Q_SELECT` reached the in-band endpoint.
        let writes = chip.transport().bulk_writes.borrow();
        let issued_q_select = writes.iter().any(|(endpoint, buffer)| {
            *endpoint == 0x08
                && buffer.len() >= dma::MT_DMA_HDR_LEN
                && dma::command_id(u32::from_le_bytes([
                    buffer[0], buffer[1], buffer[2], buffer[3],
                ])) == mcu::CMD_FUN_SET_OP
        });
        assert!(issued_q_select, "expected the MCU Q_SELECT command");
        drop(writes);

        // …but the firmware was not re-uploaded: the upload path is the only
        // user of `MT_VEND_WRITE_FCE`, and its `prepare_firmware_load` resets the
        // boot ROM, which would kill the running MCU.
        let firmware_writes = chip
            .transport()
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Out { request, .. } if *request == 0x42))
            .count();
        assert_eq!(firmware_writes, 0, "the firmware must not be re-uploaded");
    }
}
