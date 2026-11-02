# Test plan

## Automated (runnable now)

`cargo test` covers logic that needs no hardware:

| Area | Location |
| --- | --- |
| USB descriptor rendering + serial redaction | `src/usb/enumerate.rs` |
| Device status helpers | `src/usb/enumerate.rs` |
| Device ID matching | `src/mt7601u/mod.rs` |
| Firmware header parsing + validation | `src/mt7601u/firmware.rs` |
| TX/RX DMA framing (info word, buffer layout, response fields) | `src/mt7601u/dma.rs` |
| Register read/write encoding (via mock transport) | `src/mt7601u/device.rs` |
| Identification + ASIC-ready + post-firmware init | `src/mt7601u/device.rs` |
| Firmware upload flow + chunking (via mock transport) | `src/mt7601u/device.rs` |
| MCU command framing, response matching, chunking | `src/mt7601u/mcu.rs` |
| Init table sizes + beacon-offset computation | `src/mt7601u/initvals.rs`, `src/mt7601u/init.rs` |
| Full register-init sequence (via mock transport) | `src/mt7601u/init.rs` |
| eFuse read, s6/region/delta decoding, power-rate table | `src/mt7601u/eeprom.rs` |
| RF table sizes + `int_to_s6`/AGC/channel-plan helpers | `src/mt7601u/rf.rs`, `src/mt7601u/radio.rs` |
| RX segment splitting, RXWI flags, beacon/RSN parsing | `src/mt7601u/rx.rs` |
| Scan security labelling | `src/mt7601u/scan.rs` |
| Reopen re-arms the USB DMA + MCU channel (no firmware re-upload) | `src/mt7601u/scan.rs` |
| Command debug redaction (no password leak) | `src/commands.rs` |
| Wi-Fi state / BSSID formatting | `src/wifi/mod.rs` |
| GUI state transitions + bounded log buffer | `src/app_state.rs` |
| Backend event emission | `src/backend.rs` |
| Network row rendering | `src/app.rs` |
| Public-API integration | `tests/parser_tests.rs` |

Static checks required by the master plan:

```
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Hardware / manual (require the physical dongle)

* [x] Device present → correct VID:PID, bus/address, endpoints (2026-10-15).
* [x] Open + claim interface 0 → succeeds; release + close → clean (2026-10-15).
* [x] `--identify` → ASIC version `0x76010001`, revision `0x0001`,
      MAC CSR0 `0x76010500`, eFuse present (2026-10-15).
* [x] `--load-firmware mt7601u.bin` → MCU reported running; repeatable, ran
      twice (2026-10-15).
* [x] `--init` → post-firmware init + MCU `Q_SELECT` acknowledged
      (`CMD_DONE` response received); repeatable (2026-10-15).
* [x] `--hw-init` → clock enable, MAC/BBP initvals, WCID/key memory, counters all
      complete without timeouts; repeatable (2026-10-15).
* [x] `--read-eeprom` → real eFuse: MAC `88:82:79:24:0e:c0`, EEPROM v0x0d,
      channels 1-14 (2026-10-15).
* [x] `--scan` → **real passive scan**. 7 live networks with SSID/BSSID/channel/
      security, repeatable with run-to-run variation (2026-10-15).
* [ ] **Reopen without a replug**: `--scan`, then `--scan` again (and GUI
      **Stop** → **Start**) → the second run must not fail with
      `set channel 1: MCU response for seq 1 not received`. `bringup` re-arms
      `MT_USB_DMA_CFG` on the second run (`scan.rs`); this is the check that
      proves it, and the escalation path is in `HANDOVER.md` §8 item 2.
* [ ] Device absent → reports "not detected", no crash.
* [ ] Unplug during initialization → handled gracefully (needs live unplug test).
* [ ] Replug → re-detected on Refresh.
* [ ] Interface-claim failure path (simulate by claiming twice).

## Future phases (blocked on implementation)

* `phy_init` (RF tables in `initvals_phy.h`) + RF calibration, `set_rx_path` /
  `set_tx_dac`, `phy_set_channel`, and the RX data path — the remaining path to
  a real scan.
* Scan returns real SSIDs.
* Wrong password / unsupported security mode.
* AP disconnect/reconnect.
* DHCP / DNS / sustained traffic through `utun`.

## Acceptance (from the master plan)

Native build, responsive GUI, real descriptors displayed, repeatable init,
real scan results, secure association, IP/DNS, bidirectional traffic, reliable
reconnect, no credentials in logs, routes restored, and native Wi-Fi claim
either proven against a documented path or marked unsupported.
