# MT7601U Linux driver — source map

Upstream source:
<https://github.com/torvalds/linux/tree/master/drivers/net/wireless/mediatek/mt7601u>

Retrieved: 2026-10-15, `master` branch, via the GitHub contents API. The file
inventory below is the verified directory listing at that revision; the wire
facts were read from `usb.c` / `usb.h`.

## File inventory (verified present)

| File | Role |
| --- | --- |
| `usb.c` / `usb.h` | USB glue: device table, endpoint assignment, vendor control requests, register access helpers |
| `main.c` | `ieee80211_ops` — the mac80211 callbacks (scan, tx, start, etc.) |
| `init.c` | Hardware init sequence orchestration |
| `initvals.h` / `initvals_phy.h` | Register/PHY init value tables |
| `mcu.c` / `mcu.h` | MCU command interface and firmware upload |
| `regs.h` | Register offset/bit definitions |
| `mac.c` / `mac.h` | MAC layer programming |
| `phy.c` | PHY/BBP/RF programming |
| `dma.c` / `dma.h` | USB DMA buffer + URB handling |
| `tx.c` | TX path descriptor construction |
| `eeprom.c` / `eeprom.h` | eFuse/EEPROM reads (MAC address, calibration) |
| `debugfs.c` | debugfs register access (Linux-only, not portable) |
| `trace.c` / `trace.h` | ftrace instrumentation (Linux-only) |
| `util.c` | small helpers |
| `mt7601u.h` | driver-private device struct |
| `Kconfig` / `Makefile` | kernel build glue |

### Corrections to the plan

* The register header is **`regs.h`**, not `reg.h`.
* The mac80211 ops live in **`main.c`**; there is no `mac80211.c`.

## Verified USB facts (from `usb.c` / `usb.h`)

* Firmware file name: `mt7601u.bin` (`MT7601U_FIRMWARE`).
* Vendor request codes (`enum mt_vendor_req`):
  * `MT_VEND_DEV_MODE = 1`
  * `MT_VEND_WRITE = 2`
  * `MT_VEND_MULTI_READ = 7`
  * `MT_VEND_WRITE_FCE = 0x42`
* Control request type is `direction | USB_TYPE_VENDOR | USB_RECIP_DEVICE`;
  timeout `MT_VEND_REQ_TOUT_MS = 300` ms; `MT_VEND_REQ_MAX_RETRY = 10`.
* Endpoint model: exactly **2 bulk IN** (`__MT_EP_IN_MAX`) and **6 bulk OUT**
  (`__MT_EP_OUT_MAX`) endpoints. `mt7601u_assign_pipes()` fails probe if the
  counts do not match.
* Register **read** = `MT_VEND_MULTI_READ` (IN) at `offset`, 4 bytes, little
  endian.
* Register **write** = two `MT_VEND_WRITE` (OUT) control transfers: low 16 bits
  at `offset`, high 16 bits at `offset + 2`.
* `probe()` sequence: `usb_reset_device()` → `mt7601u_wait_asic_ready()` → read
  `MT_ASIC_VERSION` and `MT_MAC_CSR0` → verify `(asic_rev >> 16) == 0x7601` →
  optional eFuse check → `mt7601u_init_hardware()` → `mt7601u_register_device()`.
* The device table contains `0x148f:0x7601` plus many OEM rebrands.

## Mapping to this project

| Linux source | Rust module (this project) | Status |
| --- | --- | --- |
| `usb.c` vendor requests / register access | `src/usb/transport.rs`, `src/mt7601u/device.rs` | implemented |
| `core.c` `mt7601u_wait_asic_ready` | `src/mt7601u/device.rs` | implemented |
| `mcu.c` firmware upload | `src/mt7601u/firmware.rs`, `src/mt7601u/device.rs` | implemented |
| `regs.h` / `mcu.h` register + command model | `src/mt7601u/regs.rs` | implemented (subset) |
| `mcu.c` MCU command channel | `src/mt7601u/mcu.rs`, `src/mt7601u/dma.rs` | implemented (send + reg-pair/burst writes) |
| `init.c` post-firmware init (reset CSR/BBP, USB DMA) | `src/mt7601u/device.rs` | implemented |
| `init.c` chip_onoff + MAC/BBP initvals + memory tables | `src/mt7601u/init.rs`, `src/mt7601u/initvals.rs` | implemented |
| `phy.c` BBP register access + readiness | `src/mt7601u/phy.rs` | implemented |
| `eeprom.c` eFuse read + EEPROM params | `src/mt7601u/eeprom.rs` | implemented |
| `phy.c` RF tables + `phy_init` / `init_cal` | `src/mt7601u/rf.rs`, `src/mt7601u/radio.rs` | implemented (TSSI / temp comp omitted) |
| `phy.c` `phy_set_channel`, `init.c` `mac_start` | `src/mt7601u/radio.rs` | implemented (20 MHz) |
| `dma.c` RX segments / `mac.h` RXWI | `src/mt7601u/rx.rs` | implemented |
| `main.c` `sw_scan` | `src/mt7601u/scan.rs` | implemented (passive) |
| `mcu.c` `mt7601u_load_firmware`'s unconditional `MT_USB_DMA_CFG` arm | `src/mt7601u/scan.rs` (`bringup`, non-fresh branch) | implemented: reopen re-arms the DMA + MCU channel |
| `tx.c` TX path / probe requests | `src/mt7601u/tx.rs`, `src/wifi/frames.rs` | implemented (unverified on the air) |
| `mac.c` `mt7601u_set_macaddr` / `mt7601u_mac_wcid_setup` / `mt7601u_mac_config_tsf` | `src/mt7601u/mac.rs` | implemented (unit-tested) |
| `main.c` `mt7601u_bss_info_changed` (station setup) | `src/mt7601u/mac.rs` | partial: BSSID, basic rates, TSF, slot, short preamble (no protection/HT) |
| `main.c` auth/assoc (mac80211 MLME on Linux) | `src/mt7601u/station.rs`, `src/wifi/mgmt.rs` | implemented for open networks (unverified on hardware) |
| `main.c` `mt7601u_set_key` / WPA | — | not implemented |

## Verified firmware-upload facts (from `mcu.c` / `dma.h`)

* Firmware is chunked at `MCU_FW_URB_MAX_PAYLOAD = 0x3800` bytes.
* Each chunk buffer: `[4B TX info][payload][pad to 4B][4B zero]`; the info word
  is `TYPE = DMA_PACKET (0)`, `D_PORT = CPU_TX_PORT (2)`, `LEN` = payload length.
* `MT_VEND_WRITE_FCE` writes `MT_FCE_DMA_ADDR` (destination) and
  `MT_FCE_DMA_LEN` (padded length `<< 16`) before each chunk.
* After each chunk, `MT_TX_CPU_FROM_FCE_CPU_DESC_IDX` is incremented and
  `MT_MCU_COM_REG1` bit 31 is polled.
* ILM code is uploaded to address `MT_MCU_IVB_SIZE` (0x40); DLM to
  `MT_MCU_DLM_OFFSET` (0x80000); the IVB is sent via `MT_VEND_DEV_MODE`
  `wValue = 0x12`; completion is `MT_MCU_COM_REG0 == 1`.

## Verified MCU command-channel facts (from `mcu.c` / `dma.h`)

* Commands go to `MT_EP_OUT_INBAND_CMD` as bulk OUT, framed with
  `TYPE = DMA_COMMAND (1)`, `D_PORT = CPU_TX_PORT (2)`, a `SEQ` in
  `MT_TXD_CMD_INFO_SEQ` (bits 19..16) and a command id in `MT_TXD_CMD_INFO_TYPE`
  (bits 26..20).
* Waiting commands allocate a non-zero 4-bit sequence; responses are read from
  the second bulk IN endpoint (`MT_EP_IN_CMD_RESP`) and matched on
  `MT_RXD_CMD_INFO_CMD_SEQ` + `MT_RXD_CMD_INFO_EVT_TYPE == CMD_DONE`.
* `mt7601u_write_reg_pairs` (`CMD_RANDOM_WRITE`) packs `(address, value)` pairs,
  max `INBAND_PACKET_MAX_LEN / 8 = 24` per command, waiting only on the last.
* `mt7601u_burst_write_regs` (`CMD_BURST_WRITE`) prefixes
  `MT_MCU_MEMMAP_WLAN + offset`, max `INBAND_PACKET_MAX_LEN / 4 - 1 = 47` values
  per command.

## Known unknowns

* iOS/macOS has no equivalent of mac80211; the station state machine must be
  re-implemented. See `macos-wifi-feasibility.md`.
* TSSI DC/gain calibration and temperature compensation are not ported, so TX
  power control is incomplete.
* The open-system association path (`src/mt7601u/station.rs`) is unit-tested
  against the mock transport but **not yet verified on hardware**.
* WPA/WPA2 key management (`main.c::mt7601u_set_key`,
  `mac.c::mt76_mac_wcid_set_key` / `mt76_mac_shared_key_setup`) is not ported.
* `mac_set_basic_rates` / `mac_set_slot_time` / `mac_set_short_preamble` are
  ported, but `mt7601u_mac_set_protection` (HT/CTS protection) is not.
