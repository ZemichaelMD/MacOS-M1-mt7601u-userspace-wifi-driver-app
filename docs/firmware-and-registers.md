# Firmware and registers

Status: **Firmware, MCU command channel, MAC/BBP register initialization and eFuse
/ EEPROM read implemented.** Transcribed from the Linux driver into
`src/mt7601u/`. The RF (`phy.c` RF tables, `phy_init` calibration) and 802.11
data paths are **not** implemented.

## Implemented

| Capability | Code | Linux source |
| --- | --- | --- |
| Vendor control transfers (retrying) | `device.rs::vendor_out/vendor_in` | `usb.c::mt7601u_vendor_request` |
| Register read (32-bit) | `device.rs::read_reg` | `usb.c::mt7601u_rr` |
| Register write (32-bit) | `device.rs::write_reg` | `usb.c::mt7601u_wr` |
| Read/modify/write | `device.rs::rmw` | `usb.c::mt7601u_rmw` |
| Device-mode reset | `device.rs::vendor_reset` | `usb.c::mt7601u_vendor_reset` |
| ASIC readiness poll | `device.rs::wait_asic_ready` | `core.c::mt7601u_wait_asic_ready` |
| Identification | `device.rs::identify` | `usb.c::mt7601u_probe` |
| Firmware upload | `device.rs::load_firmware` | `mcu.c::mt7601u_load_firmware` |
| Post-firmware init (CSR/BBP reset, USB DMA) | `device.rs::init_after_firmware` | `init.c::mt7601u_init_hardware` |
| MCU command send + response | `mcu.rs::mcu_send` | `mcu.c::mt7601u_mcu_msg_send` |
| Register-pair / burst writes | `mcu.rs` | `mcu.c::mt7601u_write_reg_pairs`/`burst_write_regs` |
| MCU function select / calibrate | `mcu.rs` | `mcu.c::mt7601u_mcu_function_select`/`calibrate` |
| TX/RX DMA framing | `dma.rs` | `dma.h` / `dma.c` |
| Image parsing | `firmware.rs` | `mcu.c` |
| WLAN clock on/off | `device.rs::chip_onoff` | `init.c::mt7601u_chip_onoff` |
| BBP register read/write + ready | `phy.rs` | `phy.c::mt7601u_bbp_rr/wr`, `wait_bbp_ready` |
| MAC/BBP init tables | `initvals.rs` | `initvals.h` |
| MAC initvals + memory tables + counters | `init.rs::init_radio_registers` | `init.c::mt7601u_init_hardware` |
| eFuse read + EEPROM parameters (MAC, channels, TX power) | `eeprom.rs` | `eeprom.c::mt7601u_eeprom_init` |

CLI: `--identify` (read-only), `--read-eeprom`, `--load-firmware <path>`,
`--init [<path>]` (post-init + MCU `Q_SELECT`), and `--hw-init [<path>]` (adds
MAC/BBP initvals and the WCID/key memory tables).

## Verified on hardware

Target: Apple Silicon Mac, macOS 26.5.1, dongle `148f:7601` via hub, 2026-10-15.

```
$ mt7601u-macos --identify
ASIC reported ready.
ASIC version : 0x76010001
ASIC revision: 0x0001
MAC CSR0     : 0x76010500
eFuse        : present
Chip id      : MT7601 (expected)
```

* `ASIC version >> 16 == 0x7601` — the same check the Linux `probe()` performs.
* Repeated `--load-firmware` runs succeeded (idempotent).
* `--init` reports `MCU command channel OK — Q_SELECT acknowledged`, repeatably
  — the MCU `CMD_DONE` response was received on the second bulk IN endpoint.
* `--hw-init` completes the clock enable, MAC initvals, BBP initvals, WCID/key
  memory writes and counter resets with no timeouts; repeatable.
* `--read-eeprom` reads the real eFuse:

  ```
  EEPROM version : ee 0x0d, fae 0x00
  MAC address    : 88:82:79:24:0e:c0
  Channel range  : 1..=14
  TSSI enabled   : false
  RF freq offset : 105
  Channel power  : [0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2]
  ```

## EEPROM / eFuse (from `eeprom.c`)

`eeprom_init()` invalidates the usage map (`MT_EE_USAGE_MAP_START..END`), reads
all 256 bytes via `mt7601u_efuse_read` (`MT_EFUSE_CTRL` KICK + 4×
`MT_EFUSE_DATA`), programs the MAC address into `MT_MAC_ADDR_DW0/DW1`, and
decodes: NIC caps, channel power, country-region channel bounds, RF frequency
offset, RSSI offsets, reference temperature/LNA gain, and the per-rate TX power
table (`MT_TX_PWR_CFG_0..4`, plus `MT_TX_PWR_CFG_7/9` via
`mt7601u_extra_power_over_mac`).

## Register initialization (from `init.c`)

`init_radio_registers()` mirrors `mt7601u_init_hardware` from `mcu_cmd_init`
up to (but not including) `mt7601u_eeprom_init`:

1. `mcu_cmd_init` (`Q_SELECT`).
2. `write_mac_initvals`: `mac_common_vals` + `mac_chip_vals` via
   `CMD_RANDOM_WRITE`, then `MT_BCN_OFFSET(0..3)` (computed from
   `beacon_offsets`, and identical to the table's first two words), then
   `MT_AUX_CLK_CFG = 0`.
3. Wait for `MT_MAC_STATUS` TX|RX to clear.
4. `init_bbp`: `wait_bbp_ready` (`MT_BBP_REG_VERSION` neither 0 nor 0xff), then
   `bbp_common_vals` + `bbp_chip_vals`, each written through `MT_BBP_CSR_CFG`.
5. `init_wcid_mem` / `init_key_mem` / `init_wcid_attr_mem` via `CMD_BURST_WRITE`.
6. Clear `MT_BEACON_TIME_CFG`, reset counters, set `MT_US_CYC_CFG`, program
   `MT_TXOP_CTRL_CFG`.

`beacon_offset_words()` is a pure function and is unit-tested against the
transcribed `mac_chip_vals` entries.

## MCU command channel (from `mcu.c`)

* Commands are bulk OUT to `MT_EP_OUT_INBAND_CMD`, framed with
  `TYPE = DMA_COMMAND (1)`, `D_PORT = CPU_TX_PORT (2)`, a 4-bit `SEQ` at bits
  19..16 and the command id at bits 26..20.
* A waiting command allocates a non-zero sequence via `next_seq`; the response is
  read from `MT_EP_IN_CMD_RESP` (second bulk IN) and accepted only when
  `MT_RXD_CMD_INFO_CMD_SEQ == seq` and
  `MT_RXD_CMD_INFO_EVT_TYPE == CMD_DONE`.
* Up to 5 response attempts (300 ms each), matching `mt7601u_mcu_wait_resp`.
* `mcu_write_reg_pairs` sends `CMD_RANDOM_WRITE` (24 pairs/command, wait on the
  last); `mcu_burst_write_regs` sends `CMD_BURST_WRITE` (47 values/command);
  `mcu_function_select` sends `CMD_FUN_SET_OP` (`Q_SELECT` needs no response);
  `mcu_calibrate` sends `CMD_CALIBRATION_OP`.

## Firmware blob

* Name `mt7601u.bin`; the driver looks in `mediatek/` then the bare name.
* `linux-firmware/WHENCE` states: *"Licence: Redistributable. See
  LICENCE.ralink_a_mediatek_company_firmware for details"*
  (`SPDX-License-Identifier: LicenseRef-LICENCE.ralink_a_mediatek_company_firmware`).
* **Not vendored here.** It is loaded from a user-supplied path, so no logo/blob
  redistribution questions arise in this repo.
* Observed header of the reference image: `ilm_len = 45380`, `dlm_len = 0`,
  `build_ver = 0x7640`, `fw_ver = 0x0100`, build time `201302052146`; total size
  `32 + 45380 + 0 = 45412` bytes. The parser rejects any image whose declared
  lengths do not sum to the file size.

## Control transfers (from `usb.c`)

| Code | Name |
| --- | --- |
| `1` | `MT_VEND_DEV_MODE` |
| `2` | `MT_VEND_WRITE` |
| `7` | `MT_VEND_MULTI_READ` |
| `0x42` | `MT_VEND_WRITE_FCE` |

* Request type `direction | USB_TYPE_VENDOR | USB_RECIP_DEVICE` (`0x40` out,
  `0xC0` in); timeout 300 ms; up to 10 retries, 5 ms apart.
* Register read: `MT_VEND_MULTI_READ`, IN, `wIndex = offset`, 4-byte LE.
* Register write: two `MT_VEND_WRITE` OUT transfers — low 16 bits at `offset`,
  high 16 bits at `offset + 2`.
* Device-mode reset: `MT_VEND_DEV_MODE`, OUT, `wValue = 1`.
* IVB handoff: `MT_VEND_DEV_MODE`, OUT, `wValue = 0x12`, 0x40-byte payload.

## Firmware upload sequence (from `mcu.c`)

Pre-transfer register writes, then:

1. Split the image: ILM code → address `0x40`; DLM data → `0x80000`.
2. Transfer in `0x3800`-byte chunks. Each chunk is one bulk OUT with buffer
   `[4B info][payload][pad to 4B][4B zero]`, where the info word is
   `TYPE = DMA_PACKET (0)`, `D_PORT = CPU_TX_PORT (2)`, `LEN = payload length`.
   Before each chunk: `MT_VEND_WRITE_FCE` sets `MT_FCE_DMA_ADDR` and
   `MT_FCE_DMA_LEN`. After each chunk: increment `MT_TX_CPU_FROM_FCE_CPU_DESC_IDX`
   and poll `MT_MCU_COM_REG1` bit 31.
3. Send the IVB via the `0x12` vendor request.
4. Poll `MT_MCU_COM_REG0 == 1` (firmware running).

The bulk OUT endpoint is `MT_EP_OUT_INBAND_CMD` = the first bulk OUT endpoint in
descriptor order, resolved at runtime (it is `0x08` on this unit). It is never
hardcoded.

## Not implemented / open questions

* We do **not** call `usb_reset_device()` (the USB-level reset in `probe()`); the
  vendor reset is used instead. A macOS equivalent is not yet evaluated.
* Remaining register-level gaps: TSSI DC/gain calibration and temperature
  compensation (TX power), `mt7601u_mac_set_protection` (HT/CTS protection), and
  the WPA key tables (`MT_WCID_KEY`/`MT_SKEY`). `phy_init`, RF calibration,
  `set_rx_path`/`set_tx_dac`, `phy_set_channel` and `mac_start` *are* implemented
  (`src/mt7601u/radio.rs`).
* Timing beyond the explicit sleeps (5 ms pre-upload, 10 ms polls) is not tuned.

## Rules enforced

* Every register access is bounds-checked to the 16-bit control index.
* Every polling loop has a deadline; every transfer has a timeout.
* Firmware images are size-validated before any I/O.
* A successful transfer is **not** treated as proof the radio works.
