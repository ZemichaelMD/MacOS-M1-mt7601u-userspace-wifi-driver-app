# Protocol / responsibility notes

What the firmware handles versus what the host must do, plus what remains
unknown. Claims are tied to a source function or a hardware test where possible;
otherwise they are marked **UNKNOWN**.

## Firmware vs host

* The MT7601U runs its own MCU firmware (`mt7601u.bin`). Uploading it and
  observing `MT_MCU_COM_REG0 == 1` proves the MCU booted (verified on hardware).
* On Linux, `main.c` registers mac80211 callbacks and `wpa_supplicant` handles
  security; neither exists on macOS, so the station state machine must be
  re-implemented in user space.
* **UNKNOWN**: precisely which parts of scan / authentication / association /
  WPA key derivation the firmware performs versus the host. This can only be
  established by reading the MCU command paths in `main.c`, `mac.c` and
  `mcu.c` and testing on hardware.

## MCU command channel

* MCU commands are sent as bulk OUT to `MT_EP_OUT_INBAND_CMD` (first bulk OUT in
  descriptor order; `0x08` on this unit) and responses arrive on a bulk IN
  endpoint. Command framing uses the same TX DMA info header as firmware upload,
  with `TYPE = DMA_COMMAND` and an MCU command id in `MT_TXD_CMD_INFO_TYPE`.
* Command ids (`mcu.h`): `CMD_FUN_SET_OP = 1`, `CMD_BURST_WRITE = 8`,
  `CMD_RANDOM_WRITE = 12`, `CMD_CALIBRATION_OP = 31`, …
* The register-pair write path (`mt7601u_write_reg_pairs`, used for initvals)
  packs `(address, value)` pairs, max `INBAND_PACKET_MAX_LEN / 8 = 24` per
  command.
* **Implemented** in `src/mt7601u/mcu.rs`: command send + `CMD_DONE` matching,
  register-pair and burst writes, function select and calibration. Verified on
  hardware via `--init` (`Q_SELECT` acknowledged).

## Endpoints

* 2 bulk IN + 6 bulk OUT, all 512-byte max packet (verified from descriptors and
  `usb.h`). `out_eps[]` is filled in descriptor order; index 0 is
  `MT_EP_OUT_INBAND_CMD`, the IN endpoints are RX-packet (index 0) and
  MCU-response (index 1).
* RX segment framing (from `dma.c`): segment length = `MT_DMA_HDRS (8) + dma_len`,
  where `dma_len` is a little-endian `u16` at the start of the segment; a 4-byte
  FCE descriptor sits at the end; an `mt7601u_rxwi` (28 bytes) follows the
  DMA header and the 802.11 frame follows the RXWI.
* **Implemented** in `src/mt7601u/rx.rs`: segment splitting, RXWI decode
  (`rxinfo`, `ctl`, `snr`, `ant`, `gain`, `freq_off`), and beacon/probe-response
  parsing. Verified on hardware via `--scan`.

## Frames

* Do **not** assume every USB RX buffer begins with a radiotap header. Radiotap
  is a capture/monitor metadata format, not a guaranteed on-wire framing.
* RX descriptor handling is implemented (`src/mt7601u/rx.rs`). The **TX**
  descriptor (`struct mt76_txwi` in `mac.h`) and DMA framing are implemented in
  `src/mt7601u/tx.rs`; probe requests, auth and assoc frames are built in
  `src/wifi/frames.rs`.
* LLC/SNAP encapsulation is implemented in `src/wifi/data.rs` (RFC 1042:
  `aa aa 03 00 00 00 <ethertype>`). Station MAC is programmed at association;
  encryption/key state is **not** implemented (WPA2 missing).

## Association

* On Linux, mac80211's MLME (not the driver) runs the auth/assoc exchange; the
  driver only sees `bss_info_changed` and `sta_add` callbacks. On macOS that
  state machine must be driven by hand.
* **Implemented** in `src/mt7601u/station.rs` for **open** networks:
  program own MAC, WCID, AP BSSID, basic rates, TSF and slot time
  (`src/mt7601u/mac.rs`, from `mac.c` / `main.c`), send an open-system auth
  request, await the auth response, send an association request and await the
  association response (`src/wifi/mgmt.rs` parses the fixed fields).
* Management frames are sent at the lowest CCK rate with a hardware-assigned
  sequence number, addressed by the group WCID (`GROUP_WCID(0) = 126`).
* **UNKNOWN / not implemented**: WPA2 (4-way handshake, key installation),
  RSSI in dBm, and HT/protection setup. `associate` is unit-tested but **not yet
  verified on hardware**.

## Data path

* Outbound: an IP packet becomes `[LLC/SNAP][IP]` inside an 802.11 data frame
  (`ToDS = 1`, Address 1 = BSSID), sent at the lowest OFDM rate. Inbound:
  the reverse, with `FromDS = 1` frames from the AP stripped back to IP.
  Implemented in `src/wifi/data.rs` (pure) + `src/mt7601u/data.rs`.
* Receive segments are padded to 4 bytes, so the inbound payload is trimmed to
  the IPv4 total-length field before it reaches `utun`.
* Frames with the Protected bit set are dropped — there is no CCMP.
* **Implemented**: IPv4 in/out, LLC/SNAP, the DHCP client (`src/net/`) and the
  `utun` relay (`src/tunnel/relay.rs`). **Not implemented**: encryption, ARP
  handling (outbound frames address the AP and rely on it to route by IP),
  IPv6, fragmentation/aggregation.

## Security

* WPA/WPA2/WPA3 key negotiation is **UNKNOWN** in terms of host/firmware split.
* Linux `wpa_supplicant` is not assumed to be droppable into macOS unchanged;
  portability, interfaces, build requirements and licence would need separate
  investigation.

## Scan

* The driver uses **software scan** (`.sw_scan_start`/`.sw_scan_complete`):
  mac80211 switches channels and sends probe requests; the driver only
  saves/restores AGC (BBP R66). Beacons/probe responses are collected via RX.
* **Implemented** in `src/mt7601u/scan.rs` as a *passive* scan: for each channel
  in the EEPROM region, set the channel (`phy_set_channel`), reset AGC and read
  bulk-IN segments for a dwell period. Verified on hardware (7 live networks).
* **Not implemented**: active scanning (probe-request TX), channel dwell tuning,
  and RSSI extraction (the RXWI `gain`/`snr` fields are parsed but not yet
  converted to dBm).
