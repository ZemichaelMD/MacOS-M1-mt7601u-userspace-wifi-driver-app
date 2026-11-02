# mt7601u-macos

User-space USB driver work and a GUI for the **MediaTek MT7601U**
(`0x148f:0x7601`) on Apple Silicon macOS, written in Rust.

> **New here?** Read [`HANDOVER.md`](HANDOVER.md) first — current status, the
> next goal (association), hard-won gotchas, and a diagnostics cheat-sheet.

> **Scope and honesty.** Device detection, descriptor inspection, register
> access, chip identification, **firmware upload**, the **MCU command channel**,
> **MAC/BBP register initialization**, **eFuse/EEPROM read**, the **RX path**, a
> **real passive scan**, the **TX path**, **open-system association**,
> **WPA2-PSK** (the 4-way handshake, with keys installed for hardware CCMP), the
> **802.11 data path** (LLC/SNAP), a **DHCP client**, a **`utun` relay** and a
> **privileged helper** (so the GUI need not run as root) are implemented. The
> GUI drives scan, connect and the tunnel. **Verified on the physical dongle
> (2026-10-16): scan, association, the WPA2 4-way handshake, a real DHCP lease,
> ARP and ICMP to the gateway and to `8.8.8.8`** — `MT7601U_PSK=… cargo run
> --example hs_probe` drives the whole chain. The `utun` relay is unit-tested and
> exercised by `--tunnel-demo`; carrying the internet into macOS still needs the
> privileged helper (or `sudo`).
> **WPA (TKIP)** and **WPA3 (SAE)** are not supported. See
> [`docs/macos-wifi-feasibility.md`](docs/macos-wifi-feasibility.md) for why
> native macOS Wi-Fi registration is treated as blocked pending evidence.

## What works today

* Enumerate USB devices and match `148f:7601`; parse and display real
  configuration / interface / endpoint descriptors.
* Open the device, claim interface 0, release and close cleanly.
* Vendor control transfers, register read/write, and `MT_VEND_*` requests, with
  the Linux driver's retry/timeout policy (transcribed from `usb.c`).
* Chip identification: `ASIC version`, `MAC CSR0`, eFuse presence — verified on
  hardware (`0x76010001`, i.e. MT7601).
* Firmware upload (`mt7601u.bin`): chunked bulk transfer, DMA framing, MCU
  handshake — verified on hardware, repeatable.
* Post-firmware init (CSR/BBP reset, USB DMA config) and the MCU command channel:
  `Q_SELECT` acknowledged over bulk endpoints — verified on hardware.
* MAC/BBP register initialization: `chip_onoff`, `initvals.h` MAC/BBP tables,
  WCID/key memory, counters — verified complete on hardware, repeatable.
* eFuse / EEPROM read: MAC address, channel plan, TX-power calibration — verified
  on hardware (`88:82:79:24:0e:c0`, channels 1-14).
* RF/PHY bring-up: `initvals_phy.h` RF tables, `init_cal` (`MCU_CAL_R`,
  `TXDCOC`, `LOFT`, `TXIQ`, `RXIQ`, `DPD`, BW), `phy_set_channel`, `set_rx_path`,
  `set_tx_dac`, `mac_start`.
* **RX path + passive scan** — verified on hardware; see below.
* TX path: `struct mt76_txwi` construction and DMA framing (`src/mt7601u/tx.rs`),
  plus probe/auth/assoc frame builders (`src/wifi/frames.rs`).
* Station setup (`src/mt7601u/mac.rs`, from `mac.c` / `main.c`): own MAC address,
  WCID + AP BSSID, basic-rate fallback tables, beacon/TSF timer, slot time.
* **Open-system association** (`src/mt7601u/station.rs`, `--connect`):
  auth → assoc exchange with response parsing (`src/wifi/mgmt.rs`). Unit-tested
  against the mock transport; **not yet verified on hardware**.
* **WPA2-PSK** (`src/wifi/wpa.rs`, `rsn.rs`, `eapol.rs`, `handshake.rs`,
  `src/mt7601u/station.rs`): the PMK (`PBKDF2-HMAC-SHA1`), PTK (`PRF-512`), the
  EAPOL-Key MIC, the 4-way handshake, RFC 3394 unwrapping of the GTK, and key
  installation into the WCID/shared-key tables. CCMP itself is done by the
  hardware. Crypto is validated against the published 802.11i PMK vector and
  RFC 3394.
* **Data path** (`src/wifi/data.rs`, `src/mt7601u/data.rs`): 802.11 data frames
  with LLC/SNAP encapsulation, IP packets in and out of the station (hardware
  decryption accepted on receive).
* **DHCP client** (`src/net/`): IPv4/UDP framing and the
  DISCOVER/OFFER/REQUEST/ACK exchange, used to get an address from the AP.
* **`utun` relay** (`src/tunnel/relay.rs`): moves IP packets between the Wi-Fi
  link and macOS, with the interface/route/DNS setup and rollback in
  `src/tunnel/utun.rs`.
* **Privileged helper** (`src/helper/`): a root LaunchDaemon that creates and
  configures the `utun` interface for the unprivileged GUI and relays packets
  over a Unix socket. Install it once with `sudo mt7601u-macos --install-helper`
  (or `sudo bash scripts/install-helper.sh`) so the GUI no longer needs `sudo`.
* A GUI that behaves like the system Wi-Fi picker: the app finds the dongle,
  opens it and scans for networks on its own, then a click on a network joins it
  and brings the tunnel up in one step. Passphrases are remembered so the next
  join is a single click, the last network is rejoined automatically when it
  comes back into range, and **Stop** releases the device. **Start** (or a
  rescan) brings the radio back up on the same dongle: closing the USB handle no
  longer wedges the MCU command channel, so no replug is needed. **That reopen
  path has not been re-tested on hardware yet** — see `HANDOVER.md` §3. Details
  (link, USB device, descriptor dump) live behind a **Details** drawer, with the
  log in a console at the bottom.
* The GUI (`eframe`/`egui`, Metal via `wgpu`) also shows the device state,
  a descriptor dump and an "Identify chip" action.

### First real scan

```
$ cargo run -- --scan mt7601u-refs/linux-firmware/mediatek/mt7601u.bin
Initializing the radio (registers + RF tables + calibration)…
MAC address: 88:82:79:24:0e:c0
Scanning channels 1-14 (200 ms each)…

MD                               00:4c:e5:f9:3b:03 ch  2  WPA2/WPA3
4G-MIFI-94EC                     14:cb:49:0d:94:ec ch  3  WPA2/WPA3
YGT                              2c:b6:c2:13:43:56 ch  3  WPA2/WPA3
Zee                              72:e2:53:fe:37:93 ch 11  WPA2/WPA3
TECNO-TR109D-3792                78:12:3e:ae:37:93 ch 10  WPA2/WPA3
HUAWEI-gd8v                      b4:6e:08:8c:69:1c ch 11  WPA2/WPA3
Jantechstore                     bc:5d:a3:f5:7f:59 ch  5  WPA2/WPA3

7 network(s) found.
```

These are real beacons received over the air by the dongle. Results vary run to
run, as a passive scan does.

## What does not work yet

* **WPA (TKIP)** and **WPA3 (SAE)** — only WPA2-PSK (CCMP) is implemented.
* TSSI DC/gain calibration and temperature compensation (TX power control).
* The tunnel needs privilege (`utun`/`ifconfig`/`route`/`scutil`): either the
  privileged helper (installed once with `--install-helper`) or `sudo`. On
  macOS 15+ only apps that resolve their own DNS use a virtual interface
  reliably without a signed system extension.
* Active scan (probe-request TX) — the current scan is passive (beacons only).
* No deauthentication frame is sent on disconnect.

## Saved networks and where they live

Passphrases are remembered so joining a known network is one click. They are
stored in `~/Library/Application Support/mt7601u-macos/credentials`, written
`0600` (owner-only). The file is plain text, so treat it like `~/.netrc`: it
holds a secret, and the app warns in the log if its permissions are ever loose.
Delete a network's passphrase with the **Forget saved password** button in the
details drawer.

## Requirements

* macOS on Apple Silicon (`arm64`).
* Rust (stable) via `rustup`.
* `libusb` and `pkg-config` (`brew install libusb pkg-config`).

## Build and run

```bash
cargo build                 # builds against libusb
cargo run                   # launch the GUI: it finds, opens and scans by itself
cargo run -- --diagnose     # enumerate + dump descriptors + open/claim test
cargo run -- --identify     # read ASIC/MAC revision + eFuse (read-only)
cargo run -- --load-firmware <path-to-mt7601u.bin>   # uploads firmware (writes)
cargo run -- --init [<path-to-mt7601u.bin>]          # firmware + post-init + MCU handshake
cargo run -- --hw-init [<path-to-mt7601u.bin>]       # above + MAC/BBP initvals (writes)
cargo run -- --read-eeprom  # read eFuse: MAC address, channel plan, TX power
cargo run -- --scan [<path-to-mt7601u.bin>]          # bring up the radio + passive scan
cargo run -- --connect <ssid> [<ch> [<bssid>]]       # associate (WPA2 if MT7601U_PSK is set)
cargo run -- --tx-probe [<ch>]                       # transmit a probe request (TX test)
cargo run -- --tunnel-demo [<secs>]                  # utun self-test (needs sudo)
cargo run -- --install-helper                        # install the root helper (asks sudo)
cargo run -- --helper-status                         # is the helper running?
cargo run -- --list         # one-line summary per USB device
```

To build a double-clickable GUI app, see
[`docs/build-macos-app.md`](docs/build-macos-app.md) (or run
`bash scripts/bundle-macos-app.sh`).

The firmware blob is **not** bundled. Obtain `mt7601u.bin` from
`linux-firmware` (WHENCE: redistributable, see
`LICENCE.ralink_a_mediatek_company_firmware`).

## Checks

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Layout

```
src/
  main.rs            entry point, CLI subcommands, eframe launch
  app.rs             egui UI: Wi-Fi picker, details drawer, log console
  app_state.rs       GUI state + bounded log buffer
  theme.rs           design tokens + the egui style
  commands.rs        Command / Event channel types
  credentials.rs     saved passphrases + preferences (0600 file)
  backend.rs         backend worker thread
  logging.rs         LogLine / LogLevel
  usb/               enumerate.rs, transport.rs
  mt7601u/           regs.rs, dma.rs, firmware.rs, device.rs, mcu.rs,
                     phy.rs, radio.rs, rf.rs, rx.rs, tx.rs, scan.rs,
                     mac.rs, station.rs, data.rs, initvals.rs, init.rs,
                     eeprom.rs, mod.rs
  wifi/              domain types, frames.rs (builders), mgmt.rs (parsers),
                     data.rs (802.11 data + LLC/SNAP), rsn.rs (RSN IE),
                     eapol.rs (EAPOL-Key), wpa.rs (PMK/PTK/MIC), handshake.rs
  net/               ipv4.rs (IPv4/UDP), dhcp.rs (DHCP client), IpLink trait
  tunnel/            utun.rs (interface/routes/DNS), relay.rs (packet relay),
                     icmp.rs (tunnel self-test), TunnelLink trait
  helper/            mod.rs (socket protocol), server.rs (root daemon +
                     installer), client.rs (GUI-side client)
scripts/             bundle-macos-app.sh (builds the .app),
                     install-helper.sh (installs the root helper)
docs/                architecture, feasibility, source map, protocol notes, build guide
tests/               integration tests + captured fixture
```

## Documentation

* [`docs/build-macos-app.md`](docs/build-macos-app.md) — build the `.app`
* [`docs/architecture.md`](docs/architecture.md)
* [`docs/macos-wifi-feasibility.md`](docs/macos-wifi-feasibility.md)
* [`docs/driver-source-map.md`](docs/driver-source-map.md)
* [`docs/usb-descriptors.md`](docs/usb-descriptors.md)
* [`docs/firmware-and-registers.md`](docs/firmware-and-registers.md)
* [`docs/protocol-notes.md`](docs/protocol-notes.md)
* [`docs/macos-networking.md`](docs/macos-networking.md)
* [`docs/test-plan.md`](docs/test-plan.md)

## Licence

Project code: MIT OR Apache-2.0. The upstream firmware blob `mt7601u.bin` is
**not** included; it is loaded from a user-supplied path, and its redistribution
terms (see `linux-firmware` `WHENCE`) apply to any copy you make.
