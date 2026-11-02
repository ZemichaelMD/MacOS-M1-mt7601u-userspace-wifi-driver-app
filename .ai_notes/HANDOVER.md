# HANDOVER — MT7601U macOS user-space driver

> **2026-10-17 (latest session) — the tunnel now survives sustained load.** A
> 5-minute bidirectional soak (2×50 MB down + 2×8 MB up) runs at 12–15 Mbps
> down with **zero** tunnel restarts; the same load used to wedge the relay
> and force a reconnect every minute or two. See “Tunnel under load, fixed
> (2026-10-17)” below.
>
> **2026-10-16 — the WPA2 link now carries traffic, verified on
> hardware.** `MT7601U_PSK=… cargo run --example hs_probe` runs the whole chain
> and prints: `handshake_confirmed=true`, `LEASE 192.168.0.195 … router
> 192.168.0.1`, `ping 192.168.0.1: REPLIED`, `ping 8.8.8.8: REPLIED`.
>
> Two corrections to what the older documents in this tree claim:
>
> 1. **The 4-way handshake completes.** `HANDOVER_DHCP_TUNNEL.md` says the AP
>    never accepts our 4/4 and stays stuck on 3/4 — that was true of the code at
>    the time (4/4 was sent *protected*, which the AP cannot decrypt before it has
>    accepted us). `station.rs` now sends 4/4 unencrypted and installs the keys
>    afterwards, and the AP goes quiet exactly as it should.
> 2. **DHCP failed for a different reason — the group-key TX path.**

_Last updated: 2026-10-17. See “Tunnel under load, fixed” and “WPA2 → DHCP →
IP, fixed” below for the two changes that made the link carry traffic; everything
after them is the original 2026-10-15 map._

## WPA1 (TKIP) and WPA3 (SAE) added (2026-10-17)

**What.** The two remaining personal-network modes, both unit-tested against an
independent Python reference (`scripts/gen-crypto-vectors.py`), **not yet
verified on a real AP** (WPA2 remains the only handshake verified on hardware).

* **WPA-PSK (TKIP)** — `associate_wpa1` advertises the WPA1 vendor IE, drives
  the 4-way with the WPA1 key descriptor, then the group-key handshake whose
  encrypted group 1/2 carries the GTK; both keys get wpa_supplicant's Michael
  MIC key halves swapped before installation
  (`src/wifi/{rsn,eapol,wpa,handshake}.rs`, `station::associate_wpa1`).
* **WPA3-SAE** — full dragonfly exchange on P-256 in `src/wifi/sae.rs` (PWE
  hunting-and-pecking, commit/confirm HMACs, KCK/PMK/PMKID derivation,
  anti-clogging-token retries); the SAE-derived PMK then runs the same 4-way
  with `ptk_sae` + CMAC (`station::associate_sae`).
* **Detection** — the scan keeps the raw RSN IE; an SAE-only AKM list is
  `Security::Wpa3`, a transition-mode AP (SAE+PSK) still joins via WPA2-PSK.
* **Wiring** — picker prompt/tooltip, backend dispatch, and
  `MT7601U_SECURITY=open|wpa|wpa2|wpa3` for `--connect`.
* **Limitation** — the MT7601U has no 802.11w/PMF, so a WPA3-only AP that
  enforces PMF (or SAE H2E) cannot be joined; test on a transition-mode AP.

## Tunnel under load, fixed (2026-10-17)

**Symptom.** Under sustained throughput the download stalled to zero and the
tunnel restarted itself: `relay tun write failed: the helper is not draining
its socket; packet dropped` repeated, the `in` frame counter froze, and after
15 s without a packet reaching macOS the stall watchdog rebuilt the tunnel
(fresh DHCP lease, routes flap). Under a big download this happened every
minute or two, indefinitely.

**Root cause — a one-way queue in the helper client.** `HelperClient` stages
bytes the daemon's socket would not take in `pending` (capped at 256 KB) and
used to flush that buffer **only after appending a packet**. Once a burst
filled the queue to the cap, every later packet returned "not draining"
*before* reaching the flush — so nothing ever flushed the queue again, however
fast the daemon drained its side. The frozen `in` counter and the endless drop
storm were one and the same bug: the client had stopped talking. The daemon,
the sockets, and the kernels were healthy the whole time (its log shows no
slow rounds, no drops, and the uplink kept flowing through the same session).

**Fix.**

* `src/helper/client.rs` — `send_packet` flushes the backlog **before**
  judging the queue; at the cap, that flush is the only thing that creates
  room. `PacketTun::flush` (below) exposes the same drain to the relay loop.
* `src/tunnel/relay.rs` — new `PacketTun::flush` hook (default no-op; the
  helper client overrides it to drain `pending`).
* `src/backend.rs` — `relay_step` calls `tunnel.flush()` every iteration, so
  the backlog drains even while the downlink is quiet; previously only an
  arriving packet could trigger a flush.
* `src/helper/client.rs` tests — `a_full_queue_drains_once_the_daemon_reads_again`
  fills the queue against a stalled daemon, lets it read, and requires the
  *same connection* to recover; the old code failed this.

**Verified under load** — 5 minutes of 2×50 MB down + 2×8 MB up through
`speed.cloudflare.com`: 195k frames in / 116k out, bursts to 15 Mbps down
(normal TCP-over-Wi-Fi oscillation between 0.5–15 Mbps), **zero tunnel
restarts, zero "no packet reached macOS" events**, 71 dropped frames in total
(one per burst edge — the last 2.5 minutes dropped none, and the `in` counter
advanced continuously). The helper log shows a single session for the whole
run, where identical load previously produced a restart every ~70 s.

## WPA2 → DHCP → IP, fixed (2026-10-16)

**Symptom.** Join a WPA2 network and the device never appears in the router's
client list; DHCP times out with `no DHCP response (message type 2)`.

**What was measured on the air** (AP `HaLePo`, `98:25:4a:a7:53:8a`, and the
gateway is the AP itself, `192.168.0.1`):

* The 4-way handshake **does** complete: `associate_wpa2` returns
  `handshake_confirmed = true`, and the AP stops retransmitting 3/4.
* The **pairwise** (unicast) TX path works. An ARP request for the gateway sent
  to the AP's MAC is answered, in the clear, by the AP — so our hardware can
  transmit a keyed frame, the AP decrypts the pairwise TK, and we can read the
  reply.
* The **group** (broadcast/multicast) TX path does **not** work. The same ARP
  sent to the broadcast MAC (group WCID 126, GTK) is never answered, and the
  only thing that comes back is a copy of our own frame, relayed by the AP with
  a CCMP header it generated itself and a payload that no key we hold decrypts.
  `MT_WCID_ATTR_PAIRWISE` on the group WCID, the `WIV` DMA flag, and the PN have
  all been flipped and re-tested — none of them change the outcome.
* Our **RX** is fine: the AP's own group traffic (SSDP from `192.168.0.1`, other
  clients' mDNS, the gateway's ARP) arrives decrypted, and a unicast reply is
  decrypted too.

**Root cause.** Every DHCPDISCOVER and every ARP request went out addressed to
the *broadcast* MAC, which selects the group WCID — and a group-key frame is not
delivered by this AP.

**Fix.** Address broadcast and multicast IP to the AP (the next hop) instead:
the `802.11` Address 3 becomes the BSSID, the frame goes out on the station WCID
with the pairwise key, and the AP's bridge/router floods or consumes it from
there. The IP destination is untouched (`255.255.255.255` stays a broadcast), so
the AP still handles it as a broadcast. This is also how a DHCP client works
behind a relay.

* `src/mt7601u/data.rs` — `tx_ipv4` now always addresses the AP.
* `src/backend.rs` — `request_arp` sends the ARP request to the AP's MAC too.
* `src/mt7601u/data.rs` tests — `tx_ipv4_addresses_broadcast_traffic_to_the_ap`
  and `dhcp_discover_tx_descriptor_matches_the_hardware` pin the new descriptor
  (they previously pinned the group-WCID framing, citing `tx.c`).

**Verified end to end** with `MT7601U_PSK=… cargo run --example hs_probe`:

```
associate_wpa2 took 1.70s: AID 3 handshake_confirmed=true
LEASE 192.168.0.195 mask 255.255.255.0 router 192.168.0.1 dns [192.168.0.1] lease 7200s
ARP request for 192.168.0.195 from 192.168.0.1 — replying
ICMP echo reply from 192.168.0.1        ping 192.168.0.1: REPLIED
ICMP echo reply from 8.8.8.8            ping 8.8.8.8: REPLIED
```

**Known limits.** ARP for an on-link peer that is not the gateway still cannot
resolve (a broadcast ARP is not delivered, and a unicast ARP is consumed by the
router); peers are learned from inbound traffic instead. `--tunnel-demo`, the
helper and the GUI are unchanged by this session.

> **Verified on hardware so far:** bring-up, passive scan, **WPA2 association and
> the 4-way handshake** (`Associated with "HaLePo" (AID 1)` + `WPA2 keys
> installed`). **Not yet verified:** DHCP and the tunnel relay.
>
> **Since the last handover:** the group/pairwise key layout was fixed (the
> DHCP `DISCOVER` was being encrypted with the pairwise key — see §8/§13), and a
> **privileged helper** (`src/helper/`) was added so the GUI no longer has to run
> under `sudo`.

---

## 1. What this is

A Rust user-space driver + GUI for the **MediaTek MT7601U** (`148f:7601`) USB
Wi-Fi adapter on Apple Silicon macOS. No kernel extension, no SIP changes — it
talks to the device over libusb (`rusb`) and re-implements the parts of the Linux
driver (`drivers/net/wireless/mediatek/mt7601u`) that are needed, because macOS
has no `mac80211`.

**Where we are:** the device comes up, the radio is calibrated, and a **real
passive scan** returns live networks. The **TX path**, **station setup**,
**open-system association**, **WPA2-PSK** (4-way handshake + hardware CCMP
keys), **WPA-PSK (TKIP)** and **WPA3-SAE**, the **802.11 data path** (LLC/SNAP),
a **DHCP client** and the **`utun` relay** are implemented and unit-tested. The
GUI is a Wi-Fi picker: it finds, opens and scans by itself, and one click on a
network joins it **and** brings the tunnel up. Scan, association and the WPA2
handshake are **verified on hardware**; WPA1 and WPA3 are implemented and
unit-tested but still wait for a real AP (§4, §5).

---

## 2. Quick start

```bash
# Prereqs: libusb + pkg-config (brew install libusb pkg-config), Rust via rustup

cargo test                                   # unit + integration tests
cargo run -- --scan                          # bring the radio up + passive scan
cargo run                                    # GUI: finds, opens and scans by itself

# One-time: install the root helper so the GUI need not run as sudo
sudo cargo run -- --install-helper           # or: sudo bash scripts/install-helper.sh
cargo run -- --helper-status                 # confirm it is running

# macOS .app bundle (+ DMG) with the firmware bundled in:
bash scripts/bundle-macos-app.sh
open dist/MT7601U.app
```

The firmware blob is **not** vendored. `--scan`, `--init` etc. locate it via
`src/paths.rs` (`find_firmware()`): `$MT7601U_FIRMWARE`, then
`Contents/Resources/mt7601u.bin` inside a bundle, then `mt7601u.bin`,
`mediatek/mt7601u.bin`, `mt7601u-refs/linux-firmware/mediatek/mt7601u.bin`, then
`~/.mt7601u/mt7601u.bin`, `~/Downloads/mt7601u.bin`.
The bundle script copies the blob from the local reference clone into
`Contents/Resources/` **before** codesigning.

---

## 3. ⚠️ Read this before running anything

**If the MCU command path wedges, the dongle needs a physical replug.** The code
no longer calls `reset()` anywhere, so a fresh bring-up should work; this section
is here because the failure mode is easy to hit.

Cause (seen in an earlier session): calling `libusb_reset_device` (mirroring
`usb_reset_device()` in the Linux `probe()`). On macOS this invalidates the
libusb handle and leaves the device's MCU in-band command path unresponsive —
`phy_set_channel` then fails with
`set channel 1: libusb error: Operation timed out`.

* **Fix: unplug and replug the dongle.** The code no longer calls `reset()`
  anywhere; re-running a full bring-up after a replug should work.
* Note `--identify`, `--read-eeprom` and `--diagnose` still work (plain control
  transfers), so the USB layer is fine — only MCU commands are stuck.
* The code now detects this: `scan::mcu_recovery_hint()` appends a "replug the
  dongle" hint to any error whose message contains `MCU response … not received`
  or `Operation timed out`, in both the CLI and the GUI log.
* A **second program holding the device open** produces the same symptom (its
  bulk-IN reads steal the MCU `CMD_DONE` responses). Make sure only one instance
  (GUI *or* CLI) has the MT7601U open.
* **Reopening the device is no longer one of these cases.** Closing the USB
  handle (GUI **Stop**, then **Start**, or a rescan after an earlier run) left the
  device unable to answer MCU commands, because the reopen skipped the init that
  arms the DMA the command channel rides. `bringup` now re-initializes a running
  device in full (§8 item 2), so Stop → Start and rescans work with no replug —
  **verified on hardware 2026-10-16** with `cargo run --example reopen_probe`
  (rescan, Stop → Start ×3, and reopen after an unclean close all pass), and it
  also recovers in place a dongle left wedged by the old code.

---

## 4. Verified on hardware (2026-10-15)

| Command | Result |
| --- | --- |
| `--identify` | `ASIC version 0x76010001`, MAC CSR0 `0x76010500`, eFuse present |
| `--load-firmware <bin>` | MCU reported running; repeatable |
| `--init` | post-init + MCU `Q_SELECT` acknowledged (`CMD_DONE`) |
| `--hw-init` | MAC/BBP initvals, WCID/key memory, counters — no timeouts |
| `--read-eeprom` | MAC `88:82:79:24:0e:c0`, EEPROM v0x0d, channels 1–14 |
| `--scan` | **7 live networks** with SSID/BSSID/channel/security, repeatable |
| `cargo run --example reopen_probe` | Rescan on one handle, GUI Stop → Start ×3, and reopen after an unclean close: **all pass with no replug**. With the pre-fix skip, all of them failed with `set channel 1: MCU response for seq 1 not received` (2026-10-16) |
| GUI **Connect** (WPA2) | `Associated with "HaLePo" (AID 1)` + `WPA2 keys installed` — **the 4-way handshake completes on hardware** |
| GUI **Start tunnel** | `Created utun4`, then DHCP failed (see §13) — **in progress**. The picker starts the tunnel as part of joining, so there is no separate button |

Example scan output (real beacons, over the air):

```
MD                               00:4c:e5:f9:3b:03 ch  2  WPA2/WPA3
4G-MIFI-94EC                     14:cb:49:0d:94:ec ch  3  WPA2/WPA3
YGT                              2c:b6:c2:13:43:56 ch  3  WPA2/WPA3
Zee                              72:e2:53:fe:37:93 ch 11  WPA2/WPA3
...
7 network(s) found.
```

---

## 5. Working / not working

**Working:** USB enumerate/claim, descriptors, vendor control transfers, register
r/w, firmware upload, MCU command channel, MAC/BBP initvals, WCID/key memory,
eFuse/EEPROM, RF tables + calibration, `phy_set_channel`, `set_rx_path`/
`set_tx_dac`, `mac_start`, RX path (segments + RXWI), passive scan, the TX path
(TXWI + DMA framing + frame builders), station register setup (own MAC, WCIDs,
BSSID, basic rates, TSF, slot), open-system association, **WPA2-PSK** (PMK/PTK
derivation, 4-way handshake, GTK unwrap, pairwise + group key installation),
**WPA-PSK (TKIP)** (WPA1 IE, group-key handshake, MIC key swap) and
**WPA3-SAE** (dragonfly P-256 exchange, CMAC 4-way from the SAE PMK), the
802.11 data path (LLC/SNAP), a DHCP client, the `utun` relay and the
**privileged helper** — all unit-tested, and all driven by the GUI, where one
click on a network joins it and starts the tunnel.

**Not working / absent:**
* **DHCP and the tunnel relay are implemented but not verified on hardware**;
  scan, association, the WPA2 handshake and the data path *are* verified. See §13.
* **WPA1 and WPA3 are unit-tested but not verified on hardware** — and the
  MT7601U has no PMF, so a WPA3-only AP that enforces 802.11w cannot be joined.
* TSSI DC/gain calibration + temperature compensation (TX power control).
* HT/protection setup (`mt7601u_mac_set_protection` is not ported).
* The tunnel needs privilege — the helper (preferred) or `sudo`; on macOS 15+
  DNS is only "supplemental" without a signed system extension.
* Active scan is exercised only by `--tx-probe`; the scan command is still passive.
* RSSI in dBm (RXWI `gain`/`snr` are parsed but not converted).
* No deauthentication frame is sent on disconnect (the association is dropped
  locally only).
* No ARP: outbound unicast frames are addressed to the AP and rely on it to
  forward by IP.

---

## 6. Source map (this project)

```
src/
  main.rs              CLI: --diagnose --identify --load-firmware --init --hw-init
                            --read-eeprom --scan --tunnel-demo
                            --install-helper --uninstall-helper --helper-status
                            --helper-daemon ; GUI launch
  lib.rs               module list
  paths.rs             find_firmware()
  helper/
    mod.rs             socket protocol (framing) + osascript installer
    server.rs          root daemon: utun + ifconfig/route/scutil + packet pump
    client.rs          GUI-side client (PacketTun + TunnelLink)
  tunnel/
    mod.rs             re-exports + TunnelState + TunnelLink trait
    utun.rs            Utun: AF_SYSTEM socket, ifconfig/route/scutil, rollback
    relay.rs           utun ⇄ Wi-Fi packet relay (PacketTun, Stats)
    icmp.rs            IPv4/ICMP echo reply + checksum (pure, tested)
  net/
    mod.rs             IpLink trait (station ↦ tunnel contract)
    ipv4.rs            IPv4/UDP framing + checksum (pure, tested)
    dhcp.rs            DHCPv4 client codec + exchange (pure, tested)
  app.rs               egui UI (Wi-Fi picker, details drawer, log console)
  app_state.rs         AppState + LogBuffer (pure, testable)
  theme.rs             design tokens + the egui style
  commands.rs          Command / Event enums (Debug redacts passwords)
  credentials.rs       saved passphrases + preferences (0600 file, pure codec)
  backend.rs           worker thread; auto pipeline, join+tunnel, relay loop
  logging.rs           LogLine / LogLevel
  usb/
    enumerate.rs       descriptor model, DeviceInfo, UsbError, find_mt7601u()
    transport.rs       Transport trait + RusbTransport (control/bulk in+out)
  mt7601u/
    regs.rs            register offsets/bits (transcribed from regs.h/mcu.h)
    dma.rs             TX/RX DMA framing (dma.h) — pure, tested
    device.rs          Mt7601u<T>: vendor reqs, registers, chip_onoff,
                       firmware upload, init_after_firmware
    firmware.rs        firmware image parsing (pure, tested)
    mcu.rs             MCU command channel (send/response, reg-pair/burst writes)
    initvals.rs        initvals.h MAC/BBP tables
    init.rs            init_radio_registers() (init.c)
    eeprom.rs          eFuse read + EEPROM params (eeprom.c)
    rf.rs              RF register access + initvals_phy.h tables
    radio.rs           phy_init/init_cal, phy_set_channel, mac_start, BBP helpers
    rx.rs              RX segments, RXWI, beacon/IE parsing (pure, tested)
    tx.rs              TXWI + DMA framing + bulk-OUT submission
    scan.rs            bringup(), bringup_and_scan(), passive_scan()
    mac.rs             station setup: MAC addr, WCID, BSSID, basic rates, TSF
    station.rs         open-system association (associate())
    data.rs            station data path (IP ⇄ 802.11 data frames), StaLink
    testing.rs         shared mock transport (cfg(test))
  wifi/mod.rs          Network, Security, WifiState
  wifi/frames.rs       802.11 probe/auth/assoc builders (pure, tested)
  wifi/mgmt.rs         auth/assoc response parsing (pure, tested)
  wifi/data.rs         802.11 data frames + LLC/SNAP (pure, tested)
  wifi/rsn.rs          RSN information element (pure, tested)
  wifi/eapol.rs        EAPOL-Key frames + GTK KDE (pure, tested)
  wifi/wpa.rs          PMK (PBKDF2), PRF-512, MIC, RFC 3394 unwrap (pure, tested)
  wifi/handshake.rs    WPA2 4-way handshake state machine (pure, tested)
docs/                  architecture, feasibility, source map, protocol notes, ...
scripts/bundle-macos-app.sh
mt7601u-refs/          local clone of Linux driver + linux-firmware (gitignored)
```

**Key abstractions**
* `Mt7601u<T: Transport>` is generic so a `MockTransport` can test register
  encoding, MCU framing, firmware upload and the full init sequence with no
  hardware.
* The backend owns `Option<Mt7601u<RusbTransport>>`; `Drop` releases interfaces.

---

## 7. The scan path (how it works today)

`main.rs --scan` and `backend.rs::Command::Scan` both call
`mt7601u::scan::bringup_and_scan(chip, firmware, DEFAULT_DWELL)`:

1. `chip_onoff(true, false)` — enable WLAN clock, wait XTAL/PLL.
2. `let fresh = !chip.firmware_running()?` (`MT_MCU_COM_REG0 == 1`).
3. **If fresh:** upload firmware. **If not fresh:** `enable_usb_dma()` + `mac_stop()`
   — a running device is not re-flashed, but it is fully re-initialized (see §8
   item 2), which is what makes Stop → Start and rescans work without a replug.
4. `init_after_firmware()` → `init_radio_registers()` — on every open.
5. `eeprom_init()` (read-only + MAC addr + TX power).
6. `phy_init()` (RF tables + `init_cal`), `set_rx_path(0)`, `set_tx_dac(0)` —
   on every open.
7. `passive_scan()`: `agc_save` → `mac_start` → for each channel:
   `phy_set_channel` → `agc_reset` → drain bulk-IN for `DEFAULT_DWELL` (200 ms),
   parse segments → `rx::parse_beacon` → dedup by BSSID → `agc_restore`.

Errors are wrapped with the failing step (`set channel N: …`, `mac start: …`,
`agc save: …`) precisely so the next failure is diagnosable.

---

## 8. Hard-won lessons / gotchas

1. **Do not call `libusb_reset_device` on macOS** — it invalidates the handle and
   wedges the device. (Linux does it in `probe()`; we can't.)
2. **Only the firmware *upload* may be skipped on a running device — everything
   else must run.** The `fresh` guard in `bringup` exists for one reason:
   `load_firmware` → `prepare_firmware_load` sends `MT_VEND_DEV_MODE_RESET` (the
   boot-ROM hand-off), which kills a running MCU. Skipping the *whole* bring-up
   on a running device, however, is what broke Stop → Start and rescans: the
   reopen left `MT_USB_DMA_CFG` unconfigured, the in-band MCU command channel
   rides that DMA path, and so the first MCU command afterwards timed out with
   `set channel 1: MCU response for seq 1 not received` while plain control
   transfers kept working — indistinguishable from a wedged device (§3).
   Reproduced and fixed on hardware 2026-10-16: `bringup` now runs
   `enable_usb_dma` + `mac_stop` + `init_after_firmware` + `init_radio_registers`
   + `eeprom_init` + `phy_init` on a running device too, i.e. exactly
   `init.c::mt7601u_init_hardware` with only `mt7601u_mcu_init`'s upload gated.
   Linux draws the line in the same place (`mt7601u_resume` runs the whole init
   on a running device).
   *What was measured, on 2026-10-16:* with the pre-fix skip, every reopen in
   `reopen_probe` failed with that `seq 1` timeout; with the code above, every
   reopen passed. An earlier attempt that only re-armed `MT_USB_DMA_CFG` +
   `mcu_cmd_init` passed a two-process `--scan`/`--scan` but was never run
   against `reopen_probe`, so it is not known to be sufficient — prefer the full
   init.
3. **RX payloads are zero-padded.** A naive IE parser reads the trailing zeros as
   an empty SSID tag and wipes the real SSID. Fix: keep the *first* SSID/channel
   IE (`rx.rs::parse_beacon`).
4. **Never hardcode endpoints.** The inband-command OUT endpoint is the *first*
   bulk OUT in descriptor order (it is `0x08` on this unit, **not** EP4); the RX
   bulk IN is index 0 (`0x84`), the MCU-response IN is index 1 (`0x85`).
   Resolved at runtime in `device.rs`.
5. **Firmware licensing:** `linux-firmware/WHENCE` says redistributable
   (`LICENCE.ralink_a_mediatek_company_firmware`). The blob is *not* committed;
   it is located at runtime / copied into the bundle.
6. **`mt7601u_write_reg_pairs` vs `burst_write_regs`** differ: pairs are 8 bytes
   (`addr`,`value`) max 24/cmd; burst is a `MT_MCU_MEMMAP_WLAN + offset` prefix
   then 4-byte values, max 47/cmd. Only the **last** chunk waits for a response.
7. **MCU responses** are matched on `SEQ` + `EVT == CMD_DONE`, 5 attempts × 300 ms.
   If the device emits unrelated events, more attempts may be needed.

### WPA2 / data-path lessons (this session)

8. **The 802.11i nonces are 32 octets, not 16.** The PRF input is
   `min/max(AA,SPA) ‖ min/max(ANonce,SNonce)` = `6+6+32+32` = **76 bytes**. Getting
   this wrong still produces a plausible-looking PTK (I did, and only noticed by
   re-reading §8.5.1.1). `src/wifi/wpa.rs` asserts the 76-byte shape.
9. **CCMP runs in the hardware.** Only the key schedule is in Rust: PMK
   (`PBKDF2-HMAC-SHA1`), PTK (`PRF-512`), the EAPOL MIC (`HMAC-SHA1-128`), and
   RFC 3394 unwrapping of the GTK. Do **not** hand-roll AES-CCMP.
10. **After the 4-way handshake the AP only sends encrypted frames.** The receive
    path must accept frames whose Protected bit is set when
    `MT_RXINFO_DECRYPT` (`BIT(16)`) is set — otherwise everything after
    association (DHCP replies, ARP, real traffic) is silently dropped.
    This is exactly what broke DHCP: the tunnel's DHCP link was built *without*
    `StaLinkInfo::encrypted()`, so `wifi::data::parse` rejected every reply. Use
    `data::parse_decrypted` for hardware-decrypted frames.
11. **Group addressing matters in both directions.** Received frames addressed to
    a broadcast/multicast MAC (DHCP replies are broadcast) must be accepted —
    check the I/G bit (`mac[0] & 1`), not just equality with our MAC. And
    outbound broadcast/multicast IP must set Address 3 to `ff:ff:ff:ff:ff:ff`,
    not the BSSID, or the AP consumes rather than forwards it.
12. **A WPA2-only AP rejects an association request without an RSN IE**, so
    `associate_wpa2` appends `rsn::build_psk_ccmp()` (and sets the Privacy bit in
    the capability field).
13. **DHCP needs retries.** Association has just completed and the first
    DISCOVER is easily lost; `net::dhcp::obtain` retransmits DISCOVER/REQUEST
    up to 3 times.
14. **GTK KDE length is `0x0e`** (14): `dd 0e 00 0f ac 01 <keyid> 00 <gtk…>`.
    An off-by-one here makes the KDE parse fail.
15. **RX frames can carry two bytes of L2 padding.** `MT_RXINFO_L2PAD`
    (`BIT(14)`) means the hardware inserted 2 bytes after the 802.11 header to
    4-align the L2 payload; `mt7601u_rx_skb_from_seg` does `data += hdr_len + 2`.
    This happens for **QoS data frames** (26-byte header). Ignoring it makes the
    LLC/SNAP lookup read the padding instead of `aa aa 03`, so every QoS data
    frame is dropped — management/EAPOL frames (24-byte header, no pad) still
    parse, which is why scan, association and the 4-way handshake worked while
    **DHCP silently failed** (`src/mt7601u/rx.rs::is_l2_padded`,
    `wifi::data::parse_rx`).
16. **Broadcast and unicast frames use different WCIDs, and that selects the
    key.** `mt7601u_dma_enqueue_tx` picks the key by WCID: unicast data frames go
    on the AP's *station* WCID (`STA_WCID`, holding the pairwise TK), and
    broadcast/multicast frames (DHCP!) on the *group* WCID (`GROUP_WCID_0` = 126,
    holding the GTK). `mt7601u_set_key` with `sta == NULL` programs the GTK into
    **both** the group WCID key slot and the shared-key table (the latter is what
    decrypts group-addressed RX). Framing the DHCP `DISCOVER` on a WCID holding
    the pairwise key encrypts it with the wrong key and the AP drops it.
17. **Set the Protected bit on frames the hardware will encrypt.** mac80211 sets
    `IEEE80211_FCTL_PROTECTED` on every keyed frame before it reaches the driver
    (`ieee80211_tx_set_protected`); the mt7601u `tx.c` never touches it, so it
    must already be set in the 802.11 header. The hardware encrypts based on the
    WCID alone. Miss this and the AP sees a frame flagged *unprotected* whose
    payload is CCMP ciphertext, parses the CCMP header as LLC/SNAP, and silently
    drops it — which is exactly how the first **encrypted** uplink frame (the
    DHCP `DISCOVER`) failed while unencrypted EAPOL and association worked
    (`wifi::data::build_tx`'s `protected` argument).

---

## 9. Association → WPA2 → IP — status

Steps 1–4 below are **implemented**; see §5 for what is verified. The remaining
work is hardware verification and the open items in §5/§13.

### Step 1 — TX path (prerequisite for everything) — **DONE (unverified on air)**

Implemented in `src/mt7601u/tx.rs` + `src/wifi/frames.rs`:
* `tx::build_txwi` builds `struct mt76_txwi` (20 B: flags, rate_ctl, ack_ctl,
  wcid, len_ctl with the packet id, then zeroed IV/EIV/AID/TXSTREAM/CTL).
* `tx::rate_val` / `tx::pkt_id` transcribe `mt76_mac_tx_rate_val` and
  `mt7601u_tx_pktid_enc`.
* `tx::tx_frame` wraps `[TXWI][frame]` with `dma::info_word(TYPE=DMA_PACKET,
  D_PORT=WLAN_PORT, LEN=round_up)` + `PKT_INFO_80211 | PKT_INFO_WIV |
  QSEL<<25` and writes it to the bulk OUT endpoint.
* `tx::ac_endpoint(ac)` maps `q2ep(q2hwq(ac))`; AC_BE → `0x05`, AC_BK → `0x04`
  on the reference device.
* `wifi::frames` builds probe requests, open-system auth and assoc requests
  (unit-tested byte layouts).
* `--tx-probe <ch>` brings the radio up, sets the channel, transmits a wildcard
  probe request and counts probe responses/beacons for 3 s.

**Not yet verified on the air** — the CLI test needs the interface free (quit
`MT7601U.app`, or press **Stop** in it). Expected: `Probe responses: N > 0`.

### Step 2 — Station setup + association — **DONE (unit-tested; unverified on air)**

Implemented in `src/mt7601u/mac.rs` + `src/mt7601u/station.rs` +
`src/wifi/mgmt.rs`, wired to `cargo run -- --connect <ssid> [<ch> [<bssid>]]`:
* `mac.c::mt7601u_mac_wcid_setup` — WCID attribute (VIF index) + address.
* `main.c::mt7601u_bss_info_changed` — own MAC (`set_macaddr`, with the
  `DW1_U2ME` field), BSSID, basic rates (`MT_LEGACY_BASIC_RATE`,
  `MT_HT_FBK_CFG0/1`, `MT_LG_FBK_CFG0/1`), TSF/beacon interval, short preamble
  and slot time. *Protection/HT is not ported.*
* Build and send **auth** (open) then **assoc request**; parse auth/assoc
  responses from the RX path (`wifi/mgmt.rs`).
* `mt7601u_mac_config_tsf` is ported (note: upstream omits the final write in
  the enable path; this port writes it).

**Not yet done here:** `mt7601u_phy_con_cal_onoff` /
`mt7601u_phy_recalibrate_after_assoc` (they only feed frequency-offset tracking,
which is RSSI/beacon-monitoring work), and verification on hardware.

Original plan notes kept below for reference:
* `mac.c::mt7601u_mac_wcid_setup` — program a WCID entry for the AP MAC.
* `main.c::mt7601u_bss_info_changed` — BSSID (`mt7601u_addr_wr(MT_MAC_BSSID_DW0,…)`),
  basic rates (`MT_LEGACY_BASIC_RATE`, `MT_HT_FBK_CFG0/1`, `MT_LG_FBK_CFG0/1`),
  beacon interval / TSF, protection, short preamble, slot time.
* Build and send **auth** (open) then **assoc request**; parse auth/assoc
  responses from the RX path.
* `mt7601u_mac_config_tsf`, `mt7601u_phy_con_cal_onoff`,
  `mt7601u_phy_recalibrate_after_assoc` after association.

### Step 3 — WPA2 (the hard part) — **DONE (association + handshake verified on hardware)**

Implemented in `src/wifi/{rsn,eapol,wpa,handshake}.rs` + `src/mt7601u/station.rs`
(`associate_wpa2`) and `src/mt7601u/mac.rs` (key installation):
* PMK = `PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256)`; PTK = `PRF-512` over
  `min/max(AA,SPA) ‖ min/max(ANonce,SNonce)`. Validated against the published
  802.11i PMK vector (`IEEE`/`password`) and a cross-checked PTK/MIC.
* RSN IE in the association request (a WPA2-only AP rejects without it).
* 4-way handshake: EAPOL-Key message 1 → 2 (SNonce + RSN IE + MIC), message 3
  (MIC verify + RFC 3394 GTK unwrap) → 4.
* Key installation: `main.c::mt7601u_set_key` →
  `mac.c::mt76_mac_wcid_set_key` / `mt76_mac_shared_key_setup`
  (`MT_WCID_KEY`/`MT_WCID_IV`/`MT_WCID_ATTR`, `MT_SKEY`). **CCMP runs in the
  hardware**, so no cipher is implemented in Rust.
* Crypto uses the audited RustCrypto crates (`sha1`, `hmac`, `pbkdf2`, `aes`).

**Later additions (same pattern, unit-tested only):** WPA-PSK (TKIP) in
`associate_wpa1` + the WPA1 group handshake, and WPA3-SAE in `src/wifi/sae.rs`
+ `station::associate_sae` with the same 4-way over `ptk_sae`.

**Not done here:** `mt7601u_mac_set_ampdu_factor` / `mt76_ampdu_action`
(aggregation).

### Step 4 — IP — **DONE (unit-tested; DHCP/tunnel unverified on hardware)**
Data path (`wifi/data.rs`, `mt7601u/data.rs`), DHCP client (`net/`) and the
relay (`tunnel/relay.rs`) are implemented and driven by the GUI. Works on open
and WPA2 networks.

**Suggested first action in the fresh thread:** with the dongle plugged in, run
`cargo run -- --scan` to confirm the baseline, then finish verifying the
end-to-end path:

* `cargo run -- --tx-probe <ch>` — confirm `Probe responses: N > 0`.
* **WPA2 association is already verified** (`cargo run` → click the network in
  the picker, or `MT7601U_PSK=… cargo run -- --connect "SSID"`).
* **Next: verify the tunnel.** `cargo run` → click the network in the picker; the
  tunnel starts as part of joining. Success is `Address … from the network`
  followed by `Tunnel … is up`, then
  `ping 8.8.8.8` (or `curl`) from another terminal. If DHCP still fails, work
  through §13.
* Watch for `[INFO] Created utun4` followed by a DHCP error — that points at the
  DHCP/link layer, not the tunnel interface.

WPA (TKIP) and WPA3 (SAE) are implemented and unit-tested but not yet verified
on a real AP: `MT7601U_SECURITY=wpa` / `wpa3` exercises them directly, and the
picker offers them now.

---

## 10. Working agreements / quality bar

* `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test` must stay green. Currently **357 unit + 7 integration** tests pass.
* Keep the "honesty" rule: never claim association / IP / native Wi-Fi works
  until it is demonstrated on hardware. The GUI must not fabricate state.
* Every register/poll/transfer is bounded (timeouts + deadlines). Firmware images
  are size-validated before any I/O. Credentials never go into `LogLine`.
* Cite the Linux source for hardware behaviour instead of guessing.
* Docs to keep current when behaviour changes: `README.md`,
  `docs/architecture.md`, `docs/firmware-and-registers.md`,
  `docs/protocol-notes.md`, `docs/driver-source-map.md`, `docs/test-plan.md`.

---

## 11. Diagnostics cheat-sheet

```bash
cargo run -- --list            # enumerate, one line per device
cargo run -- --diagnose        # full descriptors + open/claim
cargo run -- --identify        # ASIC/MAC revision, eFuse present
cargo run -- --read-eeprom     # MAC, channels, TX power table
cargo run -- --scan            # full bring-up + passive scan (auto firmware)
MT7601U_PSK='passphrase' cargo run -- --connect "SSID"   # associate (WPA2)
cargo run -- --connect "SSID"  # associate (open network)
cargo run -- --connect "SSID" 6 14:cb:49:0d:94:ec   # …or give channel + BSSID directly
sudo cargo run                 # GUI (helper installed: no sudo needed) — it scans by itself
cargo run -- --tx-probe 1      # transmit a probe request on channel 1 (TX test)
sudo ./target/debug/mt7601u-macos --tunnel-demo 30   # utun + ping 10.9.9.2
sudo mt7601u-macos --install-helper    # install the privileged helper (gui: button)
cargo run -- --helper-status           # is the helper running?
MT7601U_FIRMWARE=/path/to/mt7601u.bin cargo run -- --scan
```

> Only one process can claim the interface at a time: if `MT7601U.app` is open
> (and you pressed **Open**), the CLI will fail with `Access denied`. Quit the
> app or press **Close** first.

Tracing is `INFO` by default (`main.rs::init_tracing`). Add `tracing::info!`
freely during bring-up; `scan.rs` already wraps failures with the step name.

---

## 12. macOS tunnel — implemented, and now wired to the Wi-Fi data path

`src/tunnel/` provides the "make it look like a normal network to macOS" half,
modelled on `mt7601u-refs/BetterTether` (Go) — same mechanism, reimplemented in
Rust:

* **`utun.rs`** — creates a `utunN` interface via `AF_SYSTEM` /
  `SYSPROTO_CONTROL` / `com.apple.net.utun_control` (the `CTLIOCGINFO` ioctl +
  `sockaddr_ctl` connect + `UTUN_OPT_IFNAME`). Then `ifconfig <name> <local>
  <peer> mtu up`, the two "more specific" default routes (`0.0.0.0/1`,
  `128.0.0.0/1`) so the existing default route survives, and `scutil` to register
  the service as **PrimaryService** with DNS (macOS ≥15 only treats a virtual
  interface as "online" when `State:/Network/Global/IPv4` has `PrimaryService`).
  `teardown()` — called from `Drop` — removes the routes and DNS state.
* **Framing**: reads are `[4-byte AF][IP packet]`; writes must prepend the
  4-byte header. `frame_ipv4` / `parse_frame` do this; `AF_INET = 2`,
  `AF_INET6 = 0x1e`.
* **`relay.rs`** — the packet relay (`PacketTun`, `Stats`): `utun → Wi-Fi` (an
  IP packet from macOS is encapsulated in an 802.11 data frame) and
  `Wi-Fi → utun` (an inbound IP packet is framed with the 4-byte header and
  written back). Unlike BetterTether there is **no Ethernet header** — `utun` is
  layer 3 and the 802.11 data frame carries IP via LLC/SNAP.
* **`net/`** — `IpLink` (what the relay/station implement), IPv4/UDP framing and
  the DHCP client used to get an address from the AP.
* **`icmp.rs`** — pure IPv4/ICMP echo-reply builder + RFC 1071 checksum
  (unit-tested). Used by the self-test.
* **`helper/`** — the privileged plumbing as a root LaunchDaemon (modeled on
  BetterTether's launchd daemon): `utun` creation + `ifconfig`/`route`/`scutil`
  + a packet pump over `/var/run/mt7601u-helper.sock`. The GUI connects and,
  when it is not root, uses it as its `TunnelLink`; DHCP still runs in the GUI
  (the helper cannot hold the USB device).

The GUI drives the whole thing: it finds, opens and scans by itself, and one
click on a network joins it and starts the tunnel, with
the relay running on the backend worker between command polls.

### Privileges: the helper (preferred) or `sudo`

```bash
sudo cargo run -- --install-helper    # or: sudo bash scripts/install-helper.sh
cargo run -- --helper-status
```

The GUI's tunnel panel also has an **Install helper…** button that runs the
installer through `osascript … with administrator privileges`, so macOS shows
the standard administrator-password dialog (the usual path for an unsigned
helper installer; `SMJobBless` would need a Developer ID). Without the helper
the tunnel falls back to in-process `utun` when the GUI is root.

### Self-test (needs root — `utun` creation itself is privileged on macOS)

```bash
cargo build
sudo ./target/debug/mt7601u-macos --tunnel-demo 30
# in another terminal:
ping 10.9.9.2
```

This proves **macOS → utun → our code → utun → macOS** with real ICMP, without
any Wi-Fi involvement.

### What still has to happen for real internet

```
[AP] <-802.11-> [MT7601U] <-USB-> [station: WPA2 assoc + LLC/SNAP + HW CCMP]
                                        |
                               IP packets over 802.11 data frames
                                        |
                                  [DHCP client]  (get IP from the AP)
                                        |
                                     [utun]  -> macOS network stack
```

Every box now exists. Association + the WPA2 handshake are verified on hardware;
DHCP and the relay are implemented but **not yet verified**.

---

## 13. Troubleshooting

### `Scan failed: set channel 1: MCU response for seq 1 not received`

The MCU in-band command channel has stopped responding (§3). Two causes:

1. **A wedged device** — unplug and replug the dongle. There is no software
   recovery (macOS cannot use `libusb_reset_device`).
2. **Two programs holding the device open** (e.g. an old GUI still running plus a
   new `sudo cargo run`, or a CLI run alongside the app). Bulk-IN reads on `0x85`
   steal each other's `CMD_DONE` responses. Quit every other instance first.

This is *not* what a Stop → Start or a rescan produces any more: `bringup`
re-initializes a running device in full (§8 item 2). If it happens anyway, it is
1 or 2 above — and if the dongle really is wedged, opening it again now recovers
it in place, because a wedged MCU no longer reads as "firmware running" and the
fresh path re-uploads.

`cargo run --example reopen_probe` drives exactly these cycles (rescan, Stop →
Start, reopen after an unclean close) against the physical device.

The code now appends a replug hint automatically (`scan::mcu_recovery_hint`).

### `DHCP failed: no DHCP response (message type 2); the AP did not answer a DISCOVER after 3 tries`

The AP did not answer the DHCP DISCOVER. The failure now prints a
**frame list** (`Frames seen while waiting`) — read it first:

1. **No frames listed** → the AP is not answering the DISCOVER, i.e. the uplink
   is not being accepted. Two known causes, both fixed:
   * the frame is encrypted by the hardware but its 802.11 **Protected bit** is
     clear, so the AP parses ciphertext as LLC/SNAP (§8 item 17);
   * the frame is encrypted with the **pairwise** key instead of the group key
     (§8 item 16) — unicast must use `STA_WCID`, broadcast `GROUP_WCID_0`.
   Verify the GTK was installed (`WPA2 keys installed` in the log).
2. **Frames listed but each says `rejected by the parser`** → we received the
   reply and mis-parsed it. The `l2pad` flag in the line is the usual culprit
   (§8 item 15); a `decrypt false` on an encrypted frame means the group key was
   not installed correctly.
3. **Frames listed and `accepted, ethertype 0x0800` but DHCP still fails** → the
   problem is above the 802.11 layer (UDP port, BOOTP fields, xid).
4. The AP really has a DHCP server (some enterprise/hotspot APs do not).
5. `obtain` retries DISCOVER/REQUEST 3× before failing (§8 item 13).

Also make sure the association is still live: a `--scan` (or a rescan in the
picker) mid-join retunes the radio and breaks it. The picker does not scan while
it is joining or relaying.

### `Guard: "… is WPA2; enter the password first"` / unsupported security

**Open**, **WPA-PSK (TKIP)**, **WPA2-PSK** and **WPA3-SAE** are supported. WEP
and unknown security are refused explicitly. Note that WPA3 only works on APs
that allow non-PMF stations (the MT7601U has no 802.11w) and WPA1/WPA3 are not
hardware-verified yet.

### Tunnel buttons do nothing / `privileges` shows `helper not installed`

Creating the `utun` interface needs privilege. Either press **Install helper…**
in the tunnel panel (macOS asks for the administrator password, like other
helper installers), or run once in a terminal:

```bash
sudo mt7601u-macos --install-helper     # or: sudo bash scripts/install-helper.sh
cargo run -- --helper-status            # confirm it is running
```

The helper is a root LaunchDaemon (`ai.commandcode.mt7601u`) that listens on
`/var/run/mt7601u-helper.sock`; its log is `/var/log/mt7601u-helper.log`.
Launching the GUI with `sudo` also works (then privileges show `running as
root`). On macOS 15+ DNS is only "supplemental" without a signed system
extension, so some apps may not use the tunnel.

### `target/` got root-owned (builds now fail with `Permission denied`)

Running `sudo cargo run` creates root-owned files under `target/`. Fix with:

```bash
sudo chown -R "$(id -un)":staff target
```

### Recovering after a wedged device

Unplug, wait a moment, replug, then re-open. `--identify` / `--read-eeprom`
working while `--scan` fails is the signature of a stuck MCU: the USB control
path is fine, only MCU commands are dead.

