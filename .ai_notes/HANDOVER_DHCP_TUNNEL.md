# HANDOVER — DHCP / tunnel "connected but no internet" investigation

> **Superseded on 2026-10-16 — read `HANDOVER.md` § “WPA2 → DHCP → IP, fixed”
> first.** The conclusion below (the AP never accepts our 4/4, so nothing is
> bridged) described the code at the time, when message 4/4 was sent
> *protected*. It is not true of the current tree: the handshake completes on
> hardware (`handshake_confirmed = true`), and DHCP failed for a different and
> now-fixed reason — broadcast IP was framed on the group WCID (the GTK), which
> this AP does not deliver; it is now addressed to the AP and the link carries
> real traffic (DHCP lease, ARP, ICMP to `8.8.8.8`).

_Scope: why the tunnel never carries traffic, what was verified on hardware, and
what was changed. Written at the end of the session that added the DHCP frame
trace, the ARP layer, the reopen re-init, and the manual addressing controls._

Read this together with `DHCP_TUNNEL_FIX_PLAN.md` (the plan this work followed)
and the main `HANDOVER.md` (the driver as a whole).

---

## 1. TL;DR

The symptom people report — `Could not get an address (DHCP): no DHCP response
(message type 2)` — **is not a DHCP bug**. It is the tail of a failed WPA2
4-way handshake:

* our **message 2/4 is accepted** by the AP;
* our **message 4/4 is never accepted** — the AP retransmits 3/4 forever
  (observed replays 3, 4, 5, 6,…);
* an AP that never accepts 4/4 **never registers the station**, so it does not
  appear in the AP's client list and the AP **bridges nothing** for it;
* therefore DHCP is never answered, ARP is never answered, and the relay shows
  `Sent N packets / Received 0`.

Confirmation from the field, which matches this exactly: the device does **not**
appear in the router's list of connected clients.

**Status: still broken.** Everything on the host side now reads back correct
(frame bytes, MIC, keys, IV, WCID, SKEY). The remaining unknown needs an
over-the-air capture — see §8.

Since this session the app no longer pretends otherwise: when the handshake is
not confirmed the backend logs the reason and **refuses to start the tunnel**
(§5.3).

---

## 2. What was observed (hardware evidence)

All of the following was measured on the physical MT7601U against the `HaLePo`
AP (`98:25:4a:a7:53:8a`, WPA2, channel 11 at the time; it roams — ch 10 earlier).

### 2.1 The AP is stuck on message 3/4

Parsing the AP's own EAPOL-Key frames after association:

```
AP EAPOL-Key: message Some(3), key_info 0x13ca, replay 3, key_data 56 bytes,
              pair true mic true ack true secure true enc true
AP EAPOL-Key: message Some(3), key_info 0x13ca, replay 4, …
AP EAPOL-Key: message Some(3), key_info 0x13ca, replay 5, …
AP EAPOL-Key: message Some(3), key_info 0x13ca, replay 6, …
```

`0x13ca` = `EncryptedKeyData(0x1000) | Secure(0x200) | MIC(0x100) | ACK(0x80) |
Install(0x40) | Pairwise(0x8) | version 2`. Increasing replay counters are the
AP's own 3/4 retransmissions (hostapd bumps the replay counter each time), i.e.
it is **waiting for a 4/4 it accepts**.

### 2.2 The station is not registered, and nothing is bridged

* The device is absent from the router's client list.
* During the *entire* DHCP exchange the only data frames the AP sends us are
  those EAPOL-Key 3/4 retransmissions — **no IPv4 frame at all** (captured from
  the client's own receive loop, §5.1).
* A manual address (`192.168.0.123`) brings the tunnel up ("relaying") but shows
  `Sent 241 packets / Received 0`: frames leave the radio and the AP discards
  them.
* A broadcast ARP sweep for common gateways (and an ARP for `192.168.0.1`) got
  no reply.

### 2.3 Our side reads back correct

Read back from the hardware after association:

| Register | Value | Meaning |
| --- | --- | --- |
| `WCID_KEY(1)` | 16 key bytes + zeros | the pairwise TK, correct |
| `WCID_KEY(126)` | the GTK bytes | the group key, correct |
| `WCID_IV(126)` | `01 00 00 60` | PN start, KeyID 1, ExtIV set |
| `SKEY(0,1)` | the GTK bytes | group key in the shared table |
| `WCID_ATTR(1)` | `0x00000009` | PAIRWISE + PKEY_MODE=CCMP |
| `WCID_ATTR(126)` | `0x00000008` | PKEY_MODE=CCMP, not pairwise |
| `WCID_ADDR(1)` | `98:25:4a:a7:53:8a` | the AP's BSSID |
| `WCID_ADDR(126)` | `ff:ff:ff:ff:ff:ff` | broadcast (group match) |

The DHCPDISCOVER 802.11 frame built by the driver (309 bytes):

```
fc = 0x4108   (ToDS | Protected | data)
Address 1 (RA) = 98:25:4a:a7:53:8a   (the AP)
Address 2 (TA) = 88:82:79:24:0e:c0   (us)
Address 3 (DA) = ff:ff:ff:ff:ff:ff   (broadcast)
aa aa 03 00 00 00 08 00              (LLC/SNAP, EtherType IPv4)
45 00 01 15 …                        (a textbook DHCP DISCOVER, 277 bytes)
```

The TX counters (`0x170c` / `0x1710`) move when it is sent, so the hardware
accepts it for transmission.

### 2.4 Our 4/4 matches wpa_supplicant

Compared field by field with `wpa_supplicant_send_4_of_4`:

| Field | Ours | wpa_supplicant |
| --- | --- | --- |
| EAPOL-Key `key_info` | `0x030a` | msg3's key_info with ACK/Install/EncKeyData cleared = `0x030a` |
| Key Length | 16 | 16 |
| Key Replay Counter | msg3's | msg3's |
| Key Nonce | msg3's (echoed) | msg3's (copied) |
| Key Data Length / Data | 0 / empty | 0 / empty |
| MIC | HMAC-SHA1-128 over the frame with MIC zeroed | same |

The `key_info` bit values were re-checked against hostapd's `WPA_KEY_INFO_*`
(`INSTALL=BIT(6)`, `ACK=BIT(7)`, `MIC=BIT(8)`, `SECURE=BIT(9)`,
`ENC_KEY_DATA=BIT(12)`) — the driver's constants match.

---

## 3. Hypotheses ruled out (and how)

| Hypothesis | How it was ruled out |
| --- | --- |
| Our 4/4 has the wrong shape (key_info/nonce/MIC) | Field-by-field comparison with wpa_supplicant; key_info bit math vs hostapd; the MIC code is proven by msg2 being accepted |
| The PTK/KCK is wrong | msg2's MIC verifies at the AP (it advances to 3/4) |
| The keys are not installed | Register readback (§2.3) |
| The GTK is in the wrong place | Same readback; also `WCID_ADDR(126)` is the broadcast address |
| The broadcast is encrypted with the wrong key | Group WCID holds the GTK, "address = broadcast" so group RX matches it, shared table set |
| We request an ACK on a broadcast frame | Fixed (`ack_req = !is_group_address`) |
| The Protected bit is missing on keyed frames | Present (`fc = 0x4108`, asserted by a regression test) |
| The RX buffer drops the reply | Raised to 16 KiB (`MT_RX_URB_SIZE`); the trace shows the AP sends no IPv4 at all |
| The DHCP client mis-parses the reply | It never sees one; the trace records frames from the client's own loop |
| The diagnostics were looking too late | Fixed: the trace now records **inside** the DHCP receive loop |
| It needs a replug (the "already initialized" path) | `bringup` now re-runs the full init on a running device |
| The addressing cannot be retried | `SetAddressing` now re-configures the running tunnel |

---

## 4. Root-cause statement

> The AP accepts our authentication, association and EAPOL-Key 2/4, but never
> accepts our 4/4; it retransmits 3/4 until it gives up. The station therefore
> never reaches the "authorized" state, is not added to the AP's bridge or
> client list, and every frame the station sends is discarded. DHCP, ARP and
> all payload traffic fail downstream of that.

The reason our 4/4 is not accepted is **not** visible on the host: the frame is
byte-correct, the MIC is correct, the keys are installed, and the frame is
re-sent on every 3/4 retransmission (still rejected). What is left is whether
the frame leaves the radio at all — that is §8.

---

## 5. What was changed

### 5.1 DHCP/4-way diagnostics (plan item 2)

* `src/mt7601u/data.rs` — new `FrameTrace`: one received 802.11 data frame with
  type/subtype, ToDS/FromDS, Protected, all three addresses, the RXWI **WCID**
  and **key index**, decrypt/L2PAD/CRC flags, MPDU length, EtherType and a
  **rejection reason**. Recorded **from the DHCP client's own receive loop**
  (`recv_matching`), data frames only, capped at `MAX_TRACED_FRAMES` (64).
  `payload_from_frame` now delegates to `analyse()`, which produces the reason.
  `describe_rx` was removed (superseded by the trace).
* `src/mt7601u/rx.rs` — `Rxwi::wcid()`, `Rxwi::key_index()`, `Rxwi::mpdu_len()`
  (`MT_RXWI_CTL_WCID` / `_KEY_IDX` / `_MPDU_LEN`).
* `src/mt7601u/device.rs` — the trace buffer plus
  `start_frame_trace` / `stop_frame_trace` / `frame_trace` /
  `is_frame_trace_enabled` / `record_frame_trace`.
* `src/backend.rs` — `tunnel_start` wraps `dhcp::obtain` in
  `start_frame_trace`/`stop_frame_trace`; `log_rx_diagnostics` prints the trace
  (the old post-hoc read is gone).

A failed exchange now logs one line per data frame seen, e.g.:

```
Frames seen during the DHCP exchange (9):
  type 2 subtype 0, 188 bytes (mpdu 187), rxinfo 0x00002092 (decrypt false, l2pad false, crc false), protected false, toDS false, fromDS true, rx 88:82:79:24:0e:c0, tx 98:25:4a:a7:53:8a, bssid 98:25:4a:a7:53:8a, wcid 1, key 0, … accepted, ethertype 0x888e
```

### 5.2 Transmit path, pinned against the reference (plan item 3)

* `src/mt7601u/data.rs` — no ACK request on broadcast/multicast
  (`ack_req = !is_group_address`), matching mac80211's `NO_ACK`.
* RX buffer 8 KiB → 16 KiB in `data.rs` and `scan.rs` (`MT_RX_URB_SIZE`).
* Regression test `dhcp_discover_tx_descriptor_matches_the_reference` pins the
  DISCOVER descriptor: group WCID, WIV clear, Protected set, no ACK, NSEQ,
  QSEL=EDCA, RA=BSSID / TA=us / DA=broadcast, LLC/SNAP + `0x0800`, payload
  verbatim. `analyse_explains_every_rejection` pins the rejection reasons.

### 5.3 4-way handshake (`src/mt7601u/station.rs`, `src/wifi/`)

* **The group WCID keeps `ff:ff:ff:ff:ff:ff`**, not the AP's BSSID, and its drop
  bit is cleared. `init_wcid_mem` gives every WCID the broadcast address and
  Linux never programs the group WCID's address; that is what makes
  group-addressed RX match the entry holding the GTK.
* **4/4 is sent protected**: the PTK (and GTK) are installed as soon as 3/4
  verifies (`install_keys`), so 4/4 goes out keyed — mac80211's order.
* **4/4 echoes the Key Nonce from 3/4** (`build_message4(replay, nonce, kck)`),
  as `wpa_supplicant_send_4_of_4` copies it.
* **Retransmitted 3/4 are answered** for `EAPOL_RETRY_GRACE` (1.5 s), polling
  with `EAPOL_POLL_TIMEOUT` (250 ms); a duplicate 3/4 is ignored rather than an
  error.
* **`Association.handshake_confirmed`** — false when a 3/4 arrived after we
  answered one, i.e. the AP did not accept our 4/4.

### 5.4 Reachability, so the link is usable once it works (plan item 5)

* **`src/net/arp.rs` (new)** — Ethernet/IPv4 ARP codec (`parse`, `request`,
  `reply`), `next_hop(destination, our, mask, gateway)` and `ArpCache`.
* **`src/net/ipv4.rs`** — `same_subnet(a, b, mask)`.
* **`src/backend.rs`** — the relay resolves the next hop and addresses unicast
  frames to its MAC (`send_ipv4`), sends a rate-limited ARP request while the
  next hop is unknown (`request_arp`, `ARP_RETRY` = 1 s), and answers ARP
  requests for our own address / learns from replies (`answer_arp`). The cache
  is cleared per link and per new lease. This is what turns "Sent N / Received
  0" into a working link: previously every unicast frame named the AP's own MAC
  (so the AP consumed it) and nothing answered ARP for our address (so the
  gateway had nowhere to send replies).
* `LinkDetails.subnet_mask` so the relay knows what is on-link.

### 5.5 Manual controls (TetherKit-style) + retry

* `src/commands.rs` — `Addressing { Dhcp, Manual { address, gateway, dns } }`,
  `Command::SetAddressing`, `Event::Addressing`.
* `src/credentials.rs` — the choice is persisted (`addressing` line, `dhcp` or
  `manual <addr> <gw> <dns,…>`; a damaged line falls back to DHCP).
* `src/backend.rs` — `tunnel_start` uses `Manual` to skip DHCP entirely and
  configure the interface from the entered address; **`set_addressing`
  re-configures a running tunnel immediately**, so a new or corrected address
  takes effect at once instead of needing a disconnect/reconnect.
* `src/app_state.rs` — `addressing`, the typed `manual_address`/`_gateway`/
  `_dns` fields, `manual_problem`, and `manual_addressing()` (validated).
* `src/app.rs` — a **Tunnel address** section in the details drawer:
  *Automatic (DHCP)* / *Manual* with Address, Router and DNS fields, validation
  errors, and persistence.

### 5.6 Honesty (the "it says connected but the router disagrees" fix)

* `src/backend.rs` — when `!handshake_confirmed` the backend logs a warning at
  connect time and **`tunnel_start` refuses to start**, reporting:

  > The AP is still retransmitting the WPA2 handshake (message 3/4): it never
  > accepted our reply, so this device is not registered with it and cannot
  > reach anything. Nothing was started.

### 5.7 Reopen re-init (already in the tree, kept)

`bringup` now re-runs the full init (`enable_usb_dma`, `mac_stop`,
`init_after_firmware`, `init_radio_registers`, `phy_init`) on a device whose
firmware is still running, so Stop/Start and rescans converge on the same state
as a fresh device without a replug. Its two tests
(`reopen_rearms_the_usb_dma_the_mcu_channel_rides_on`,
`reopen_brings_the_mcu_channel_up_without_reuploading_firmware`) pass.

---

## 6. What is verified vs. not

**Verified on hardware**

* The DISCOVER frame, the 4/4 shape, all key/IV/ATTR/SKEY/WCID readbacks (§2).
* The AP is stuck on 3/4 and sends no IPv4 during the DHCP exchange (§2.1, §2.2).
* Our association + msg2 are accepted; the AP never accepts 4/4.
* `handshake_confirmed` reports false against this AP.

**Implemented and unit-tested, not verifiable while the link is unbridged**

* The ARP layer and the next-hop relay (no ARP reply can come back until the
  station is registered).
* The manual addressing / retry path (it brings the interface up, but nothing
  flows for the same reason).
* The reopen re-init and the DHCP frame trace (the trace itself works and is
  what produced §2.2).

**Not done**

* Internet access; the handshake does not complete.
* `HANDOVER.md`/`README.md` were intentionally not updated with a "works" note —
  per the plan, that waits for a real lease and end-to-end traffic.

---

## 7. Reproducing the diagnosis

Prerequisites: the dongle is the only thing holding the device (quit any other
`MT7601U.app`/CLI), and the AP is in range. `HaLePo` roams channels — check with
`cargo run -- --scan` first.

```bash
cargo run -- --scan                 # confirm the radio works; note SSID/channel
sudo cargo run                      # GUI: Open → Scan → Connect
```

The GUI log then shows the trace after the DHCP failure, and (with the fix here)
the refusal message instead of a false "relaying".

The interactive probes used during the investigation were temporary examples
(`examples/dhcp_trace.rs`, `examples/eapol_watch.rs`, `examples/arp_probe.rs`,
`examples/hs_check.rs`) and have been removed. To recreate the two most useful
ones, write an example that:

1. **Frame trace** — `scan::bringup`, `phy_set_channel`, `mac_start`,
   `agc_reset`, `station::associate_wpa2`, then
   `chip.start_frame_trace()`, `dhcp::obtain(&StaLink::new(&chip, info), …)`,
   `chip.stop_frame_trace()`, and print `chip.frame_trace()`; never needs
   `sudo`.
2. **EAPOL watch** — after `associate_wpa2`, loop over
   `chip.recv_frame(&info, 300 ms)` and print
   `EapolKey::parse(&frame.payload)`'s `message_number`, `key_info`, `replay`
   and `key_data.len()`. This is what showed the AP stuck on 3/4.

The CLI equivalents: `MT7601U_PSK=… cargo run -- --connect "HaLePo" 11
98:25:4a:a7:53:8a` (association/4-way only; no tunnel), and
`cargo run -- --tx-probe <ch>` for the TX smoke test.

---

## 8. The next step (this is the blocker)

**Capture the air while it connects.** Everything host-side is verified correct,
so the one open question is whether our 4/4 leaves the radio:

1. Put a second machine's Wi-Fi into **monitor mode on the AP's channel**
   (11 for `HaLePo`) and start a capture on that channel. macOS: `sudo
   airport sniff 11` (deprecated but often present) or Wireshark in monitor
   mode; any Linux box with `iw … interface add mon0 type monitor` works.
2. Trigger a connection (GUI *Open → Scan → Connect*).
3. Look for the EAPOL-Key **message 4/4** from `88:82:79:24:0e:c0` to the AP
   (`98:25:4a:a7:53:8a`), and for the DHCPDISCOVER from the same MAC.

Interpretation:

* **Our 4/4 (and the DISCOVER) are on the air, well formed** → the fault is on
  the AP's side or in how it validates the key; work around it (e.g. try a
  different AP to confirm, or match the AP's quirks) — and the ARP/DHCP work
  here becomes directly usable.
* **Our 4/4 is not on the air** (or is on the air but malformed/plaintext) →
  the fault is our TX path for keyed unicast frames. Chase the TX descriptor
  (WCID/WIV/Protected/LEN) and the key-selection path; the DHCP trace and the
  regression tests in §5.2 are the starting point.

A useful cross-check while capturing: the AP echoes our **broadcast** frames
back (a `fc = 0x62xx`, `SA = us` frame), which suggests broadcast encryption is
accepted; comparing that with the unicast 4/4 isolates whether only the unicast
key path is at fault.

---

## 9. Environment gotchas (cost real time)

* **The MCU channel wedges.** After repeated failed runs the device stops
  answering MCU commands (`set channel N: MCU response for seq 1 not received`).
  There is no software recovery on macOS — **unplug and replug**. Only one
  process may hold the device (another `MT7601U.app` or CLI steals the bulk-IN
  `CMD_DONE` responses and produces the same symptom).
* **The AP moves.** `HaLePo` was on channel 10 and then 11, and it disappears
  from range for minutes at a time; a probe hard-coded to a channel fails
  "no authentication response from the AP". Always rescan first.
* **`target/` can become root-owned** after `sudo cargo run`; fix with
  `sudo chown -R "$(id -un)":staff target`.
* Everything that touches `utun`/`route`/`scutil` needs the helper or `sudo`.

---

## 10. Where the relevant code lives

```
src/mt7601u/station.rs   associate / associate_wpa2 / run_wpa2_handshake /
                         install_keys / program_station  ← the 4-way handshake
src/wifi/handshake.rs    Wpa2Handshake state machine (pure)
src/wifi/eapol.rs        EAPOL-Key codec + build_message2/4
src/wifi/wpa.rs          PMK / PRF-512 (PTK) / MIC / RFC 3394 unwrap
src/mt7601u/data.rs      StaLinkInfo, tx path, recv_matching, FrameTrace, analyse
src/mt7601u/rx.rs        RXWI (wcid / key index / mpdu len)
src/mt7601u/device.rs    mt7601u registers, frame-trace buffer, keys via wr_copy
src/mt7601u/mac.rs       WCID/key installation (mac_wcid_set_key, shared_key_setup)
src/net/arp.rs           ARP codec, next_hop, ArpCache
src/net/dhcp.rs          DHCP client
src/backend.rs           worker: bring-up, connect, tunnel_start, relay_step (ARP),
                         set_addressing, frame-trace logging
src/tunnel/              utun + relay + helper protocol
src/app.rs               GUI (Tunnel address controls)
src/commands.rs          Command/Event/Addressing/LinkDetails
src/credentials.rs       persisted preferences incl. addressing
DHCP_TUNNEL_FIX_PLAN.md  the plan this work followed
```

Related references: `mt7601u-refs/linux/drivers/net/wireless/mediatek/mt7601u`
(`tx.c`, `dma.c`, `mac.c`, `main.c`), `mt7601u-refs/TetherKit` (the L2/feth
approach and the `ipconfig` DHCP model), `mt7601u-refs/BetterTether`.

---

## 11. Open leads (if the air capture shows our 4/4 is fine)

* The AP may require 4/4 on a specific access category; mac80211 sends EAPOL on
  AC_VO (`ep 0x07`) and we use AC_BE (`0x05`). msg2 is accepted on AC_BE, so
  this is unlikely, but it is one line to change.
* Our data/EAPOL frames use `assign_seq`; confirm the hardware-assigned
  sequence numbers are actually advancing between msg2 and msg4.
* Compare the encrypted 4/4 byte-for-byte with a Linux `mt7601u` station on the
  same AP (a USB capture on the Linux side would settle it).
