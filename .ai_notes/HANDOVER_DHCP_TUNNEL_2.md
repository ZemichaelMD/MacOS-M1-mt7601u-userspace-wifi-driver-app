# HANDOVER — tunnel, round 2: registration, RX, and the remaining DHCP question

_Continues `HANDOVER_DHCP_TUNNEL.md`, and **corrects one of its central claims**
(§2.1). Read that file first for the original diagnosis and the hardware
readbacks, then this one for what was actually wrong and what changed._

- **Status:** the station now **associates, completes WPA2, is registered by the
  AP, and relays traffic outbound**. The one thing still unproven is inbound
  traffic (replies) over the link — see §5.
- Test state: `cargo test` → 278 unit + 7 integration tests pass; `cargo clippy
  --all-targets` clean.

---

## 1. TL;DR

Three separate bugs were stacked on top of each other, all on the **station**
side, and none of them were where the first investigation looked:

1. **The AP never registered us because our 4/4 was sent *encrypted*.** The AP
   installs its copy of the PTK only when it *accepts* 4/4, so a protected 4/4 is
   undecryptable and it is dropped — the AP then retransmits 3/4 forever. That is
   the "not in the router's client list" symptom. **Fixed** by sending every
   handshake EAPOL frame in the clear and installing the keys *after* 4/4, the
   order wpa_supplicant uses (§2).
2. **Every decrypted frame was rejected by our RX parser.** The hardware does not
   strip the CCMP header when it reports `MT_RXINFO_PN_LEN`, so the LLC/SNAP
   header sits 8 bytes further along than we assumed. **Fixed** (§2.2). This is
   what made the AP's own traffic parse at all.
3. **Unicast protected RX had no key to use.** Every frame we have ever
   successfully received is broadcast/multicast. The hardware picks a received
   frame's key by matching its addresses against the WCID address table, and
   nothing held *our own* address — so unicast frames addressed to us (a DHCP
   OFFER, an ARP reply, an ICMP echo reply) had nothing to decrypt with.
   **Addressed** by programming an entry for our own address holding the PTK (§3).

What is **still open** is not a parsing problem any more: the router never
answers a DHCPDISCOVER that provably reaches it, and we could not yet confirm
that inbound *unicast* frames survive the radio. §5.

---

## 2. What was wrong, in order

### 2.1 The 4/4 was sent encrypted — the AP never registered us

The previous handover stated:

> mac80211 installs the PTK once 3/4 has been verified, so the final 4/4 message
> goes out *protected*.

**That is not true for the initial 4-way handshake, and acting on it was the
blocker.** Two independent confirmations:

* The upstream `ath12k` patch "fix encrypted EAPOL TX in encap offload mode"
  describes mac80211 handing (only) the **initial** handshake's EAPOL frames to
  the driver **unencrypted**; it is EAPOL during **GTK re-keying** — with the
  PTK already live — that carries a cipher.
* The decisive protocol argument: hostapd installs its copy of the PTK for **RX**
  when it processes 4/4. Before that there is no key to decrypt with, so a
  protected 4/4 is dropped at the AP's driver and never reaches hostapd. The AP
  then retransmits 3/4 (which is exactly what the first handover captured:
  replays 3, 4, 5, 6…).

wpa_supplicant's order is "send 4/4, *then* install the PTK"; the handshake's
EAPOL frames are all transmitted in the clear.

**Change** (`src/mt7601u/station.rs`, `run_wpa2_handshake`):

* the reply (2/4 or 4/4, including any 4/4 sent in answer to a retransmitted 3/4)
  is transmitted with an **unencrypted** `StaLinkInfo`;
* `install_keys` runs **after** 4/4 and no longer mutates the link info.

`install_keys` is now `install_keys(chip, &handshake)`.

### 2.2 The CCMP header is left in the frame — our parser looked 8 bytes early

The first over-the-air trace from the *new* build showed every received data
frame being rejected:

```
type 2 subtype 0, 336 bytes (mpdu 333), rxinfo 0x001120e2 (decrypt true, …),
protected true, toDS false, fromDS true, …, wcid 1, key 1,
rejected: no LLC/SNAP header at the expected offset
```

`MT_RXINFO_PN_LEN` (`GENMASK(21, 19)`, = 2 here) is **non-zero**, which is
precisely the condition under which the Linux `mt7601u` driver clears
`RX_FLAG_IV_STRIPPED` and lets mac80211 strip the CCMP header in software
(`mac.c`: `if (rxinfo & MT_RXINFO_PN_LEN) status->flag &= ~RX_FLAG_IV_STRIPPED;`).
So the payload is `[802.11 hdr][CCMP 8][LLC/SNAP][IP]`, not
`[802.11 hdr][LLC/SNAP]`.

**Change:**

* `src/mt7601u/rx.rs` — `Rxwi::has_crypto_header()` reads `MT_RXINFO_PN_LEN`.
* `src/wifi/data.rs` — `CCMP_HEADER_LEN = 8`; `parse_rx` takes the flag and skips
  the header. Because the hardware does not report its pad/IV flags reliably,
  for a **protected** frame that does not land on the LLC/SNAP prefix the parser
  falls back to locating `aa aa 03` at the plausible offsets
  (`base`, `base+2`, `base+8`, `base+10`). Neither a CCMP header nor an L2 pad
  can begin with `aa aa 03`, so the search is unambiguous.
* `src/mt7601u/data.rs` — `analyse` / `payload_from_frame` take the flag
  (threaded from `recv_matching` and `trace_segment`).

**Proof it works:** the AP's own frames now parse —
`accepted, ethertype 0x0800` (mDNS/IPv4), `0x86dd` (IPv6), `0x0806` (ARP).

### 2.3 Unicast protected RX: nothing held our own address

Everything received so far is group-addressed (mDNS `01:00:5e…`, IPv6
`33:33…`, broadcast ARP, and the AP's echo of our own broadcast DISCOVER). A
**unicast** protected frame had never been seen — and OFFERs, ARP replies and
echo replies are all unicast.

The hardware resolves a received frame's decryption key by matching the frame's
addresses against the **WCID address table** — that is exactly why the group
WCID must keep the broadcast address (see `HANDOVER_DHCP_TUNNEL.md` §5.3).
Nothing held *our* address, so a frame addressed to us had no key.

**Change** (`src/mt7601u/mac.rs`, `src/mt7601u/station.rs`):

* new `OWN_WCID = 2` — an entry programmed with **our own MAC**;
* `program_station` programs it (and clears its drop bit);
* `install_keys` installs the **PTK** on it as well as on the AP's `STA_WCID`.

This is harmless if the hardware already resolves unicast frames by the AP's
address, and it is the fix if it resolves by the destination address.

### 2.4 DHCP client: hostname and minimum length

`src/net/dhcp.rs`:

* **option 12 hostname** (`HOSTNAME = "MT7601U-Dongle"`) in DISCOVER and REQUEST,
  so the AP's client list shows a name instead of an unidentified MAC (it only
  takes effect once a lease is granted);
* the DISCOVER/REQUEST are padded to the **RFC 2131 minimum of 300 octets**
  (`MIN_MESSAGE_LEN`); a shorter message is ignored outright by some servers.

### 2.5 Honesty and the confirmation heuristic

* `src/backend.rs` — when the AP never accepted 4/4 the UI no longer reports
  "Connected"; it reports the failure and logs why. (`tunnel_start` still refuses
  and prints the message the user quoted.)
* `run_wpa2_handshake` — `handshake_confirmed` is now "the AP went **quiet** for
  `EAPOL_RETRY_GRACE` after our 4/4" instead of "we ever saw a second 3/4". This
  AP retransmits 3/4 readily, and a single retransmission that merely *crossed*
  our 4/4 must not be read as failure — that would block a working link.

### 2.6 Diagnostics added

* `FrameTrace` gained `llc_at` (where `aa aa 03` occurs anywhere in the frame)
  and `head` (hex dump of the first 64 bytes), both printed on a **rejection**.
  This is what turned "no LLC/SNAP header" from a guess into `llc_at: None` +
  the actual bytes.
* `relay_step` logs inbound ARP (`answer_arp` now returns a note):
  `ARP reply from <ip>: inbound unicast receive is working`. The next hop's ARP
  reply is unicast, so this single line is the on-device test for §2.3.

---

## 3. Reference facts that settled arguments (keep these)

| Fact | Source |
| --- | --- |
| Initial-handshake EAPOL frames are **unencrypted**; only GTK-rekey EAPOL carries a cipher | `ath12k` "fix encrypted EAPOL TX in encap offload mode" (lists.infradead.org, Jul 2026) |
| EAPOL frames are `IEEE80211_TX_INTFL_DONT_ENCRYPT` only when `control_port_no_encrypt` is set; otherwise `ieee80211_tx_h_select_key` would pick `sta->ptk` | `net/mac80211/tx.c` |
| The hardware may leave the CCMP IV in a decrypted frame; `RX_FLAG_IV_STRIPPED` is cleared when `MT_RXINFO_PN_LEN` is non-zero | `mt7601u/mac.c` `mt76_mac_process_rx` |
| `GROUP_WCID(idx) = N_WCIDS - 2 - idx` (so VIF 0 → 126); `init_wcid_mem` fills every WCID address with `ff:ff:ff:ff:ff:ff`, so Linux never programs the group WCID's address | `mt7601u/mt7601u.h`, `init.c` |
| TX descriptors are DRAM-agnostic: `[4B info][TXWI 20B][802.11 frame][pad to 4][4B zero]`, `LEN = round_up(TXWI+frame, 4)`; `WIV` is set only when `wcid->hw_key_idx == 0xff` (no key) | `mt7601u/dma.h`, `dma.c`, `tx.c` |
| Key slot layout: 32 bytes, the cipher key at offset 0; `iv_data[3] = keyidx << 6`, `| 0x20` (ExtIV), `iv_data[0] |= 1` | `mt7601u/mac.c` `mt76_mac_get_key_info` / `mt76_mac_wcid_set_key` |

(The Linux tree is kept locally under `mt7601u-refs/linux/…`; mac80211 itself is
not in that sparse checkout and was read from source browsers.)

---

## 4. What is verified vs. not

**Verified on hardware**

* After §2.1: `Connected to "HaLePo" (AID 3)` and the device **appears in the
  router's client list** — the AP accepted the handshake and registered the
  station. This crossed the barrier the first handover was stuck behind.
* After §2.2: the AP's own frames decrypt and parse (`0x0800`, `0x86dd`,
  `0x0806`). Before the fix every decrypted frame was rejected.
* Our DISCOVER is transmitted: the AP echoes the broadcast back, the echoed
  frame's size tracks ours (336 → 368 bytes when the DHCP padding was added) and
  its CCMP header carries the **AP's** PN (e.g. `0x15d2`, then `0x176a`) — so TX
  and the group key work.
* Outbound relay works end to end: `utun` traffic is on the air (the Mac's mDNS
  from the dongle's address), and a `tcpdump -i utunN` capture shows macOS
  handing complete IPv4/TCP packets to the tunnel.

**Implemented and unit-tested, not yet confirmed on hardware**

* §2.3 (the own-address WCID). Its on-device signal is the new ARP log line.
* The manual addressing path and the hostname option (the name only appears once
  a lease is granted).

**Not done / open**

* Inbound traffic over the link is unproven — no unicast protected frame has ever
  been received (§5).
* No DHCP lease has been observed. The link has only ever been online with a
  **manually entered** address.

---

## 5. The open question, and how to settle it

The symptom is now precise: **the router never answers a DHCPDISCOVER that
provably reaches the AP**, and after the fixes above we still have not seen a
single inbound *unicast* frame.

Two candidate root causes remain, and they are distinguished by one measurement:

1. **We drop inbound unicast frames.** Then the OFFER/ARP reply is on the air and
   lost in our RX (key/WCID selection). Driver-side, fixable.
2. **The router never answers.** Then no OFFER exists to receive; router-side.

**On-device test (already in the build):** connect and look for
`ARP reply from <gateway>: inbound unicast receive is working` in the Logs. The
gateway's ARP reply is unicast, so this line appearing means (1) is fixed.

**Air-side test (decisive either way):** monitor the AP's channel and check

```
wlan.addr == 88:82:79:24:0e:c0 && bootp.option.dhcp == 1   # our DISCOVER on the air?
bootp.option.dhcp == 2                                     # does any OFFER exist?
wlan.da == 88:82:79:24:0e:c0                               # frames addressed to us
arp && wlan.da == 88:82:79:24:0e:c0                        # the gateway's ARP reply
```

* an OFFER (or ARP reply) on the air that the app never logs ⇒ (1);
* nothing addressed to us at all ⇒ (2), and the fix is on the router (guest /
  isolated SSID, client limit, address reservation, or MAC filter — the router
  shows this MAC with no address and logs no DHCP request for it).

**Interim path to a working link:** the app's **Tunnel address → Manual** mode.
It has been demonstrated working: with a manual address in the AP's subnet the
tunnel comes up and carries traffic (observed on `utun4`/`utun5`, e.g.
`192.168.0.200 → 142.251.150.4 UDP 443`). Use the Mac's own Wi-Fi on the same
network as the source of the subnet/gateway/mask (Manual assumes `/24`).

---

## 6. Reproducing

Prerequisites as before: the dongle is the only process holding the device; the
AP is in range and the channel is checked first (`cargo run -- --scan`).

```bash
sudo cargo run                      # GUI; utun needs root or the helper daemon
```

Then: let it scan → click the network → watch **Details → Logs**. On a DHCP
failure the log prints the `Frames seen during the DHCP exchange (n)` block,
now with `llc_at` and a hex dump for each rejected frame.

Watching the tunnel itself (Wireshark does not list `utun*`):

```bash
ifconfig -l | tr ' ' '\n' | grep -x 'utun[0-9]*'   # the live name (also in the Logs)
sudo tcpdump -i utun4 -w /tmp/tunnel.pcap          # open the file in Wireshark
```

`sudo cargo run -- --tunnel-demo 30` exercises the `utun` + route stack on its
own (it answers echo requests for `10.9.9.2`), no radio involved.

---

## 7. Environment gotchas (unchanged from the first handover, still true)

* **Only one process may hold the dongle**; a stale `/Applications/MT7601U.app`
  will silently steal the device (and will not contain these fixes).
* The MCU channel wedges after repeated failed runs — unplug/replug.
* The AP roams channels (10/11) and vanishes for minutes; rescan first.
* `target/` can become root-owned after `sudo cargo run`.
* `utun`/`route`/`scutil` need root or the helper.

---

## 8. Changes at a glance

| File | Change |
| --- | --- |
| `src/mt7601u/station.rs` | handshake EAPOL sent unencrypted, keys installed after 4/4; `install_keys(chip, &handshake)`; `OWN_WCID` programmed + PTK installed on it; `handshake_confirmed` = "AP went quiet" |
| `src/mt7601u/mac.rs` | new `OWN_WCID = 2` (our own address + pairwise key) |
| `src/mt7601u/rx.rs` | `MT_RXINFO_PN_LEN`, `Rxwi::has_crypto_header()` |
| `src/wifi/data.rs` | `CCMP_HEADER_LEN`; `parse_rx` skips the CCMP header and falls back to locating the LLC/SNAP prefix |
| `src/mt7601u/data.rs` | crypto-header flag threaded through `analyse`/`payload_from_frame`; `FrameTrace.llc_at` + `head` hex dump on rejection |
| `src/net/dhcp.rs` | option 12 hostname `MT7601U-Dongle`; RFC 2131 300-byte minimum padding |
| `src/backend.rs` | honest Connect state; `answer_arp` returns a note and the relay logs inbound ARP |

New/updated tests: the handshake EAPOL frames are never Protected; an AP that
keeps retransmitting 3/4 reports unconfirmed; the CCMP header is skipped (and
the padded/plain cases still reject as before); the DISCOVER/REQUEST carry the
hostname and reach 300 bytes; the own-address WCID gets our MAC and the pairwise
key.
