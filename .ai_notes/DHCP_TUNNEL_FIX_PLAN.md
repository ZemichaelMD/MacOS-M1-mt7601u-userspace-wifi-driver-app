# DHCP Tunnel Fix Plan

## Current evidence

- The current project build finds the MT7601U, scans, associates to `HaLePo`,
  and completes the WPA2 four-way handshake on the physical adapter.
- The failure occurs after keys are installed, when the app sends DHCPDISCOVER:
  `no DHCP response (message type 2)`.
- The receive diagnostics collected after the timeout contain only beacons; no
  accepted IPv4/DHCP response was observed.
- The `utun` interface and macOS route/DNS setup are not the immediate cause:
  DHCP runs before the tunnel is created.
- The included Linux MT7601U driver remains the reference for broadcast WCID
  selection. Its transmit path uses the VIF group WCID when mac80211 has no
  destination station for a broadcast/multicast frame.

## Goal

Demonstrate a complete, real path on the physical adapter:

1. DHCPDISCOVER leaves the station.
2. The AP accepts it and sends DHCPOFFER.
3. The app receives and parses OFFER/ACK.
4. `utun` starts and relays packets to and from macOS.
5. An IP-level check succeeds through the tunnel.

## Plan

### 1. Preserve the known-good association baseline

- Keep the established WPA2 key installation and OFDM data-rate behavior.
- Do not use the stale `/Applications/MT7601U.app`; run only a build made from
  this project directory.
- Before each trial, ensure no other MT7601U app or CLI process holds the USB
  device.

### 2. Add per-attempt DHCP packet tracing

- Add a small diagnostics structure for the DHCP exchange that records every
  received 802.11 data frame while waiting for OFFER and ACK.
- Record frame-control flags, receiver/transmitter/BSSID addresses, RXWI WCID,
  key index, decrypt flag, L2-padding flag, EtherType, and parser rejection
  reason.
- Log the diagnostics from the same receive loop as DHCP, rather than reading
  the adapter only after the timeout. This prevents potential OFFER/ACK frames
  from being discarded before the diagnostic pass starts.

### 3. Confirm transmit configuration against the reference driver

- Capture and log the DHCP frame’s TXWI and DMA descriptor: WCID, WIV flag,
  protected-bit state, rate, queue selection, sequence assignment, and frame
  addresses.
- Compare those values with `mt7601u-refs/linux/.../tx.c` and `dma.c`.
- Verify the GTK is installed in the group WCID and shared-key table, while the
  PTK remains installed in the AP station WCID.
- Add regression tests for the expected DHCP TX descriptor and frame layout.

### 4. Use hardware observations to isolate the failure

- If no data frame is received at all, inspect transmit status/FIFO support and
  confirm whether the hardware accepted the DHCP frame for transmission.
- If an encrypted DHCP response arrives but is rejected, fix the RX parser or
  WCID/key mapping using its logged RXWI values.
- If the AP sends no response despite a confirmed transmit, capture the AP
  side or use a monitor-capable second adapter to verify the over-the-air frame
  and its CCMP protection.

### 5. Complete the tunnel only after DHCP works

- Verify that the lease’s address, gateway, subnet mask, and DNS are propagated
  into `utun` configuration.
- Confirm the two split default routes and DNS cleanup on disconnect.
- Test outbound ICMP/DNS/HTTPS traffic and inbound replies; record relay packet
  counters and dropped packets.
- Add a hardware validation note to `HANDOVER.md` and `README.md` only after a
  real successful lease and end-to-end traffic test.

## Acceptance criteria

- The UI shows a real DHCP lease instead of a DHCP timeout.
- The tunnel transitions to `Running` with nonzero receive and transmit packet
  counters during an actual network request.
- A physical-device test reaches an external IP and resolves DNS through the
  tunnel.
