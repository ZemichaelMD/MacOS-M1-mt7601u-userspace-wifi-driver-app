# macOS networking notes (utun path)

This describes the experimental Track B path. The station, the `utun`
interface, the packet relay, the DHCP client, the routes/DNS setup and the
privileged helper are implemented (`src/mt7601u/`, `src/net/`, `src/tunnel/`,
`src/helper/`). Scan, association and the WPA2 handshake are verified on
hardware; the data path, DHCP and the relay are unit-tested. It must not be
presented as working internet until end-to-end traffic is demonstrated.

## utun is layer 3, not Wi-Fi

* macOS `utun` is a point-to-point IP tunnel. The user-space program exchanges
  raw IP packets with the kernel over a `com.apple.net.utun_control` socket.
* It does **not** scan, associate, negotiate WPA, or appear as a Wi-Fi device in
  System Settings.
* TUN is layer 3; TAP is layer 2 Ethernet where supported. `utun` is not a
  generic TAP device and exposes no Ethernet framing. The relay therefore carries
  IP directly inside 802.11 data frames via LLC/SNAP (no Ethernet header, unlike
  BetterTether's RNDIS path).

## How it is built here

1. **Station** (`src/mt7601u/station.rs`) associates with the AP — open or
   WPA2-PSK — and installs the hardware keys.
2. **Data path** (`src/wifi/data.rs`, `src/mt7601u/data.rs`) wraps/strips the
   802.11 data frame + LLC/SNAP around IP packets. Unicast frames use the AP's
   *station* WCID (pairwise key); broadcast/multicast frames use the *group*
   WCID (group key), so the DHCP `DISCOVER` is encrypted with the key the AP
   expects.
3. **DHCP** (`src/net/dhcp.rs`) obtains an address, router and DNS from the AP.
4. **Interface setup**: `src/tunnel/utun.rs` creates the interface, runs
   `ifconfig`, installs the `0.0.0.0/1` + `128.0.0.0/1` routes and registers the
   service with `scutil`; `teardown()` restores routes and DNS on stop/exit.
5. **Relay** (`src/tunnel/relay.rs`) moves packets both ways.

All of the above is driven from the GUI, where the app finds, opens and scans by
itself and one click on a network joins it and brings the tunnel up.

## Privileges and the helper

Creating and configuring `utun` needs root. Rather than requiring the whole GUI
to run under `sudo`, `src/helper/` provides a small root LaunchDaemon:

* `sudo mt7601u-macos --install-helper` (or `sudo bash scripts/install-helper.sh`)
  copies the binary to `/Library/PrivilegedHelperTools/` and loads
  `/Library/LaunchDaemons/ai.commandcode.mt7601u.plist`.
* The daemon listens on `/var/run/mt7601u-helper.sock` (`root:admin`, mode 0660)
  and does only the privileged plumbing: `utun` creation, `ifconfig`, `route`,
  `scutil`, and the packet pump.
* The GUI keeps the Wi-Fi station, DHCP and the relay: a second process cannot
  claim the USB device at the same time. It exchanges raw IP packets with the
  daemon over the socket.
* Without the helper (and without root) the tunnel start fails with an
  actionable message; the GUI shows the privilege state in the tunnel panel.

## Open questions / limits

* On macOS 15+ DNS is only "supplemental" without a signed system extension, so
  some apps may not use the tunnel.
* Unicast outbound traffic is addressed to the AP (Address 3 = BSSID) and relies
  on the AP to forward by IP; there is no ARP resolution yet.
* Association, data path, DHCP and relay are unit-tested but **not verified on
  hardware**; loopback (`--tunnel-demo`) alone is not proof.

## Exit gate

Real IP packets must traverse the real Wi-Fi station to the internet and back.
Loopback traffic alone is insufficient.

## References

* `mt7601u-refs/BetterTether` — the launchd daemon + `utun` model this follows.
* `utun_control` example (old, reference only): <https://github.com/mafintosh/utun>
