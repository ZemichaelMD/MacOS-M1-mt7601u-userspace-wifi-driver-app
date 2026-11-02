# Architecture

## Layering

```
GUI (src/app.rs, eframe/egui)             <- renders state, sends Commands
   |  Command (channel)                   <- src/commands.rs
   v
Backend worker (src/backend.rs)           <- owns the device, one dedicated thread
   |  Event (channel)
   v
MT7601U driver (src/mt7601u/)             <- vendor requests, registers, firmware,
   |  Transport trait                     <-   MCU commands, initvals, RF/PHY, scan
   v
USB layer (src/usb/transport.rs)           <- control + bulk transfers
   |  src/usb/enumerate.rs                 <- descriptors, device matching
   v
mt7601u hardware                           <- WPA/WPA2: NOT IMPLEMENTED
                                           <-   (assoc + data path + tunnel: unit-tested)
```

* The GUI never performs USB I/O. All blocking calls happen on the backend
  thread; the GUI drains an event queue each frame.
* The backend calls `egui::Context::request_repaint()` whenever it produces an
  event, so the UI is event-driven rather than polled.
* `Command` implements `Debug` by hand so a connect password can never be
  revealed by logging.

## Threading and channels

* One OS thread named `mt7601u-backend` runs a `tokio` current-thread runtime.
* `tokio::sync::mpsc` unbounded channels carry `Command` (GUI→backend) and
  `Event` (backend→GUI). `UnboundedSender::send` and `UnboundedReceiver::try_recv`
  are both synchronous, so neither side is forced to be async.
* While the tunnel runs, the worker alternates a relay step with a short sleep
  and drains commands between steps, so all USB I/O stays on this one thread
  (the `rusb` handle is not shared across threads).
* `Backend::drop` sends `Command::Shutdown` and joins the worker. The worker
  owns the device handle, whose `Drop` releases claimed interfaces.

## State model

* `usb::DeviceStatus`: `Unknown -> Absent | Present(info) | Open(info) | Error`.
  `Open` is only set after the interface is actually claimed.
* `wifi::WifiState` / `tunnel::TunnelState`: the GUI mirrors backend events only.
  `Connected`/`Running` are produced solely by a real association / a real
  `utun` interface — the GUI cannot fabricate them.
* `app_state::AppState` is a pure function of the event stream, which makes it
  unit-testable without any hardware.

## Testability

The driver layer is generic over the `Transport` trait, so a mock transport can
record transfers and serve canned register values. Register read/write encoding,
identification, firmware upload, the station-setup registers, and the
auth/assoc exchange (with queued RX frames) are all covered by unit tests with
no hardware.

## Honesty constraints (from the master plan)

1. The GUI drives scan, connect and the tunnel, all via the backend worker. It
   must never fabricate state: `Connected`/`Running` are only produced after a
   real association / a real `utun` interface exists. WPA networks are refused
   with an explicit "not implemented" error rather than silently failing.
2. The GUI's network list stays empty until the backend is wired to the scan.
   No placeholder SSIDs.
3. "Open" does not imply "Connected", and a firmware upload does not imply a
   working radio.
4. Serial numbers are redacted in descriptor dumps.

## Modules

| Module | Responsibility |
| --- | --- |
| `src/app.rs` | egui rendering and command dispatch |
| `src/app_state.rs` | GUI state + event application, bounded log buffer |
| `src/commands.rs` | `Command` / `Event` definitions |
| `src/backend.rs` | worker thread and state machine |
| `src/logging.rs` | `LogLine` / `LogLevel`, tracing bridge |
| `src/usb/enumerate.rs` | device listing, descriptor model, matching |
| `src/usb/transport.rs` | `Transport` trait + `rusb` control/bulk transfers |
| `src/mt7601u/regs.rs` | register offsets and bit fields |
| `src/mt7601u/dma.rs` | TX/RX DMA descriptor framing (`dma.h`) |
| `src/mt7601u/firmware.rs` | firmware image parsing (pure) |
| `src/mt7601u/device.rs` | vendor requests, registers, clock on/off, firmware upload |
| `src/mt7601u/mcu.rs` | MCU command channel (send, response, reg-pair/burst writes) |
| `src/mt7601u/phy.rs` | BBP register access + readiness |
| `src/mt7601u/initvals.rs` | MAC/BBP init value tables (`initvals.h`) |
| `src/mt7601u/init.rs` | post-MCU init sequence (`init.c`) |
| `src/mt7601u/eeprom.rs` | eFuse read + EEPROM parameters (`eeprom.c`) |
| `src/mt7601u/rf.rs` | RF register access + RF init tables (`initvals_phy.h`) |
| `src/mt7601u/radio.rs` | PHY init/calibration, channel set, MAC start (`phy.c`/`init.c`) |
| `src/mt7601u/rx.rs` | RX DMA segments, RXWI, 802.11 beacon parsing (`dma.c`/`mac.h`) |
| `src/mt7601u/tx.rs` | TXWI construction + DMA framing + bulk-OUT (`tx.c`) |
| `src/mt7601u/scan.rs` | passive channel scan |
| `src/mt7601u/mac.rs` | station setup: MAC addr, WCID, BSSID, basic rates, TSF (`mac.c`/`main.c`) |
| `src/mt7601u/station.rs` | open-system association: auth → assoc exchange |
| `src/mt7601u/data.rs` | station data path: IP ⇄ 802.11 data frames (`StaLink`) |
| `src/wifi/frames.rs` | 802.11 probe/auth/assoc frame builders (pure) |
| `src/wifi/mgmt.rs` | auth/assoc response parsing (pure) |
| `src/wifi/data.rs` | 802.11 data frames + LLC/SNAP (pure) |
| `src/net/ipv4.rs` | IPv4/UDP framing + RFC 1071 checksum (pure) |
| `src/net/dhcp.rs` | DHCPv4 client codec + DISCOVER/REQUEST exchange |
| `src/tunnel/relay.rs` | `utun` ⇄ Wi-Fi packet relay (`PacketTun`, `Stats`) |
| `src/paths.rs` | runtime asset lookup (firmware blob) |
| `src/tunnel/utun.rs` | macOS `utun` interface + routes/DNS (`AF_SYSTEM`) |
| `src/tunnel/icmp.rs` | IPv4/ICMP helpers for the tunnel self-test |
| `src/mt7601u/testing.rs` | shared test doubles (mock transport) |
| `src/mt7601u/mod.rs` | device identity constants |
| `src/wifi/mod.rs` | Wi-Fi domain types and state enum |
| `scripts/bundle-macos-app.sh` | builds the `.app` bundle |
