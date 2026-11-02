# Feasibility Study — One App for Wi-Fi and Bluetooth on Apple Silicon macOS

**Status:** Research / decision document
**Date:** 2026-11-02
**Target machine:** Apple Silicon Mac (this machine reports `Apple M1`), macOS 26.5.1 (25F80), arm64
**Devices in scope:** MediaTek MT7601U Wi-Fi (`148f:7601`) and CSR8510 A10 Bluetooth (`0a12:0001`) as **two separate USB dongles**, plus the Mac's built-in `BCM_4378` combo radio
**Replaces:** the earlier combo-dongle draft, which assumed a single custom PCB. That assumption was wrong; the hardware analysis is retained in Appendix A.
**Related documents:** [`docs/macos-wifi-feasibility.md`](../docs/macos-wifi-feasibility.md), [`docs/usb-descriptors.md`](../docs/usb-descriptors.md), [`masterplan.md`](../masterplan.md), [`README.md`](../README.md)

---

## 0. Bottom line

You asked three things:

1. **Can the MT7601U do Bluetooth, so one dongle covers both?**
   **No.** The MT7601U is a Wi-Fi-only single chip. It has no Bluetooth radio, no Bluetooth firmware, and not even the USB endpoint a Bluetooth controller requires. This is not a driver limitation; the hardware is not there. Details in §2.1.

2. **Can one app present a Wi-Fi section and a Bluetooth section?**
   **Yes.** Both halves are feasible, but they are very different kinds of integration:
   - **Wi-Fi** is app-managed. The app drives the MT7601U itself and shows its own network list. macOS will **not** show that adapter in System Settings → Wi-Fi. This is already how the project works.
   - **Bluetooth** is system-managed. The app uses Apple's public `IOBluetooth` and `CoreBluetooth` APIs and talks to whichever controller macOS has selected. Paired devices appear in System Settings too, because the app and the system share one Bluetooth stack.

3. **Can Bluetooth be integrated separately?**
   **Yes, and it already works without the CSR dongle.** This Mac has a working built-in Bluetooth 5.x controller. The app can scan, pair, connect, and list devices against it today, with no custom driver, no root, and no NVRAM changes. The CSR8510 is optional.

**Recommendation:** build the app as one UI with two independent backends. Use the built-in controller for Bluetooth and the MT7601U for Wi-Fi. Treat the CSR8510 as an optional experiment, not a dependency — it may not even be selectable on an M1 (§6).

What the app still cannot do:

- put the MT7601U in **System Settings → Wi-Fi**;
- **power Bluetooth on or off** (the public API exposes a read-only power state);
- provide AirDrop, Handoff, Continuity, or Apple Watch unlock through a third-party controller.

---

## 1. The question, restated

The earlier study assumed a single custom USB device containing both radios. That is not the plan. The actual plan is:

- two off-the-shelf USB dongles, plugged in separately;
- **one application** that gives the user a Wi-Fi section and a Bluetooth section;
- Wi-Fi: scan and connect through the MT7601U;
- Bluetooth: scan and connect through the CSR8510 **or** the built-in radio;
- if the MT7601U could handle Bluetooth too, drop the second dongle.

This document answers whether that software bundling is feasible, and what each half can honestly deliver.

### 1.1 What "integrate" means for each half

| Surface | Wi-Fi (MT7601U) | Bluetooth (built-in or CSR8510) |
|---|---|---|
| List of nearby networks/devices inside the app | **Yes** — app scans the radio | **Yes** — public API |
| Join / pair / connect from the app | **Yes** | **Yes** |
| Appears in System Settings | **No** | **Yes**, because it is the system stack |
| Appears in the menu-bar Wi-Fi picker | **No** | n/a |
| Can the app turn the radio on/off | **Yes** — open/close the USB device | **No** — read-only state |
| AirDrop / Handoff / Continuity | **No** | **No** for third-party controllers; built-in only |

The asymmetry is the single most important design fact in this document: **Wi-Fi is private to the app, Bluetooth is shared with the system.** The UI must say so, or users will expect the Wi-Fi list to appear in Control Center and conclude the app is broken.

---

## 2. Device facts

### 2.1 MT7601U — Wi-Fi only, no Bluetooth

MediaTek's own product page describes the MT7601U as:

> "a highly integrated Wi-Fi single chip that's fully compliant with 802.11b/g/n standards (150Mbit/s PHY)"

with specifications of Wi-Fi 4 (b/g/n), 2.4 GHz, 1T1R, USB 2.0, and no Bluetooth entry at all ([MediaTek MT7601U product page](https://www.mediatek.com/products/broadband-wifi/mt7601u)).

The project's own captured descriptors confirm the physical layer is wrong for Bluetooth ([`docs/usb-descriptors.md`](../docs/usb-descriptors.md)):

```
Interface 0 alt 0: class 0xff/0xff/0xff, 8 endpoint(s)
  Endpoint 0x84 (IN Bulk),  max packet 512
  Endpoint 0x85 (IN Bulk),  max packet 512
  Endpoint 0x08 (OUT Bulk), max packet 512
  ... six bulk OUT endpoints in total
```

Three independent facts rule Bluetooth out:

1. **No Bluetooth radio.** Bluetooth needs a 2.4 GHz GFSK transceiver, a link controller, and a Bluetooth-specific baseband. The MT7601U's RF/BBP is built for 802.11 OFDM/DSSS. They are not the same modulation or the same MAC.
2. **No HCI interface.** Every USB Bluetooth controller enumerates as class `E0/01/01` with an **interrupt IN** endpoint for HCI events. The MT7601U is vendor-specific class `FF` with only bulk endpoints. There is no endpoint to deliver HCI events on.
3. **No Bluetooth firmware.** The driver loads `mt7601u.bin`, which is Wi-Fi firmware. MediaTek publishes no Bluetooth firmware for this part.

**Verdict: impossible.** No amount of driver work changes this. If Bluetooth is required, it comes from a second radio — the built-in controller or the CSR8510.

### 2.2 CSR8510 A10 — Bluetooth only

| Property | Value |
|---|---|
| Function | Bluetooth 4.0 HCI controller |
| USB class | `E0/01/01` (wireless / RF / Bluetooth) |
| VID:PID | `0a12:0001` in HCI mode; some units ship as `0a12:100b` (HID mode) |
| Speed | Full-speed, 12 Mb/s |
| bcdDevice on the user's unit | `0x8891` — typical clone firmware |
| Wi-Fi | None |

The CSR8510 is a legitimate Bluetooth controller and nothing else. It cannot help Wi-Fi.

### 2.3 The built-in `BCM_4378`

This Mac already has:

- Wi-Fi 6 (`en0`, Broadcom `0x14E4:0x4378`, `IO80211_driverkit`);
- Bluetooth 5.x on PCIe, vendor `0x004C` (Apple), currently **on**.

The built-in Bluetooth controller is the path of least resistance for the app's Bluetooth section. It is always present, survives sleep/wake, supports Continuity features, and needs no allowlist, no NVRAM variable, and no extra hardware.

---

## 3. What the combined app can control

### 3.1 Capability matrix

| Capability | Wi-Fi tab | Bluetooth tab |
|---|---|---|
| Enumerate available radios | MT7601U via `rusb` | selected controller via `IOBluetooth` |
| Scan for networks/devices | passive 802.11 scan (already built) | classic inquiry + BLE scan |
| Show signal / RSSI | yes | yes (classic RSSI, BLE RSSI) |
| Join / pair | WPA2-PSK, open (already built) | `IOBluetoothDevicePair`, CoreBluetooth pairing |
| Persist credentials | existing credential store | system stores pairings |
| Disconnect | yes | `closeConnection` / cancel |
| Forget network/device | delete stored profile | **no public unpair API** — user must use System Settings |
| Power the radio on/off | yes (open/close USB handle) | **no** (read-only `powerState`) |
| Work without root | yes (device is user-accessible) | yes |
| Work without the other tab | yes | yes |

### 3.2 The power-switch limitation

The user's phrasing was "turn on Wi-Fi and Bluetooth." Only half of that is controllable:

- **Wi-Fi:** the app owns the MT7601U. Opening the USB device and running the init sequence powers it up; closing the handle powers it down. The app can genuinely toggle *its own* radio.
- **Bluetooth:** `IOBluetoothHostController.powerState` is **read-only**. Apple's header states: *"This will be 1 for on, or 0 for off. Only Apple Bluetooth adapters support power off."* There is no public API to switch the controller on or off. The app can show the state and deep-link the user to System Settings, but cannot flip it.

Design consequence: the Bluetooth tab should show a controller card with state and a "Open Bluetooth Settings" button, not a toggle that silently does nothing.

---

## 4. Wi-Fi backend

### 4.1 Already implemented

The repository contains a working user-space MT7601U station:

- firmware upload, MCU command channel, MAC/BBP/RF init, calibration;
- passive scan, open-system association, WPA2-PSK 4-way handshake, hardware CCMP;
- 802.11 data path, DHCP client, `utun` relay, privileged helper, egui GUI.

`README.md` records hardware verification on 2026-10-16: scan, association, WPA2 handshake, a real DHCP lease, and traffic through the tunnel.

### 4.2 Why it cannot appear in System Settings → Wi-Fi

This is unchanged from [`docs/macos-wifi-feasibility.md`](../docs/macos-wifi-feasibility.md) and re-checked on macOS 26.5.1:

- macOS 26 ships **no USB Wi-Fi class driver** (0 of 183 USB driver personalities match Wi-Fi/WLAN/802.11/AirPort on this machine).
- There is **no public 802.11 driver API**. NetworkingDriverKit supports **Ethernet only**.
- Apple's own Wi-Fi dext uses the private class `IOUserNetworkWLAN`, which is not in the public SDK.
- Intel-era third-party Wi-Fi kexts are `x86_64`; the Apple Silicon kernel is `arm64e` and refuses them.
- OpenCore/AMFI workarounds are Hackintosh-only and do not apply to a real Apple Silicon Mac.

No app, driver, or enclosure changes this. The MT7601U stays app-managed.

### 4.3 What the Wi-Fi tab should do

| Feature | Status |
|---|---|
| Scan and list SSIDs with signal/security | built |
| Join open / WPA2-PSK | built |
| Show link state, IP, gateway, DNS | built |
| Disconnect / rescan / radio off | built |
| Explain that System Settings will not list it | **needed** |
| Offer "use system Wi-Fi instead" when the built-in radio is available | **needed** |

That last row matters. On this Mac the built-in Wi-Fi already works. The app should not pretend the dongle replaces it; it should present the dongle as an alternative path (lab, travel, testing, or a machine whose internal radio is unavailable).

### 4.4 Permissions

The Wi-Fi side needs no new privacy permission. It talks to a USB device through `rusb`, exactly as it does today. macOS does not gate raw USB access for a non-sandboxed Developer ID app, and the project already proves this on the target machine.

(Location Services is only required for `CoreWLAN` SSID access. This project does not use `CoreWLAN` for scanning, so that gate does not apply.)

---

## 5. Bluetooth backend

### 5.1 Two public APIs, two device classes

macOS exposes two complementary frameworks, and a complete Bluetooth tab needs both:

| API | Covers | Key classes |
|---|---|---|
| **IOBluetooth** | Classic BR/EDR: inquiry, SDP, RFCOMM, L2CAP, pairing, connected devices | `IOBluetoothDeviceInquiry`, `IOBluetoothDevice`, `IOBluetoothDevicePair`, `IOBluetoothHostController` |
| **CoreBluetooth** | Bluetooth Low Energy: scanning, connecting, GATT | `CBCentralManager`, `CBPeripheral` |

The split is not optional. `IOBluetoothDeviceInquiry` defaults to `kIOBluetoothDeviceSearchClassic` and does not discover BLE peripherals; `CoreBluetooth` does not discover classic devices. Headphones and older mice are usually classic; modern mice, keyboards, sensors, and phones are usually BLE.

A single "Bluetooth" tab should therefore run both scanners and merge the results with a type badge (`Classic` / `BLE`), or offer a segmented filter.

### 5.2 What the public API actually provides

From the SDK headers on this machine:

- `IOBluetoothHostController.defaultController` — the selected controller;
- `addressAsString`, `nameAsString`, `powerState` (read-only);
- `IOBluetoothDeviceInquiry` — `start`, `stop`, delegate callbacks for found/updated devices;
- `IOBluetoothDevice.pairedDevices` — all paired devices on the system;
- `IOBluetoothDevice.openConnection` / `closeConnection`, `isPaired`, `isConnected`;
- `IOBluetoothDevicePair` — `start` / `stop` with delegate callbacks;
- `IOBluetoothDevice` SDP queries for service discovery.

Notably absent: a public **unpair** call. Removing a pairing is a System Settings action. The app can pair and connect, but should hand off "forget device" to the system.

### 5.3 Which controller does the app talk to?

The app does not choose. `IOBluetooth` and `CoreBluetooth` always talk to whichever controller macOS has selected. That gives two deployment modes with **identical application code**:

| Mode | Controller | Requirements | Risk |
|---|---|---|---|
| **Built-in** (default) | `BCM_4378` | none | none — already working |
| **External CSR8510** | `0a12:0001` | `bluetoothd` allowlist + controller switch | medium; unproven on M1 |

This is the key architectural win: building the Bluetooth tab against the built-in controller is not throwaway work. If the CSR dongle later becomes selectable, the same tab uses it with no code change.

### 5.4 Permissions and packaging

Bluetooth access is gated by TCC (Transparency, Consent, and Control), not by a driver entitlement:

- The app's `Info.plist` must contain **`NSBluetoothAlwaysUsageDescription`**. Apple's own Bluetooth File Exchange ships this key on this machine (`"Allow BT"`), which confirms the requirement on macOS 26.
- On first Bluetooth use, macOS shows *"<App> would like to use Bluetooth"*. Denial is sticky until changed in System Settings → Privacy & Security → Bluetooth.
- If the app is ever sandboxed (e.g. Mac App Store), it additionally needs the **`com.apple.security.device.bluetooth`** entitlement, which is defined in `/System/Library/Sandbox/Profiles/application.sb`.
- For stable TCC identity, sign with a Developer ID and notarize. Ad-hoc signatures can re-prompt after rebuilds because the code identity changes.

The current bundle (`dist/MT7601U-current.app`) has no Bluetooth key. Adding it is a one-line change in `scripts/bundle-macos-app.sh`.

### 5.5 What Bluetooth still will not do

Even with everything working:

- **No Continuity.** AirDrop, Handoff, Universal Clipboard, Apple Watch unlock, and Find My offload are tied to Apple's own combo radio and private stack. A CSR dongle does not provide them; the built-in controller does, but only through Apple's system features, not through the app.
- **No power toggle.** See §3.2.
- **No LE Audio** on CSR8510 (Bluetooth 4.0).
- **No guarantee across macOS releases.** The CSR allowlist is private and has changed before. The built-in controller is stable.

---

## 6. The CSR8510 decision

### 6.1 Three tiers

| Tier | Approach | Effort | Verdict |
|---|---|---|---|
| **0** | Use the built-in controller; app calls `IOBluetooth` / `CoreBluetooth` | Low | **Recommended** |
| **1** | Make the CSR8510 the selected controller, then use the same APIs | Low code, medium risk | Optional experiment |
| **2** | Ship an app-owned HCI stack that drives the dongle over USB | Very high (person-years) | **Not viable** |

Tier 2 deserves a sentence, because it is the obvious "just bypass macOS" idea. A full host stack needs HCI, L2CAP, SDP, RFCOMM, GATT, SMP, and profile support, plus a DriverKit USB transport or exclusive `IOUSBHost` access. That is a multi-year project with no payoff over Tier 0. Do not start it.

### 6.2 Tier 1: what is known

`bluetoothd` on macOS 26 contains a vendor gate. Independent disassembly of 26.4.1 reports that it accepts `0a12:*` (CSR, any product ID), `0a5c:*` (Broadcom), and `0b05:190e` (ASUS BT500), after checking `bDeviceClass` and the HCI interfaces. Strings on this machine's 26.5.1 binary confirm the same logic (`Found_USB_Dongle`, `Not in supported list`, `BAM supported list`, `bluetoothHostControllerSwitchBehavior`).

So the CSR8510 is *eligible*. What is **not** proven is whether an Apple Silicon Mac will switch away from its internal controller. The switch is controlled by:

```bash
sudo nvram bluetoothHostControllerSwitchBehavior=always   # prefer external
# reboot
sudo nvram -d bluetoothHostControllerSwitchBehavior        # revert
# reboot
```

On this machine the variable is currently unset. The independent analysis that documented the variable explicitly notes it was untested on Apple Silicon. Treat Tier 1 as an experiment until §10.3 passes.

### 6.3 Why you probably do not need the dongle

The built-in controller already gives Bluetooth 5.x, better range, better sleep/wake behaviour, and Continuity support. The CSR8510 would give Bluetooth 4.0, clone firmware, no Continuity, a possible sleep/wake bug, and a dependency on a private allowlist.

Use the dongle only if:

- the built-in controller is broken or unavailable on the target machine; or
- you specifically want to demonstrate an external-controller path; or
- you are building for a Mac without built-in Bluetooth (rare).

Otherwise, leave it in the drawer.

---

## 7. Architecture for the combined app

### 7.1 Module layout

The existing crate is already organised by concern. The Bluetooth half fits alongside `wifi`:

```
src/
  app.rs                 egui shell; add a sidebar with Wi-Fi / Bluetooth / Diagnostics
  wifi/                  existing 802.11 frames, EAPOL, RSN, SAE
  mt7601u/               existing radio driver
  usb/                   existing rusb transport
  tunnel/                existing utun relay
  helper/                existing privileged helper (Wi-Fi only)
  bt/                    NEW
    mod.rs               backend trait, unified device model, events
    classic.rs           IOBluetooth inquiry, pairing, connections
    ble.rs               CoreBluetooth central
    controller.rs        host controller info and power state
  ui/
    wifi_tab.rs          extracted from app.rs
    bt_tab.rs            NEW
    diagnostics.rs       NEW
```

The privileged helper stays Wi-Fi-only. Bluetooth needs no root, and adding it to the helper would widen the attack surface for no reason.

### 7.2 Threading and run loops

This is the part most likely to cause bugs:

- **egui** owns the main thread and its event loop.
- **Wi-Fi** already runs on worker threads with `tokio` and `rusb`.
- **IOBluetooth** is run-loop based. Its inquiry and pairing delegates expect a run loop. Do **not** attach it to the main thread's run loop, where it will fight winit/egui. Run it on a dedicated thread with its own `CFRunLoop`, and forward events to the UI over a channel.
- **CoreBluetooth** is dispatch-queue based. Give it its own serial queue; callbacks can be forwarded over the same channel.

A single `bt::Event` enum (`ControllerChanged`, `DeviceFound`, `DeviceUpdated`, `PairingFinished`, `ConnectionChanged`, `Error`) keeps the UI thread simple.

### 7.3 Rust bindings

The ecosystem already covers both frameworks, and the project already depends on `objc2` 0.6:

| Crate | Version | Provides |
|---|---|---|
| `objc2-io-bluetooth` | 0.3.2 | `IOBluetoothDeviceInquiry`, `IOBluetoothDevice`, `IOBluetoothDevicePair`, `IOBluetoothHostController` |
| `objc2-core-bluetooth` | 0.3.2 | `CBCentralManager`, `CBPeripheral`, GATT types |

Both were published in October 2025 and are current. No hand-written Objective-C bindings are required.

### 7.4 Unified device model

```rust
pub enum Transport { Wifi, ClassicBt, Ble }

pub struct Device {
    pub id: DeviceId,          // transport + address/BSSID
    pub name: String,
    pub rssi: Option<i16>,
    pub paired: bool,
    pub connected: bool,
    pub kind: DeviceKind,      // Ap, Headphones, Keyboard, Phone, Unknown
}
```

Wi-Fi and Bluetooth stay separate lists in the UI, but share the `Device` shape so the detail pane and status bar can be reused.

### 7.5 Failure isolation

The tabs must be independent:

- If Bluetooth permission is denied, the Wi-Fi tab still works, and the Bluetooth tab shows a clear explanation plus a button that opens Privacy settings.
- If the MT7601U is unplugged, the Bluetooth tab is unaffected.
- If the CSR dongle is rejected by `bluetoothd`, the app silently falls back to the built-in controller and shows which controller is active.

---

## 8. User experience

### 8.1 Layout

```
┌─────────────────────────────────────────────────────┐
│  [Wi-Fi]  [Bluetooth]  [Diagnostics]                │
├─────────────────────────────────────────────────────┤
│  Wi-Fi (MT7601U)            ● Radio on   [Rescan]   │
│  ─────────────────────────────────────────────────  │
│  ▂▄▆█  HomeNet             WPA2    -48 dBm   [Join] │
│  ▂▄▆_  CafeGuest           Open    -61 dBm   [Join] │
│  ...                                                │
│  Status: associated, 192.168.1.42, gw 192.168.1.1   │
└─────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────┐
│  [Wi-Fi]  [Bluetooth]  [Diagnostics]                │
├─────────────────────────────────────────────────────┤
│  Bluetooth controller: BCM_4378  ● On  [Settings…]  │
│  ─────────────────────────────────────────────────  │
│  [All] [Classic] [BLE]                    [Scan]    │
│  🎧 Sony WH-1000XM4   Classic  -52 dBm  Paired  [⌁] │
│  🖱 MX Master 3       BLE      -60 dBm  Paired  [⌁] │
│  📱 Pixel 9           BLE      -71 dBm  —       [+] │
└─────────────────────────────────────────────────────┘
```

### 8.2 Honesty rules

1. Label the Wi-Fi panel **"Wi-Fi (MT7601U) — managed by this app"** and add a one-line note: *"This adapter does not appear in System Settings → Wi-Fi."*
2. Label the Bluetooth panel **"Bluetooth — system controller"** and show which controller is active (built-in or dongle).
3. Do not show a Bluetooth on/off toggle. Show state plus a Settings button.
4. Do not claim Continuity features.
5. On first run, explain the two permission/behaviour models before the user hits a confusing empty list.

### 8.3 Menu bar

The app already has a status item (`src/menu_bar.rs`). A compact menu could show:

- current Wi-Fi SSID and signal (from the app's own station);
- Bluetooth controller state and connected device count;
- quick actions: rescan Wi-Fi, open Bluetooth settings.

Do not put a Bluetooth power toggle there either.

---

## 9. Effort

| Work item | Effort | Notes |
|---|---|---|
| Extract Wi-Fi UI into `ui/wifi_tab.rs` | 1–2 days | Mechanical refactor |
| Bluetooth classic backend (inquiry, pair, connect, paired list) | 1–2 weeks | `objc2-io-bluetooth`; run-loop thread |
| BLE backend (scan, connect, GATT summary) | 1 week | `objc2-core-bluetooth` |
| Unified model, events, error handling | 3–5 days | Shared with Wi-Fi |
| Permissions, Info.plist, signing, notarization | 2–3 days | TCC prompt, Developer ID |
| UX polish, empty/error states, docs | 1 week | |
| Testing on hardware (built-in BT + MT7601U) | 1 week | HID, headphones, BLE sensor |
| **Total, one developer familiar with the codebase** | **4–6 weeks** | No hardware cost |
| CSR8510 validation (optional) | 0.5–1 day | §10.3 |

This is software-only work. There is no PCB, no certification, and no new BOM.

---

## 10. Validation plan

### 10.1 Phase A — confirm the Bluetooth API path (no code)

Before building the tab, prove the public API works on this machine:

1. Write a throwaway Swift or Objective-C probe that:
   - gets `IOBluetoothHostController.defaultController()`;
   - prints `nameAsString`, `addressAsString`, `powerState`;
   - starts an `IOBluetoothDeviceInquiry` and prints the first few devices;
   - starts a `CBCentralManager` scan and prints the first few peripherals.
2. Run it from Terminal. Accept the Bluetooth TCC prompt.
3. Expected: the controller is `BCM_4378`, state is on, and both classic and BLE devices appear.

If this fails, stop and investigate before writing Rust. If it passes, the backend design is sound.

### 10.2 Phase B — app prototype

1. Add `objc2-io-bluetooth` and `objc2-core-bluetooth`.
2. Implement `bt::classic` and `bt::ble` behind one event channel.
3. Add a minimal Bluetooth tab that lists devices and pairs one HID device.
4. Verify the pairing also appears in System Settings → Bluetooth.
5. Deny Bluetooth permission once and confirm the error path is clear.

### 10.3 Phase C — CSR8510 experiment (optional)

Only if you want the external-controller path. Use the dongle directly in a USB-C port, not through a hub, for the first test.

1. Confirm identity:
   ```bash
   system_profiler SPUSBHostDataType | grep -A 12 -i "CSR8510"
   ```
   Expected `idVendor 0x0a12`, `idProduct 0x0001`, `bcdDevice 0x8891`.
2. Watch `bluetoothd` while plugging it in:
   ```bash
   log stream --style compact --predicate 'process == "bluetoothd"'
   ```
   Look for `Found USB Device`, `FoundBluetoothInterfaces() ... returned true`, and absence of `Not in supported list`.
3. Check the selected controller:
   ```bash
   system_profiler SPBluetoothDataType
   ioreg -c IOBluetoothHCIController -r -d 1
   ```
4. Force the external controller:
   ```bash
   sudo nvram bluetoothHostControllerSwitchBehavior=always
   sudo reboot
   ```
5. Repeat step 3. If the CSR appears, pair a mouse and a headset, then sleep/wake.
6. Revert:
   ```bash
   sudo nvram -d bluetoothHostControllerSwitchBehavior
   sudo reboot
   ```

**Pass criteria:** the CSR controller appears, pairs with a HID device, survives sleep/wake, and the internal controller is restored afterwards.

**Kill criteria:** the controller never appears even with `always`; or it appears but cannot pair; or it dies after sleep. In those cases, close the Tier 1 path and ship Tier 0.

### 10.4 Phase D — combined app

1. Run both tabs simultaneously for an hour: Wi-Fi scan/join plus Bluetooth inquiry/pairing.
2. Confirm no run-loop deadlock and no UI stalls.
3. Unplug each dongle in turn and confirm the other tab recovers.
4. Test on a second Mac if available, to catch machine-specific assumptions.

---

## 11. Risks and unknowns

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Expectation that Wi-Fi appears in System Settings | High | User thinks the app is broken | Label clearly; explain in first-run and docs |
| Bluetooth TCC permission denied | Medium | Empty Bluetooth tab | Clear error state + deep link to Privacy settings |
| IOBluetooth run-loop conflicts with egui | Medium | Crashes or hangs | Dedicated thread + `CFRunLoop`; never the main loop |
| CSR8510 not selectable on M1 | Medium | Tier 1 dead | Tier 0 is the default; test before relying on it |
| CSR allowlist changes in a macOS update | Medium | Dongle stops working | Built-in controller remains; pin/test OS releases |
| Classic/BLE device duplication in the list | High | Confusing UI | Deduplicate by address; type badge |
| Unpair not available in-app | Certain | Feature gap | Hand off to System Settings |
| Continuity features expected | Medium | Disappointment | State the limitation up front |
| Notarization/TCC identity churn during development | Medium | Repeated prompts | Stable Developer ID; keep bundle ID fixed |

---

## 12. Recommendation

1. **Drop the idea of MT7601U Bluetooth.** The chip has no Bluetooth radio and no HCI endpoint. One dongle cannot do both.
2. **Build the Bluetooth tab against the built-in controller.** Use `IOBluetooth` for classic and `CoreBluetooth` for BLE, both public API, both available in Rust via `objc2-*` crates. This works today and needs no hardware.
3. **Keep the Wi-Fi tab as it is.** It is already a real station. Add honest labelling and a link to the existing feasibility note; do not promise System Settings integration.
4. **Treat the CSR8510 as optional.** Run Phase C only if you specifically need an external controller. If it fails, nothing in the app changes.
5. **Ship one app, two backends, one event model.** Keep the privileged helper Wi-Fi-only; Bluetooth needs no root.
6. **Write the limitation into the UI, not just the README.** The Wi-Fi/Bluetooth asymmetry is the main source of user confusion.

---

## 13. References

### Apple documentation and SDK

- NetworkingDriverKit — <https://developer.apple.com/documentation/networkingdriverkit> ("Ethernet is the only networking interface currently supported by NetworkingDriverKit.")
- IOBluetooth — <https://developer.apple.com/documentation/iobluetooth>
- CoreBluetooth — <https://developer.apple.com/documentation/corebluetooth>
- `NSBluetoothAlwaysUsageDescription` — <https://developer.apple.com/documentation/bundleresources/information-property-list/nsbluetoothalwaysusagedescription>
- Securely extending the kernel in macOS — <https://support.apple.com/guide/security/securely-extending-the-kernel-sec8e454101b/web>
- Local SDK headers: `IOBluetooth.framework/Headers/objc/{IOBluetoothDeviceInquiry,IOBluetoothDevice,IOBluetoothDevicePair,IOBluetoothHostController}.h`; `CoreBluetooth.framework/Headers/CBCentralManager.h`
- Local sandbox profile: `/System/Library/Sandbox/Profiles/application.sb` (`com.apple.security.device.bluetooth`)

### MediaTek and hardware

- MediaTek MT7601U product page — <https://www.mediatek.com/products/broadband-wifi/mt7601u>
- Project USB descriptor capture — [`docs/usb-descriptors.md`](../docs/usb-descriptors.md)

### Bluetooth allowlist and CSR8510

- "USB Bluetooth Adapter for Mac: The Allowlist in bluetoothd" (picklog, September 2026) — <https://picklog.cc/blog/usb-bluetooth-adapter-mac>
- "USB WiFi Adapter for Mac: macOS Has No Driver for One" (picklog, September 2026) — <https://www.picklog.cc/blog/usb-wifi-adapter-mac>
- Qualcomm CSR8510 product page — <https://www.qualcomm.com/bluetooth/products/csr8510>
- InsanelyMac: CSR8510 sleep/wake thread — <https://www.insanelymac.com/forum/topic/357956-solved-csr8510-usb-bluetooth-not-working-after-wake-from-sleep-in-ventura/>

### Rust bindings

- `objc2-io-bluetooth` 0.3.2 — <https://docs.rs/objc2-io-bluetooth>
- `objc2-core-bluetooth` 0.3.2 — <https://docs.rs/objc2-core-bluetooth>
- `objc2` 0.6 — <https://docs.rs/objc2>

### Project documents

- [`docs/macos-wifi-feasibility.md`](../docs/macos-wifi-feasibility.md) — the original "native Wi-Fi registration is blocked" finding
- [`masterplan.md`](../masterplan.md) — architecture tracks and the Linux-backed fallback
- [`README.md`](../README.md) — current MT7601U implementation status
- [`docs/build-macos-app.md`](../docs/build-macos-app.md) — bundle layout and `Info.plist`

---

## Appendix A — If you ever do want a single enclosure

This section is retained from the earlier combo-dongle study. It is **not** part of the current plan; it is here so the hardware work is not lost if the requirement changes.

### A.1 Topology

```
USB-C receptacle → ESD/fuse → 3.3 V regulator → USB 2.0 hub
                                                  ├── CSR8510 A10 (BT, 0a12:0001)
                                                  └── MT7601U (Wi-Fi, 148f:7601)
```

A hub is the only sane topology. A single composite device with one VID/PID would need a microcontroller proxying both radios, which is impractical for the Wi-Fi data path and would break the Bluetooth allowlist.

### A.2 The VID trap

`bluetoothd` keys its allowlist on vendor ID. A custom-branded VID is logged as `Not in supported list`. To keep native Bluetooth you must either ship the CSR module's `0a12` identity with the module vendor's permission, or license a supported VID. Reporting CSR's VID without permission is not a legitimate product strategy.

### A.3 Power and RF

- Peak load with both radios active is roughly 600–700 mA, above the 500 mA USB 2.0 bus limit. Request 900 mA from USB-C, add 220–470 µF bulk capacitance, or use a powered hub.
- Both radios are 2.4 GHz. Separate the antennas by 20–30 mm, shield the modules, and keep clocks away from the antennas.
- Coordinated coexistence is unlikely: consumer CSR8510 modules do not expose a usable BT coexistence interface. Expect A2DP to degrade Wi-Fi throughput and vice versa.

### A.4 BOM sketch (1k units)

| Part | Est. cost |
|---|---|
| USB 2.0 hub IC | $0.40–1.50 |
| CSR8510 module | $2–5 |
| MT7601U module | $2–4 |
| Power, passives, ESD | $1–2 |
| 4-layer RF PCB | $2–5 |
| Assembly/test | $2–5 |
| Enclosure, antennas, cable | $3–8 |
| **Total** | **~$12–30** |

Excludes NRE, RF tuning, firmware, and certification (FCC/CE/IC, Bluetooth SIG, Wi-Fi Alliance, USB-IF: roughly $15k–50k+).

### A.5 Verdict

Technically buildable, commercially weak for the stated goal, and unnecessary now that the plan is two off-the-shelf dongles plus one app.

---

## Appendix B — Reproduction commands

```bash
# Machine and OS
sw_vers
uname -m
sysctl -n machdep.cpu.brand_string

# Radios
system_profiler SPAirPortDataType
system_profiler SPBluetoothDataType
system_profiler SPUSBHostDataType

# USB devices
ioreg -p IOUSB -l -w0 | grep -E '"USB Product Name"|"idVendor"|"idProduct"|"bcdDevice"'

# Wi-Fi driver landscape
ls /System/Library/Extensions | grep -iE '80211|wlan|airport'
ls /System/Library/DriverExtensions | grep -iE 'wlan|80211|airport'
ioreg -c IOUserNetworkWLAN -r -d 1

# Bluetooth stack
ioreg -c IOBluetoothHCIController -r -d 2
strings -a /usr/sbin/bluetoothd | grep -iE 'Found_USB_Dongle|Not in supported|BAM supported|bluetoothHostControllerSwitchBehavior'
nvram bluetoothHostControllerSwitchBehavior

# Public frameworks present in the SDK
ls "$(xcrun --show-sdk-path)/System/Library/Frameworks" | grep -iE 'bluetooth'
```

---

## Appendix C — Decision checklist

- [ ] Accept that the MT7601U is Wi-Fi-only and cannot do Bluetooth.
- [ ] Accept that the Wi-Fi tab is app-managed and will not appear in System Settings.
- [ ] Confirm the Bluetooth tab targets the built-in controller by default.
- [ ] Add `NSBluetoothAlwaysUsageDescription` to the bundle.
- [ ] Run Phase A (API probe) before writing the Rust backend.
- [ ] Decide whether the CSR8510 is in scope at all.
- [ ] If yes, run Phase C and record pass/kill before depending on it.
- [ ] Keep the privileged helper Wi-Fi-only.
- [ ] Write the Wi-Fi/Bluetooth asymmetry into the UI copy.
