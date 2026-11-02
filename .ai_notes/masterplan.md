# MT7601U macOS Wi-Fi Bridge --- Rust Master Plan

**Target:** Apple Silicon Mac (M1/M2/M3/M4), macOS ARM64\
**USB device:** MediaTek MT7601U, commonly VID:PID `148f:7601`\
**Language:** Rust\
**GUI:** List available Wi-Fi networks, select an SSID,
connect/disconnect, and show status\
**Primary goal:** Make the device appear as a normal Wi-Fi interface in
macOS settings if a supported integration path exists.\
**Fallback goal:** Connect the dongle to Wi-Fi and provide internet
connectivity to macOS through a user-space or Linux-backed
network-sharing path.

## 0. Executive decision

A Rust user-space program is easier to develop and debug than a kernel
extension. It can communicate with vendor-specific USB devices using
`rusb`/libusb or `nusb`. However, **Rust + USB + `utun` does not by
itself make the MT7601U a working Wi-Fi adapter**.

The hard part is implementing or porting the device's full Wi-Fi station
behavior. The Linux driver is integrated with Linux `mac80211`, which
provides major parts of the 802.11 stack; that infrastructure is not
automatically available to a macOS user-space program.

  -----------------------------------------------------------------------------------
  Goal                                Feasibility             Notes
  ----------------------------------- ----------------------- -----------------------
  Detect USB device from Rust         High                    Verify real descriptors
                                                              and access on the
                                                              target macOS

  Port firmware/register operations   Medium                  Requires careful
                                                              translation and
                                                              hardware tests

  Implement full                      Low-to-medium           Significant driver and
  scan/associate/authenticate/TX/RX                           wireless-protocol work
  station                                                     

  GUI to display scan results         Medium                  Depends on real scan
                                                              support in the backend

  `utun` IP tunnel                    Medium                  Does not implement
                                                              Wi-Fi

  Native Wi-Fi device in System       Very low / potentially  Apple documents
  Settings                            platform-blocked        NetworkingDriverKit as
                                                              Ethernet-only

  Linux driver plus shared            Best practical fallback Reuses the upstream
  connectivity                                                working wireless stack
  -----------------------------------------------------------------------------------

**Recommendation:** Build a Rust GUI and USB diagnostic tool first.
Treat scanning/association as a separate milestone. Do not promise a
working connection until it has been demonstrated on the physical
adapter.

## 1. Critical correction: `utun` is not Wi-Fi

`utun` is a layer-3 IP tunnel. It exchanges IP packets with a user-space
program. It does not scan access points, select an SSID, associate,
perform WPA key negotiation, or create a normal Wi-Fi device in System
Settings.

For a tunnel-based design, the daemon must still implement a working
Wi-Fi station, convert outgoing IP packets into the device's expected
data path, and decapsulate received traffic back into IP packets. This
depends on the chip's firmware, descriptors, security state, and station
behavior.

Do **not** hardcode endpoint numbers such as EP1, EP2, or EP4 based on
an unverified description. Read the actual USB descriptors and the Linux
driver. Radiotap is a common monitor-capture metadata format; do not
assume every USB packet contains a radiotap header.

## 2. Architecture tracks

### Track A --- Native macOS Wi-Fi interface (research; very high risk)

``` text
MT7601U USB
    |
Rust USB transport + device implementation
    |
802.11 station behavior
    |
Supported public macOS Wi-Fi registration mechanism?
    |
System Settings Wi-Fi UI / macOS Wi-Fi stack
```

This track has a major feasibility gate. Apple's public
NetworkingDriverKit documentation currently says Ethernet is the only
networking interface supported by that framework. USBDriverKit is not
itself a Wi-Fi registration API, and an Ethernet DriverKit sample does
not establish that a third-party Wi-Fi interface can be registered.

Research current Apple documentation and entitlement requirements before
investing heavily. If no supported public Wi-Fi integration mechanism
exists, document the blocker rather than trying to disguise a `utun`
interface as Wi-Fi.

### Track B --- Rust user-space station plus `utun` (experimental; hard)

``` text
macOS apps -> IP routing -> utun (IP packets)
                         -> Rust daemon
                            - MT7601U USB transport
                            - firmware/register/MCU operations
                            - RX/TX descriptor handling
                            - 802.11 station state machine
                            - authentication/encryption integration
                         -> MT7601U -> Wi-Fi AP
```

This could theoretically provide IP connectivity without a native Wi-Fi
device, but only after the station implementation works. Raw packet
crafting and a TUN crate do not provide WPA2 station behavior.

### Track C --- Linux-backed connectivity (recommended fallback)

``` text
MT7601U -> Linux kernel mt7601u + mac80211 + wpa_supplicant/NetworkManager
        -> Linux internet connection
        -> VM networking / Ethernet / USB Ethernet / router sharing
        -> Mac internet connection
```

Use an ARM64 Linux VM with verified USB passthrough or a separate Linux
device such as a Raspberry Pi. USB passthrough/reset can be unreliable
for some devices, so a separate Linux device is the fallback if the VM
cannot claim the adapter reliably.

## 3. Reference repositories and documentation

Use upstream sources first. Record source paths and commit hashes in
project notes.

### Hardware and USB

-   Linux MT7601U driver:
    https://github.com/torvalds/linux/tree/master/drivers/net/wireless/mediatek/mt7601u
-   Linux firmware repository:
    https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/mediatek
-   libusb: https://github.com/libusb/libusb
-   Rust `rusb`: https://docs.rs/rusb/latest/rusb/
-   Rust `nusb`: https://docs.rs/nusb/latest/nusb/

The Linux driver depends on Linux kernel services and `mac80211`; it is
not a standalone user-space library. Verify firmware filename/version
and licensing before redistributing any blob.

### Apple platform

-   DriverKit: https://developer.apple.com/documentation/driverkit
-   USBDriverKit: https://developer.apple.com/documentation/usbdriverkit
-   NetworkingDriverKit:
    https://developer.apple.com/documentation/networkingdriverkit
-   Apple network-driver sample (Ethernet, not Wi-Fi):
    https://developer.apple.com/documentation/pcidriverkit/connecting-a-network-driver
-   Example of macOS `utun_control` implementation (old code; reference
    only): https://github.com/mafintosh/utun

### Rust GUI

-   `eframe`/`egui`: https://github.com/emilk/egui
-   `egui` documentation: https://docs.rs/egui/latest/egui/
-   Alternative GUI framework, Tauri: https://tauri.app/start/

**GUI recommendation:** Use `eframe`/`egui` initially. It keeps the GUI
in Rust and avoids a separate JavaScript frontend. Never perform
blocking USB I/O on the UI thread.

## 4. Install the toolchain on the Mac

### 4.1 Confirm platform

``` bash
uname -m
sw_vers
```

The native Apple Silicon architecture should be `arm64`. If the terminal
runs under Rosetta, investigate before building.

### 4.2 Install Apple command-line tools

``` bash
xcode-select --install
xcode-select -p
clang --version
git --version
```

A full Xcode installation may be useful later for signing, entitlements,
app packaging, and debugging.

### 4.3 Install Homebrew

Follow the official instructions at https://brew.sh/ and follow its
printed shell setup steps. Apple Silicon Homebrew normally lives under
`/opt/homebrew`.

``` bash
brew --version
```

### 4.4 Install Rust with rustup

Official instructions: https://www.rust-lang.org/tools/install

``` bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts, reload the shell environment, then verify:

``` bash
rustc --version
cargo --version
rustup show
rustup target add aarch64-apple-darwin
rustup component add rustfmt clippy
```

Do not use `sudo` for Cargo package installation.

### 4.5 Install USB build dependencies

For `rusb`/libusb:

``` bash
brew install libusb pkg-config
pkg-config --modversion libusb-1.0
pkg-config --cflags --libs libusb-1.0
```

If using `nusb`, libusb may not be required because `nusb` uses native
platform USB support. Choose one USB library initially and validate it
against the real device.

Optional:

``` bash
brew install cmake
```

Install other packages only when the selected crate or a reproducible
build error requires them.

## 5. Create the Rust project

``` bash
mkdir -p ~/Projects/mt7601u-macos
cd ~/Projects/mt7601u-macos
cargo new --bin mt7601u-app
cd mt7601u-app
cargo run
git init
git add .
git commit -m "Initialize MT7601U macOS Rust project"
```

Suggested layout:

``` text
mt7601u-macos/
├── README.md
├── Cargo.toml
├── Cargo.lock
├── docs/
│   ├── architecture.md
│   ├── feasibility.md
│   ├── usb-descriptors.md
│   ├── firmware-and-registers.md
│   ├── protocol-notes.md
│   ├── macos-networking.md
│   └── test-plan.md
├── src/
│   ├── main.rs
│   ├── app.rs
│   ├── app_state.rs
│   ├── commands.rs
│   ├── usb/{mod.rs,enumerate.rs,transport.rs}
│   ├── mt7601u/{mod.rs,firmware.rs,registers.rs,mcu.rs,rx.rs,tx.rs}
│   ├── wifi/{mod.rs,scan.rs,station.rs,security.rs}
│   └── networking/{mod.rs,utun.rs,routes.rs,packet_bridge.rs}
└── tests/
    ├── parser_tests.rs
    └── fixtures/
```

Do not create fake module implementations merely to fill the directory
tree. Add modules when their responsibilities and tests are understood.

## 6. Rust dependency strategy

Keep the initial dependency set small. Commit `Cargo.lock` for the
application.

### GUI, async coordination, and logging

``` bash
cargo add eframe
cargo add tokio --features rt-multi-thread,macros,sync,time
cargo add tracing tracing-subscriber
cargo add anyhow thiserror
```

Use `anyhow` for application-level error context and `thiserror` for
typed errors in library modules.

### Choose one USB crate

**Option A --- `rusb` + libusb**

``` bash
cargo add rusb
```

`rusb` wraps libusb and maps well to common USB driver concepts. Keep
blocking operations off the UI thread, using a dedicated worker thread
or `tokio::task::spawn_blocking`. Do not assume `rusb` automatically
makes all transfers asynchronous; verify the API before designing a
transfer engine.

**Option B --- `nusb`**

``` bash
cargo add nusb
```

`nusb` is a Rust-native cross-platform USB library with blocking and
async APIs and macOS support via IOKit. Check its current documentation
for device configuration, interface claiming, and transfer behavior.

**Decision gate:** Prototype enumeration/open/claim using one library.
Select based on actual build and device-access results on the target
macOS version. Abstract transport behind a small trait so protocol logic
is not tied to one crate.

Do not add packet or 802.11 crates just because their names sound
relevant. Verify they support the exact needed functions; a packet
parser does not implement a Wi-Fi station or WPA supplicant.

## 7. GUI requirements

The first GUI should include:

-   **Device:** detected/not detected, VID/PID, interface and USB state.
-   **Wi-Fi:** state values such as "not implemented," "scanning,"
    "networks found," "connecting," "connected," or a clear error.
-   **Network list:** SSID, BSSID, signal, channel, and security only
    when actually obtained from the device.
-   **Controls:** Scan, select SSID, enter password, Connect,
    Disconnect.
-   **Connection info:** IP address, gateway, DNS, duration, diagnostics
    once those features exist.
-   **Logs:** status/error messages and copy/export, excluding
    credentials and key material.

Backend architecture: 1. The UI sends commands through a channel to a
backend worker/state machine. 2. The backend returns state updates
through another channel. 3. USB operations and packet processing never
block the UI thread. 4. Operations have timeouts and cancellation
behavior. 5. Passwords are never logged or stored in plaintext. 6. Until
scan support exists, show a disabled Scan button or "not implemented";
never show fake networks. 7. Do not show "Connected" just because USB
opened or firmware loaded.

The first GUI milestone is only a working app shell, device detection,
descriptor display, and logs.

## 8. Implementation phases and exit gates

### Phase 0 --- Collect facts and protect the machine

Run:

``` bash
system_profiler SPUSBDataType
system_profiler SPAirPortDataType
```

Record macOS version and USB descriptors. Remove serial numbers from
public logs. Avoid disabling SIP or changing startup security. Keep a
recovery/internet option available if possible.

**Exit gate:** Confirm the exact VID/PID, interface descriptors,
endpoints, and USB speed.

### Phase 1 --- Prove the adapter works on Linux

Use an ARM64 Linux environment or a VM with USB passthrough:

``` bash
lsusb
lsusb -t
ip link
iw dev
iw list
dmesg | grep -iE 'mt7601|firmware|wlan|usb'
```

Connect with the distro's normal network manager or supplicant. Verify
scan, association, DHCP/IP, DNS, internet access, sustained traffic, and
reconnect.

**Exit gate:** The exact physical dongle works on Linux. If not, resolve
hardware/firmware/USB problems before macOS porting.

### Phase 2 --- Build the Rust GUI skeleton

-   Create the `eframe` app and backend worker.
-   Display status and logs.
-   Add a device panel and disabled scan/connect controls.
-   Add tests for GUI state transitions.

**Exit gate:** ARM64 app launches and remains responsive.

### Phase 3 --- USB enumeration and descriptors

-   Enumerate devices and match `0x148f:0x7601` if present.
-   Display configuration, interface, alternate-setting, and endpoint
    descriptors.
-   Open/close safely and log errors.
-   Test unplug/replug.
-   Do not assume macOS can detach kernel drivers the same way Linux
    can.

**Exit gate:** Repeatable detection/open/close with no crashes or
unrelated-device interference.

### Phase 4 --- Firmware/register initialization

Map Linux functions to small Rust operations. Document control requests,
register accesses, MCU commands, firmware upload, calibration and
timing. Verify firmware provenance and redistribution terms. Add
timeouts and bounds checks. Do not blindly replay register dumps or
guess values.

**Exit gate:** A repeatable initialized state is demonstrated. A
successful firmware transfer alone is not proof of radio operation.

### Phase 5 --- Understand firmware and 802.11 responsibilities

Document what the firmware handles versus the Linux host
driver/mac80211. Determine the actual scan commands, RX/TX descriptor
formats, management-frame behavior, security/key handling, retries, and
power management. Tie claims to source functions or hardware tests.

**Exit gate:** A protocol document exists with unknowns clearly marked.

### Phase 6 --- RX/TX transport and parsers

Implement bounded queues, checked lengths, explicit endianness,
cancellation, unplug handling, and recovery. Unit-test
malformed/truncated buffers. Keep raw USB transport separate from
station logic. Successful USB bulk-out completion does not prove
over-the-air transmission.

**Exit gate:** Stable transport behavior and passing parser tests.

### Phase 7 --- Wi-Fi scanning and secure station connection

This is a major milestone. Implement or port the necessary station
behavior based on evidence. It may include scan initiation/result
parsing, channel/regulatory handling, authentication, association,
WPA/WPA2 key management, protected data frames, sequence numbers,
retries, disconnect events, and firmware-specific descriptors.

Do not assume Linux `wpa_supplicant` can be dropped into macOS
unchanged. If reuse is considered, research portability, interfaces,
build requirements, and license separately.

**Exit gate:** Real access points can be scanned; a secure connection
can be established; bidirectional data works; reconnect after AP loss
works.

### Phase 8 --- Test `utun` independently, then integrate

Prototype a macOS `utun` interface independently before connecting it to
the USB path. The macOS `utun_control` mechanism commonly uses
`PF_SYSTEM`, `SYSPROTO_CONTROL`, and `com.apple.net.utun_control`;
confirm details for the target OS and the chosen implementation.

-   Verify read/write framing and IPv4/IPv6 packet handling.
-   Specify tunnel addressing and routing; do not copy an arbitrary
    `192.168.1.x` example.
-   Configure routes, DNS, and MTU using a tested approach.
-   Define how IP packets map to the Wi-Fi station's data path.
-   Avoid routing loops.
-   Restore previous routes/DNS on disconnect and application exit.
-   Test DHCP/IP configuration, DNS, MTU, packet loss, and reconnection.

**Exit gate:** Real IP packets travel through the real Wi-Fi station to
the internet and return. Loopback alone is insufficient.

### Phase 9 --- Decide native Wi-Fi feasibility

Identify a documented public API that can register a third-party Wi-Fi
device and integrate scanning/association with macOS settings. Verify
target OS support and entitlements. Do not use an Ethernet DriverKit
sample as proof of Wi-Fi support.

Apple's public NetworkingDriverKit documentation currently states that
Ethernet is the only networking interface supported by that framework.
If no supported public Wi-Fi integration point can be established, mark
native System Settings integration as blocked and keep the tunnel/Linux
fallback separate.

### Phase 10 --- Packaging and reliability

Only after real traffic works: - package GUI and helper; - use least
privilege; - document installation and permissions; - handle USB
removal, shutdown, reconnect and backoff; - keep credentials out of
logs; - test sustained traffic, sleep/wake, and route rollback; -
provide uninstall/recovery steps.

Do not disable SIP as a routine workaround. Do not install a launch
daemon until foreground operation is stable.

## 9. Networking details the agent must not gloss over

-   `utun` addressing is not automatically the address of the Wi-Fi LAN.
    Specify and test the route/addressing model.
-   TUN is layer 3; TAP is layer 2 Ethernet where supported. `utun` is
    not a generic TAP device.
-   A Wi-Fi station is not simply an Ethernet bridge. Device-specific
    802.11 framing, LLC/SNAP, station MAC, encryption/key state, and
    descriptors matter.
-   The GUI cannot create scan support; it can only display actual
    backend results.
-   If station implementation or macOS integration becomes blocked,
    Linux can operate the adapter and share connectivity with the Mac.

## 10. Tests and acceptance checklist

### Unit tests

-   USB descriptor parsing
-   request construction and firmware chunk bounds
-   RX/TX descriptor parsing
-   malformed/truncated frame handling
-   station state transitions
-   GUI state transitions
-   route rollback logic

### Hardware tests

-   device absent/present
-   unplug during initialization
-   firmware failure and retry
-   interface-claim failure
-   AP unavailable
-   wrong password
-   unsupported security mode
-   AP disconnect/reconnect
-   IP/DHCP failure
-   DNS failure
-   sustained traffic
-   quit with transfers pending

### Acceptance

-   [ ] Native ARM64 build succeeds
-   [ ] GUI stays responsive
-   [ ] Actual USB descriptors are displayed
-   [ ] Initialization is repeatable and documented
-   [ ] Scan results are real SSIDs from the device
-   [ ] Secure association works
-   [ ] IP and DNS work
-   [ ] Internet traffic works bidirectionally
-   [ ] Reconnect/shutdown are reliable
-   [ ] No credentials/key material in logs
-   [ ] Routes restore after exit
-   [ ] Native Wi-Fi claim is tested against a documented path or marked
    unsupported

## 11. Instructions for the AI coding agent

Work incrementally. After each phase: 1. Summarize changes and exact
commands/tests run. 2. Add tests for parser/state logic. 3. Cite Linux
source paths or official documentation for hardware/API claims. 4. Mark
unknowns explicitly; never invent endpoints, registers, entitlements,
APIs, firmware behavior, or test results. 5. Keep `cargo fmt --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, and
`cargo test` passing where applicable. 6. Do not claim Wi-Fi works until
tested on the physical dongle. 7. Never silently substitute `utun` for a
Wi-Fi interface. 8. Do not modify SIP/startup security or system routes
without explicit approval and a rollback plan. 9. Document third-party
licenses and firmware redistribution terms.

### First tasks to start now

1.  Inspect the upstream Linux driver and write
    `docs/driver-source-map.md`.
2.  Create the `eframe` GUI shell and backend worker.
3.  Implement USB enumeration using either `nusb` or `rusb`.
4.  Display real descriptors and log open/close results.
5.  Write `docs/macos-wifi-feasibility.md` about the supported Wi-Fi
    integration boundary.
6.  Do not attempt full 802.11 station behavior until these steps build
    and pass tests.

## 12. Final recommendation

Rust makes the implementation easier to structure and safer to test, but
it does not eliminate the missing Wi-Fi integration or the complexity of
802.11 station/WPA behavior.

Recommended order: 1. Validate the dongle on Linux. 2. Build the Rust
GUI and USB diagnostic tool. 3. Port initialization and document the
protocol in testable pieces. 4. Prove scanning and secure association
before integrating `utun`. 5. Investigate native Wi-Fi registration
early and stop that track if no supported public path exists. 6. Keep
Linux-based network sharing as the practical fallback for getting the
Mac online.

**Do not promise that this plan will create a normal Wi-Fi entry in
macOS System Settings.** A Rust USB tool and possibly an experimental
user-space connection path are plausible; native Wi-Fi integration is a
separate, unproven feasibility problem.
