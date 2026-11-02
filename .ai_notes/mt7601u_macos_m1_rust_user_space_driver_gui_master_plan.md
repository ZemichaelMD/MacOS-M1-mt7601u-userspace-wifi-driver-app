# Master Plan & Requirements: Native macOS (Apple Silicon) Rust User-Space Driver & Wi-Fi Client for MediaTek MT7601U (`0x148f:0x7601`)

This document is an exhaustive engineering blueprint and implementation guide intended for an AI coding agent or developer to build a standalone, native Rust application on an M1/M2/M3/M4 macOS MacBook Air.

The application will feature a **Graphical User Interface (GUI)** to scan, list, and connect to Wi-Fi SSIDs, backed by a custom **user-space USB driver and network bridge** communicating directly with the MediaTek MT7601U USB Wi-Fi adapter via `libusb`, bypassing kernel extension restrictions without requiring permanent SIP disablement for standard user-space app execution.

## 1. System Requirements & Environment Setup

Before starting the coding agent workflow, your M1 MacBook Air must have the correct toolchain installed to compile cross-platform USB and graphics libraries.

### Step 1: Install Homebrew (Package Manager)

If not already installed, open Terminal and run:

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

```

### Step 2: Install System Dependencies (`libusb` & `pkg-config`)

`rusb` relies on native `libusb` C libraries. Install them via Homebrew:

```
brew install libusb pkg-config

```

### Step 3: Install Rust Toolchain (ARM64 Native)

Install Rust via `rustup`:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

```

Follow the on-screen prompts, then reload your shell environment:

```
source "$HOME/.cargo/env"

```

Verify the target architecture is native Apple Silicon (`aarch64-apple-darwin`):

```
rustc --version
rustup target add aarch64-apple-darwin

```

## 2. Reference Repositories for the Agent

To correctly implement register maps, initialization sequences, and firmware byte injections, the agent **must** reference these open-source implementations:

1. **Linux Kernel Driver Reference (Register Maps & Init Logic):**

   * Repo: [Linux Kernel - MediaTek `mt7601u`](https://github.com/torvalds/linux/tree/master/drivers/net/wireless/mediatek/mt7601u)

   * *Key files to inspect:* `init.c`, `mcu.c`, `reg.h`, `mac80211.c`.

2. **Firmware Blob Source:**

   * Repo: [Linux Firmware - `mt7601u.bin`](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/mediatek/mt7601u.bin)

   * *Action:* Download `mt7601u.bin` and embed it directly into the binary or package it as a resource asset.

3. **User-Space USB Rust Reference:**

   * Crate/Repo: [`rusb` (Rust libusb wrapper)](https://github.com/a1wong/rusb)

## 3. Project Architecture & Cargo Configuration (`Cargo.toml`)

The application will use a modular structure combining asynchronous runtime handling (`tokio`), USB communication (`rusb`), a lightweight GUI (`egui`/`eframe`), and TUN network bridging.

### Recommended `Cargo.toml`

```
[package]
name = "mt7601u_macos_bridge"
version = "0.1.0"
edition = "2021"

[dependencies]
rusb = "0.9"
tokio = { version = "1.35", features = ["full"] }
eframe = "0.26" # Cross-platform GUI framework (Metal accelerated on macOS)
egui = "0.26"
log = "0.4"
env_logger = "0.10"
etherparse = "0.13" # For packet parsing if inspecting IP layers
tun-tap = "0.1"     # Virtual network interface management

```

## 4. Step-by-Step Implementation Blueprint for the Agent

### Phase 1: USB Device Discovery & Firmware Initialization

1. **Enumeration:** Search connected USB devices for Vendor ID `0x148f` and Product ID `0x7601`.

2. **Claim Interface:** Open the device handle, detach kernel drivers if present, and claim Interface `0`.

3. **Firmware Upload:** Load `mt7601u.bin` into memory and execute the vendor-specific control transfers to upload the microcode to the MT7601 MCU.

4. **Register Configuration:** Execute the baseband (BBP) and RF transceiver initialization sequence derived from the Linux driver (`init.c`).

### Phase 2: GUI Development (`eframe` / `egui`)

Create a native desktop window allowing the user to interact with the hardware adapter:

* **Status Card:** Displays adapter connection state (`Disconnected`, `Initializing`, `Connected to SSID`).

* **Scan Button:** Triggers an active/passive channel scan loop via the USB control endpoints.

* **Network List UI:** Displays a table of discovered SSIDs, signal strengths (RSSI), and encryption types (WPA2/WPA3).

* **Connect Input Form:** Input text boxes for SSID and Password, paired with a "Connect" action button that initiates the association handshake state machine.

### Phase 3: Packet Tunneling & Network Bridge (`utun`)

1. **Virtual Interface Creation:** Spawn a user-space TUN interface (`utunX`) on macOS using system APIs or the `tun-tap` crate.

2. **Data Loop (TX Pipeline):** Read raw IP packets coming out of macOS via the TUN file descriptor, encapsulate them into 802.11 data frames, and push them to the MT7601U bulk-out endpoint (`EP4`).

3. **Data Loop (RX Pipeline):** Read incoming bulk transfers from the MT7601U bulk-in endpoint (`EP1`/`EP2`), strip 802.11/radiotap headers, and write the raw Ethernet/IP payloads back into the macOS TUN interface.

## 5. Verification Checklist for the Agent

* \[ \] **Compilation Test:** `cargo build --target aarch64-apple-darwin` builds successfully without linking errors against `libusb`.

* \[ \] **Device Detection Test:** Launching the app successfully logs `Found MT7601U Dongle (0x148f:0x7601)` when plugged into the M1 MacBook Air USB port.

* \[ \] **GUI Launch:** The egui application window opens smoothly with native Metal rendering on macOS.

* \[ \] **Firmware Handshake:** USB control register read-backs confirm successful MCU boot state post-firmware injection.