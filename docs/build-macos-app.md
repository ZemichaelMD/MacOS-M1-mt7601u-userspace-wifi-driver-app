# Building a macOS `.app` for the GUI

This produces a double-clickable `MT7601U.app` so you can test the GUI while
development continues. It is an **ad-hoc signed, non-notarized** bundle: fine for
your own machine, not for distribution.

## Prerequisites

* Apple Silicon Mac, `rustup` toolchain (already set up for this project).
* Xcode command line tools (`xcode-select --install`) — provides `codesign`.
* `libusb` via Homebrew (`brew install libusb pkg-config`).

## Build it

From the project root:

```bash
bash scripts/bundle-macos-app.sh
```

That builds in release mode and assembles:

```
dist/MT7601U.app
├── Contents/
│   ├── Info.plist
│   ├── MacOS/MT7601U        # the binary
│   └── Resources/           # (optional AppIcon.icns)
```

Options (environment variables):

```bash
PROFILE=debug bash scripts/bundle-macos-app.sh          # debug build (faster to rebuild)
APP_NAME=MT7601U bash scripts/bundle-macos-app.sh       # rename the bundle
```

## Run it

```bash
open dist/MT7601U.app
```

or double-click `dist/MT7601U.app` in Finder.

### First-launch Gatekeeper prompt

The bundle is ad-hoc signed, so macOS may say it is from an "unidentified
developer". Either:

* Right-click the app → **Open** → **Open**, or
* Clear the quarantine flag:

  ```bash
  xattr -dr com.apple.quarantine dist/MT7601U.app
  ```

### USB access

No entitlements or special permission are required because the app is **not
sandboxed**. If you later sandbox it, add the
`com.apple.security.device.usb` entitlement, or libusb will not see the device.

## The CLI is inside the bundle too

The same binary exposes the diagnostic subcommands:

```bash
dist/MT7601U.app/Contents/MacOS/MT7601U --identify
dist/MT7601U.app/Contents/MacOS/MT7601U --diagnose
dist/MT7601U.app/Contents/MacOS/MT7601U --load-firmware /path/to/mt7601u.bin
dist/MT7601U.app/Contents/MacOS/MT7601U --list
```

## Where logs go

The GUI's **Export…** button writes `mt7601u-log.txt` to `~/Downloads` (falling
back to `$HOME`, then the temp directory). A Finder-launched app has `/` as its
working directory, so it never writes next to the process.

## Testing checklist for the GUI

1. Launch the app; the status bar shows *Device: Not detected* or *Detected*.
2. Click **Refresh** — the log panel should show
   `Found MediaTek MT7601U (VID:PID 148f:7601) …`.
3. Click **Open** — status becomes *Open (interface claimed)*.
4. Click **Identify chip** — the log shows the ASIC version (`0x76010001`),
   MAC CSR0, and eFuse state.
5. Click **Close** — status returns to *Detected (closed)*.
6. Confirm **Scan** and **Connect** stay greyed out (not implemented), and the
   network list stays empty.
7. **Export…** then check `~/Downloads/mt7601u-log.txt`.

## Troubleshooting

* **Window doesn't appear / no output** — run the inner binary from a terminal
  to see stderr:
  `dist/MT7601U.app/Contents/MacOS/MT7601U`
* **"App is damaged"** — re-run the signing step, or `xattr -dr
  com.apple.quarantine dist/MT7601U.app`.
* **Device not detected in the app but works from `--diagnose`** — make sure only
  one process has the interface claimed; quit other instances.
* **Rebuild after code changes** — just re-run the script; it rebuilds and
  replaces the bundle.
