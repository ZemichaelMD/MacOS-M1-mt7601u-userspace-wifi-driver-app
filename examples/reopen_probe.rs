//! Hardware probe for the reopen path: Stop → Start, and rescan.
//!
//! Two separate `--scan` runs are not the same thing as the GUI's Stop → Start,
//! which closes and reopens the USB handle *in the same process* with no delay.
//! This probe drives those cycles directly against the library so the reopen
//! path can be exercised on the physical dongle.
//!
//! ```text
//! cargo run --example reopen_probe [cycles]     # cycles defaults to 3
//! ```
//!
//! Each case prints `[ ok ]` or `[FAIL]`, and the exit code is non-zero if any
//! case failed. A failure that mentions `MCU response for seq … not received` is
//! the wedge this probe exists to catch (`HANDOVER.md` §3).

use std::path::Path;
use std::time::Duration;

use mt7601u_macos::mt7601u::{self, scan, Mt7601u};
use mt7601u_macos::paths;
use mt7601u_macos::usb::{enumerate, RusbTransport, Transport};

/// Short dwell: this probe is about init, not about how many APs are in range.
const DWELL: Duration = Duration::from_millis(60);

fn open_chip() -> Result<Mt7601u<RusbTransport>, String> {
    let info = enumerate::find_mt7601u()
        .map_err(|error| format!("USB enumeration failed: {error}"))?
        .ok_or_else(|| {
            format!(
                "MT7601U ({:04x}:{:04x}) not detected",
                mt7601u::VENDOR_ID,
                mt7601u::PRODUCT_ID
            )
        })?;

    let mut transport =
        RusbTransport::open(&info).map_err(|error| format!("open failed: {error}"))?;
    transport
        .claim_interface(mt7601u::DEFAULT_INTERFACE)
        .map_err(|error| format!("claim interface 0 failed: {error}"))?;

    Ok(Mt7601u::new(transport, info))
}

/// Scan on an already-open chip, reporting the outcome.
fn scan_on(chip: &Mt7601u<RusbTransport>, firmware: Option<&Path>, label: &str) -> bool {
    match scan::bringup_and_scan(chip, firmware, DWELL) {
        Ok(networks) => {
            println!("[ ok ] {label}: {} network(s)", networks.len());
            true
        }
        Err(error) => {
            println!("[FAIL] {label}: {error}");
            if let Some(hint) = scan::mcu_recovery_hint(&error) {
                println!("       {hint}");
            }
            false
        }
    }
}

/// `Command::Scan` twice on one open device (the rescan button).
fn case_rescan(firmware: Option<&Path>) -> bool {
    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            println!("[FAIL] rescan: {error}");
            return false;
        }
    };

    let mut ok = scan_on(&chip, firmware, "rescan: open + first scan");
    ok &= scan_on(&chip, firmware, "rescan: second scan, same handle");
    ok
}

/// GUI Stop → Start `cycles` times: init, scan, quiesce, release, reopen.
fn case_stop_start(firmware: Option<&Path>, cycles: u32) -> bool {
    let mut ok = true;

    for cycle in 1..=cycles {
        let chip = match open_chip() {
            Ok(chip) => chip,
            Err(error) => {
                println!("[FAIL] stop/start cycle {cycle}: {error}");
                return false;
            }
        };

        ok &= scan_on(&chip, firmware, &format!("stop/start cycle {cycle}"));

        // What the backend's Stop does before releasing the device.
        chip.mac_stop();
        drop(chip);
    }

    ok
}

/// A previous run that closed the handle *without* quiescing (a crashed GUI, or
/// a CLI `--scan` that simply exited), then a clean open.
fn case_abrupt_close(firmware: Option<&Path>) -> bool {
    let mut ok = true;

    if let Ok(chip) = open_chip() {
        ok &= scan_on(&chip, firmware, "abrupt: open + scan");
        drop(chip); // no mac_stop
    } else {
        println!("[FAIL] abrupt: could not open");
        return false;
    }

    match open_chip() {
        Ok(chip) => ok &= scan_on(&chip, firmware, "abrupt: reopen after unclean close"),
        Err(error) => {
            println!("[FAIL] abrupt: reopen failed: {error}");
            ok = false;
        }
    }

    ok
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .without_time()
        .with_target(false)
        .init();

    let cycles: u32 = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);

    let firmware = paths::find_firmware();
    match firmware.as_deref() {
        Some(path) => println!("Firmware image: {}", path.display()),
        None => println!("Firmware image: not found (a fresh device needs one)"),
    }

    println!("\n--- rescan (same open handle) ---");
    let mut ok = case_rescan(firmware.as_deref());

    println!("\n--- Stop → Start ({cycles} cycles) ---");
    ok &= case_stop_start(firmware.as_deref(), cycles);

    println!("\n--- reopen after an unclean close ---");
    ok &= case_abrupt_close(firmware.as_deref());

    println!();
    if ok {
        println!("PASS: every reopen brought the radio back up.");
        std::process::ExitCode::SUCCESS
    } else {
        println!("FAIL: a reopen needed more than the software can do (see above).");
        std::process::ExitCode::FAILURE
    }
}
