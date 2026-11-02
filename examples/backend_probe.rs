//! Hardware probe for the GUI's own state machine, without a window.
//!
//! The reopen probe drives `scan::bringup_and_scan` directly. This one drives
//! `backend::Backend` with the very `Command`s the toolbar buttons send — the
//! automatic open/scan on launch, **Stop**, **Start** and the **Scan** button —
//! so the path the GUI takes is exercised end to end.
//!
//! ```text
//! HOME=/tmp/probe cargo run --example backend_probe [cycles]   # cycles default 3
//! ```
//!
//! Run it with a throwaway `HOME`: the backend reads its saved networks from
//! `$HOME/Library/Application Support/...`, so an empty home also means no
//! automatic reconnect (and therefore no tunnel, routes or DNS changes).
//!
//! Exits non-zero if any scan failed or the backend asked for a replug.

use std::time::{Duration, Instant};

use mt7601u_macos::backend::Backend;
use mt7601u_macos::commands::{Command, Event};
use mt7601u_macos::logging::LogLevel;
use mt7601u_macos::wifi::WifiState;

/// Long enough for a 14-channel passive scan plus a bring-up.
const STEP_TIMEOUT: Duration = Duration::from_secs(45);

/// What the probe saw while waiting.
#[derive(Default)]
struct Observed {
    scanned: Vec<usize>,
    failures: Vec<String>,
}

/// Drain events until `done` says so, or the step times out.
fn wait_for(
    backend: &mut Backend,
    observed: &mut Observed,
    what: &str,
    mut done: impl FnMut(&Event) -> bool,
) -> bool {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while Instant::now() < deadline {
        for event in backend.drain() {
            match &event {
                Event::Log(line) => {
                    if line.level == LogLevel::Error {
                        observed.failures.push(format!("{what}: {}", line.message));
                    }
                }
                Event::Replug(Some(hint)) => {
                    observed
                        .failures
                        .push(format!("{what}: asked for a replug — {hint}"));
                }
                Event::Wifi(WifiState::Error(message)) => {
                    observed.failures.push(format!("{what}: {message}"));
                }
                Event::ScanResults(networks) => observed.scanned.push(networks.len()),
                _ => {}
            }
            if done(&event) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("[FAIL] {what}: timed out after {:?}", STEP_TIMEOUT);
    false
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

    let mut backend = Backend::spawn(egui::Context::default());
    let mut observed = Observed::default();
    let mut ok = true;

    // What the app does on launch: open the dongle and scan unprompted.
    println!("--- launch: automatic open + scan ---");
    ok &= wait_for(&mut backend, &mut observed, "launch", |event| {
        matches!(event, Event::ScanResults(_))
    });

    for cycle in 1..=cycles {
        println!("--- Stop → Start, cycle {cycle} ---");

        backend.send(Command::CloseDevice);
        ok &= wait_for(&mut backend, &mut observed, "Stop", |event| {
            matches!(event, Event::Paused(true))
        });

        backend.send(Command::OpenDevice);
        ok &= wait_for(
            &mut backend,
            &mut observed,
            &format!("Start {cycle}"),
            // The reopened device scans on its own.
            |event| matches!(event, Event::ScanResults(_)),
        );
    }

    println!("--- Scan button (rescan) ---");
    backend.send(Command::Scan);
    ok &= wait_for(&mut backend, &mut observed, "rescan", |event| {
        matches!(event, Event::ScanResults(_))
    });

    println!("\nscan results seen: {:?}", observed.scanned);
    if observed.failures.is_empty() {
        println!("no errors reported by the backend");
    } else {
        println!("errors reported by the backend:");
        for failure in &observed.failures {
            println!("  {failure}");
        }
    }

    let scans_ok = observed.scanned.iter().all(|count| *count > 0);
    if !scans_ok {
        println!("note: only network-free scans were seen (nothing in range?)");
    }

    ok &= observed.failures.is_empty();
    println!();
    if ok && scans_ok {
        println!("PASS: Stop → Start and rescan both came back with networks.");
        std::process::ExitCode::SUCCESS
    } else {
        println!("FAIL: the GUI path did not recover (see above).");
        std::process::ExitCode::FAILURE
    }
}
