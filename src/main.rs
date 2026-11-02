//! MT7601U macOS bridge — application entry point.
//!
//! Subcommands:
//!   (none)                 launch the GUI
//!   --diagnose             enumerate USB devices, dump descriptors, open/claim
//!   --identify             read ASIC/MAC revision and eFuse state (read-only)
//!   --load-firmware <path> upload an mt7601u.bin image (writes to the device)
//!   --list                 print a one-line summary per USB device
//!   --help                 show usage

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use mt7601u_macos::app::Mt7601uApp;
use mt7601u_macos::helper;
use mt7601u_macos::mt7601u::{self, dma, rx, scan, station, tx, Mt7601u};
use mt7601u_macos::paths;
use mt7601u_macos::tunnel::{self, icmp};
use mt7601u_macos::usb::{enumerate, RusbTransport, Transport, UsbError};
use mt7601u_macos::wifi::{frames, Security};

fn main() -> ExitCode {
    init_tracing();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--diagnose") | Some("-d") => diagnose(),
        Some("--identify") | Some("-i") => identify(),
        Some("--load-firmware") => load_firmware(args.get(1).map(String::as_str)),
        Some("--init") => init_chip(args.get(1).map(String::as_str)),
        Some("--hw-init") => hw_init(args.get(1).map(String::as_str)),
        Some("--read-eeprom") => read_eeprom(),
        Some("--scan") => scan_channels(),
        Some("--connect") => connect(
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
            args.get(3).map(String::as_str),
        ),
        Some("--tx-probe") => tx_probe(
            args.get(1)
                .and_then(|value| value.parse().ok())
                .unwrap_or(1),
        ),
        Some("--tunnel-demo") => tunnel_demo(
            args.get(1)
                .and_then(|value| value.parse().ok())
                .unwrap_or(30),
        ),
        Some("--list") | Some("-l") => list(),
        Some("--helper-daemon") => helper_daemon(),
        Some("--install-helper") => install_helper(),
        Some("--uninstall-helper") => uninstall_helper(),
        Some("--helper-status") => helper_status(),
        Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown argument: {other}\n");
            print_help();
            ExitCode::FAILURE
        }
        None => run_gui(),
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .try_init();
}

fn print_help() {
    println!(
        "mt7601u-macos — user-space diagnostics for the MediaTek MT7601U\n\n\
         USAGE:\n\
         \x20   mt7601u-macos [--diagnose | --identify | --load-firmware <path> | --list | --help]\n\n\
         OPTIONS:\n\
         \x20   --diagnose, -d          Enumerate USB devices, print descriptors, open/claim\n\
         \x20   --identify, -i          Read ASIC/MAC revision and eFuse state (read-only)\n\
         \x20   --load-firmware <path>  Upload a firmware image (WRITES to hardware)\n\
         \x20   --init [<path>]         Upload firmware if needed, run post-init, MCU handshake\n\
         \x20   --hw-init [<path>]      Above, plus MAC/BBP initvals and memory tables (WRITES)\n\
         \x20   --read-eeprom          Read the eFuse: MAC address, channel plan, TX power\n\
         \x20   --scan                  Bring the radio up and passively scan for networks\n\
         \x20   --connect <ssid> [<ch> [<bssid>]]  Associate with an OPEN network (experiment)\n\
         \x20   --tx-probe [<ch>]       Transmit a probe request on a channel and listen (TX test)\n\
         \x20   --tunnel-demo [<secs>]  Create a utun interface and answer pings (needs sudo)\n\
         \x20   --install-helper        Install the privileged helper (sudo) so the GUI need not run as root\n\
         \x20   --uninstall-helper      Remove the privileged helper\n\
         \x20   --helper-status         Report whether the privileged helper is running\n\
         \x20   --helper-daemon         Run the privileged helper in the foreground (launchd)\n\
         \x20   --list, -l              Print a one-line summary for each USB device\n\
         \x20   --help, -h              Print this help\n\
         \x20   (no args)               Launch the GUI"
    );
}

/// Open the MT7601U, claim interface 0, and return the device driver handle.
fn open_chip() -> Result<Mt7601u<RusbTransport>, String> {
    let info = enumerate::find_mt7601u()
        .map_err(|error| format!("USB enumeration failed: {error}"))?
        .ok_or_else(|| {
            format!(
                "MT7601U ({:04x}:{:04x}) not detected.",
                mt7601u::VENDOR_ID,
                mt7601u::PRODUCT_ID
            )
        })?;

    let mut transport =
        RusbTransport::open(&info).map_err(|error| format!("open failed: {error}"))?;

    transport
        .claim_interface(mt7601u::DEFAULT_INTERFACE)
        .map_err(|error| {
            format!(
                "claim interface {} failed: {error}",
                mt7601u::DEFAULT_INTERFACE
            )
        })?;

    Ok(Mt7601u::new(transport, info))
}

fn run_gui() -> ExitCode {
    let viewport = eframe::egui::ViewportBuilder::default()
        .with_title("MT7601U Wi-Fi")
        .with_inner_size([420.0, 660.0])
        .with_min_inner_size([380.0, 420.0])
        // The app paints its own title bar: the native one only contributes
        // the traffic lights, floating over the header, and the content
        // fills the whole window.
        .with_fullsize_content_view(true)
        .with_titlebar_shown(false)
        .with_title_shown(false);
    let viewport = match mt7601u_macos::icon::window_icon() {
        Some(icon) => viewport.with_icon(icon),
        None => viewport,
    };

    let options = eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };

    match eframe::run_native(
        "MT7601U Wi-Fi",
        options,
        Box::new(|cc| Ok(Box::new(Mt7601uApp::new(cc)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("GUI error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn list() -> ExitCode {
    match enumerate::list_devices() {
        Ok(devices) => {
            println!("{} USB device(s) visible to this process:", devices.len());
            for device in &devices {
                let tag = if device.is_mt7601u() {
                    "  <-- MT7601U"
                } else {
                    ""
                };
                println!(
                    "{:04x}:{:04x} bus {:>3} addr {:>3}  {}  {}{}",
                    device.vid,
                    device.pid,
                    device.bus,
                    device.address,
                    device.speed.label(),
                    device.product.as_deref().unwrap_or("<no product string>"),
                    tag
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("USB enumeration failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Run the privileged helper daemon. launchd starts this as root.
///
/// It creates the `utun` interface and shuffles IP packets for the GUI, which
/// otherwise could not create the interface without `sudo`.
fn helper_daemon() -> ExitCode {
    match helper::server::run_daemon() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("helper daemon failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Install the helper LaunchDaemon (re-running itself under `sudo` if needed).
fn install_helper() -> ExitCode {
    match run_as_root("--install-helper") {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Remove the helper LaunchDaemon and binary.
fn uninstall_helper() -> ExitCode {
    match run_as_root("--uninstall-helper") {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Report whether the helper daemon is reachable.
fn helper_status() -> ExitCode {
    if helper::server::is_running() {
        println!(
            "Privileged helper is running (socket {}).",
            helper::SOCKET_PATH
        );
        ExitCode::SUCCESS
    } else {
        println!("Privileged helper is not running.");
        println!(
            "Install it with:  sudo {} --install-helper",
            current_exe_display()
        );
        ExitCode::FAILURE
    }
}

/// Run `this <flag>` as root, re-executing through `sudo` when necessary.
fn run_as_root(flag: &str) -> Result<(), String> {
    if tunnel::is_root() {
        return match flag {
            "--install-helper" => helper::server::install().map(|message| println!("{message}")),
            "--uninstall-helper" => {
                helper::server::uninstall().map(|message| println!("{message}"))
            }
            other => Err(format!("unknown helper flag: {other}")),
        };
    }

    eprintln!("Administrator access is required to {flag}; running sudo…");
    let status = std::process::Command::new("sudo")
        .arg(current_exe_display())
        .arg(flag)
        .status()
        .map_err(|error| format!("could not run sudo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "`sudo {} {flag}` failed. Run it from a terminal, or launch the GUI with sudo.",
            current_exe_display()
        ))
    }
}

fn current_exe_display() -> String {
    std::env::current_exe()
        .map_or_else(|_| "mt7601u-macos".to_string(), |p| p.display().to_string())
}

fn diagnose() -> ExitCode {
    let devices = match enumerate::list_devices() {
        Ok(devices) => devices,
        Err(error) => {
            eprintln!("USB enumeration failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("Found {} USB device(s).\n", devices.len());
    for device in &devices {
        println!("{}", device.describe());
    }

    let Some(info) = devices.into_iter().find(|d| d.is_mt7601u()) else {
        eprintln!(
            "MT7601U ({:04x}:{:04x}) not detected.",
            mt7601u::VENDOR_ID,
            mt7601u::PRODUCT_ID
        );
        return ExitCode::FAILURE;
    };

    println!(
        "Attempting to open and claim interface {}…",
        mt7601u::DEFAULT_INTERFACE
    );
    let mut transport = match RusbTransport::open(&info) {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("  open failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    match transport.claim_interface(mt7601u::DEFAULT_INTERFACE) {
        Ok(()) => {
            println!("  claimed interface {}", mt7601u::DEFAULT_INTERFACE);
            transport.close();
            println!("  released interface and closed device");
            println!("\nDiagnostics OK.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("  claim failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn identify() -> ExitCode {
    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    match chip.wait_asic_ready(100, Duration::from_millis(1)) {
        Ok(()) => println!("ASIC reported ready."),
        Err(error) => eprintln!("warning: ASIC not ready ({error}); reading registers anyway"),
    }

    match chip.identify() {
        Ok(ident) => {
            println!("ASIC version : 0x{:08x}", ident.asic_version);
            println!("ASIC revision: 0x{:04x}", ident.asic_revision());
            println!("MAC CSR0     : 0x{:08x}", ident.mac_csr0);
            println!(
                "eFuse        : {}",
                if ident.efuse_present() {
                    "present"
                } else {
                    "absent"
                }
            );
            println!(
                "Chip id      : {}",
                if ident.is_mt7601() {
                    "MT7601 (expected)"
                } else {
                    "UNEXPECTED — top 16 bits are not 0x7601"
                }
            );
            println!("\nIdentify OK.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("identify failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn load_firmware(path: Option<&str>) -> ExitCode {
    let Some(path) = path else {
        eprintln!("usage: mt7601u-macos --load-firmware <path-to-mt7601u.bin>");
        return ExitCode::FAILURE;
    };
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("Read {} bytes from {path}.", data.len());

    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = chip.wait_asic_ready(100, Duration::from_millis(1)) {
        eprintln!("warning: ASIC not ready before upload ({error})");
    }

    println!("Uploading firmware… (this writes to the device)");
    match chip.load_firmware(&data) {
        Ok(report) => {
            println!("  ILM bytes : {}", report.ilm_bytes);
            println!("  DLM bytes : {}", report.dlm_bytes);
            println!(
                "  Firmware  : {} build {} time '{}'",
                report.version, report.build, report.build_time
            );
            println!(
                "\nFirmware upload OK. Note: a successful transfer is not proof that the radio works."
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("firmware upload failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Read the eFuse: MAC address, channel plan, TX power and calibration.
fn read_eeprom() -> ExitCode {
    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    // The eFuse is only reachable while the WLAN block is clocked.
    if let Err(error) = chip.chip_onoff(true, false) {
        eprintln!("chip_onoff failed: {error}");
        return ExitCode::FAILURE;
    }

    match chip.eeprom_init() {
        Ok(eeprom) => {
            println!(
                "EEPROM version : ee {:#04x}, fae {:#04x}",
                eeprom.version_ee, eeprom.version_fae
            );
            println!("MAC address    : {}", eeprom.mac_string());
            println!(
                "Channel range  : {}..={}",
                eeprom.channels().start(),
                eeprom.channels().end()
            );
            println!("TSSI enabled   : {}", eeprom.tssi_enabled);
            println!("RF freq offset : {}", eeprom.rf_freq_off);
            println!("RSSI offset    : {:?}", eeprom.rssi_offset);
            println!("Reference temp : {}", eeprom.ref_temp);
            println!("LNA gain       : {}", eeprom.lna_gain);
            println!("Channel power  : {:?}", eeprom.chan_pwr);
            if eeprom.version_ee > mt7601u_macos::mt7601u::eeprom::EE_MAX_VER {
                println!("warning: unsupported EEPROM version");
            }
            println!("\nEEPROM read OK.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("EEPROM read failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Bring the radio up, hop to a channel and transmit a probe request, then
/// report anything that comes back. This is the TX-path smoke test.
fn tx_probe(channel: u8) -> ExitCode {
    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    let firmware = paths::find_firmware();
    let (eeprom, mut state) = match scan::bringup(&chip, firmware.as_deref()) {
        Ok(pair) => pair,
        Err(error) => {
            print_usb_error("bring-up failed", &error);
            return ExitCode::FAILURE;
        }
    };
    println!("MAC address: {}", eeprom.mac_string());

    if let Err(error) = chip.phy_set_channel(&eeprom, &mut state, channel) {
        eprintln!("could not set channel {channel}: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = chip.mac_start() {
        eprintln!("mac start failed: {error}");
        return ExitCode::FAILURE;
    }

    // Wildcard probe request at the lowest OFDM rate, broadcast, no encryption.
    let frame = frames::probe_request(eeprom.mac_addr, &[]);
    let rate = tx::rate_val(tx::PHY_TYPE_OFDM, 0, false, false);
    let txwi = tx::build_txwi(frame.len(), 0, rate, false, true, true, 0);

    let endpoint = match chip.ac_endpoint(tx::AC_BE) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "Transmitting a {} byte probe request on channel {channel} (endpoint {endpoint:#04x}) …",
        frame.len()
    );
    match chip.tx_frame(&txwi, &frame, endpoint, dma::QSEL_EDCA, true) {
        Ok(written) => println!("TX completed: {written} bytes handed to the bulk OUT endpoint."),
        Err(error) => {
            eprintln!("TX failed: {error}");
            return ExitCode::FAILURE;
        }
    }

    let rx_endpoint = match chip.rx_endpoint() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    println!("Listening for responses for 3 s …");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buffer = vec![0u8; 8192];
    let mut responses = 0u32;
    let mut beacons = 0u32;

    while Instant::now() < deadline {
        let Ok(len) = chip
            .transport()
            .bulk_in(rx_endpoint, &mut buffer, Duration::from_millis(50))
        else {
            continue;
        };
        if len < 2 {
            continue;
        }
        for segment in rx::parse_segments(&buffer[..len]) {
            if segment.rxwi.is_crc_error() || segment.payload.len() < 2 {
                continue;
            }
            let subtype = (segment.payload[0] >> 4) & 0x0f;
            if let Some(bss) = rx::parse_beacon(segment.payload) {
                match subtype {
                    5 => {
                        responses += 1;
                        println!("  probe response: {:?} ({})", bss.ssid, bss.bssid_string());
                    }
                    8 => beacons += 1,
                    _ => {}
                }
            }
        }
    }

    println!();
    println!("Probe responses: {responses}, beacons seen: {beacons}");
    if responses > 0 {
        println!("TX path works: the radio transmitted and its probe was answered.");
    } else if beacons > 0 {
        println!("RX works, but no probe responses — TX may not be reaching the air yet.");
    } else {
        println!("Nothing received; check the channel and that an AP is in range.");
    }
    ExitCode::SUCCESS
}

/// Create a `utun` interface, configure it and answer ICMP echo requests.
///
/// This proves the macOS half of the tunnel end to end: `ping <peer>` goes
/// macOS -> utun -> this process -> utun -> macOS. Requires root.
fn tunnel_demo(seconds: u64) -> ExitCode {
    let mut utun = match tunnel::Utun::open() {
        Ok(utun) => utun,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("creating a utun interface needs root: {error}");
            eprintln!(
                "try:  sudo {} --tunnel-demo {seconds}",
                std::env::current_exe().map_or_else(
                    |_| "mt7601u-macos".to_string(),
                    |path| path.display().to_string()
                )
            );
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("could not create a utun interface: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("Created {}", utun.name());

    let local = Ipv4Addr::new(10, 9, 9, 1);
    let peer = Ipv4Addr::new(10, 9, 9, 2);

    if !tunnel::is_root() {
        eprintln!();
        eprintln!("{} created, but configuring it needs root.", utun.name());
        eprintln!(
            "try:  sudo {} --tunnel-demo {seconds}",
            std::env::current_exe().map_or_else(
                |_| "mt7601u-macos".into(),
                |path| path.display().to_string()
            )
        );
        return ExitCode::FAILURE;
    }

    if let Err(error) = utun.configure(local, peer, 1500) {
        eprintln!("ifconfig failed: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = utun.set_read_timeout(Duration::from_millis(200)) {
        eprintln!("could not set the read timeout: {error}");
        return ExitCode::FAILURE;
    }

    println!("{} is up: {} -> {}", utun.name(), local, peer);
    println!();
    println!("In another terminal, run:  ping {peer}");
    println!("Answering echo requests for {seconds}s …");
    println!();

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut buffer = [0u8; 2048];
    let mut answered: u64 = 0;

    while Instant::now() < deadline {
        let Ok(len) = utun.read(&mut buffer) else {
            continue;
        };
        if len <= 4 {
            continue;
        }
        let Some((family, packet)) = tunnel::parse_frame(&buffer[..len]) else {
            continue;
        };
        if family != tunnel::AF_INET_HEADER {
            continue;
        }
        if let Some(reply) = icmp::echo_reply(packet) {
            if utun.write_all(&tunnel::frame_ipv4(&reply)).is_ok() {
                answered += 1;
            }
        }
    }

    println!("Answered {answered} ICMP echo request(s); tearing down.");
    utun.teardown();
    ExitCode::SUCCESS
}

/// Bring the radio up (auto-detecting the firmware) and passively scan.
fn scan_channels() -> ExitCode {
    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    let firmware = paths::find_firmware();
    if let Some(path) = &firmware {
        println!("Firmware image: {}", path.display());
    }

    match scan::bringup_and_scan(&chip, firmware.as_deref(), scan::DEFAULT_DWELL) {
        Ok(networks) => {
            if networks.is_empty() {
                println!(
                    "\nNo networks found. If this is unexpected, the RX path/calibration is incomplete."
                );
            } else {
                println!();
                for network in &networks {
                    println!(
                        "{:<32} {:<17} ch {:>2}  {}",
                        network.ssid,
                        network.bssid_string().unwrap_or_else(|| "?".to_string()),
                        network
                            .channel
                            .map(|channel| channel.to_string())
                            .unwrap_or_else(|| "?".to_string()),
                        network.security.label()
                    );
                }
            }
            println!("\n{} network(s) found.", networks.len());
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_usb_error("scan failed", &error);
            ExitCode::FAILURE
        }
    }
}

/// Associate with an **open** network. Experimental: WPA2 and the data path do
/// not exist yet, so success here only proves the 802.11 association exchange.
///
/// With `<ch>` and `<bssid>` the target is used directly; otherwise the radio
/// is scanned for the SSID (reusing the passive scan) to discover them.
fn connect(ssid: Option<&str>, channel: Option<&str>, bssid: Option<&str>) -> ExitCode {
    let Some(ssid) = ssid else {
        eprintln!("usage: mt7601u-macos --connect <ssid> [<channel> [<bssid>]]");
        return ExitCode::FAILURE;
    };
    let channel = match channel {
        Some(value) => match value.parse::<u8>() {
            Ok(channel) => Some(channel),
            Err(_) => {
                eprintln!("invalid channel: {value}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    let bssid = match bssid {
        Some(value) => match parse_mac(value) {
            Ok(bssid) => Some(bssid),
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    let firmware = paths::find_firmware();
    let (eeprom, mut state) = match scan::bringup(&chip, firmware.as_deref()) {
        Ok(pair) => pair,
        Err(error) => {
            print_usb_error("bring-up failed", &error);
            return ExitCode::FAILURE;
        }
    };
    println!("MAC address: {}", eeprom.mac_string());

    let (target, security) = match (bssid, channel) {
        (Some(bssid), Some(channel)) => (
            station::BssTarget::infrastructure(
                ssid.to_string(),
                bssid,
                channel,
                station::CAPABILITY_ESS,
            ),
            // With an explicit BSSID/channel there is no beacon to read the
            // security from: `MT7601U_SECURITY=open|wpa|wpa2|wpa3` states it,
            // and an `MT7601U_PSK` alone still implies WPA2.
            match std::env::var("MT7601U_SECURITY").as_deref() {
                Ok("open") => Security::Open,
                Ok("wpa") => Security::Wpa,
                Ok("wpa2") => Security::Wpa2,
                Ok("wpa3") => Security::Wpa3,
                Ok(other) => {
                    eprintln!("\"{other}\" is not a security mode (open, wpa, wpa2 or wpa3).");
                    return ExitCode::FAILURE;
                }
                Err(_) if std::env::var_os("MT7601U_PSK").is_some() => Security::Wpa2,
                Err(_) => Security::Open,
            },
        ),
        _ => {
            println!("Scanning for \"{ssid}\" to find its BSSID and channel…");
            let networks = match scan::passive_scan(&chip, &eeprom, &mut state, scan::DEFAULT_DWELL)
            {
                Ok(networks) => networks,
                Err(error) => {
                    print_usb_error("scan failed", &error);
                    return ExitCode::FAILURE;
                }
            };
            let Some(network) = networks.into_iter().find(|network| network.ssid == ssid) else {
                eprintln!("no network named \"{ssid}\" was found.");
                return ExitCode::FAILURE;
            };
            let (Some(bssid), Some(channel)) = (network.bssid, network.channel) else {
                eprintln!("\"{ssid}\" was found but without a BSSID/channel.");
                return ExitCode::FAILURE;
            };
            (
                station::BssTarget::infrastructure(
                    ssid.to_string(),
                    bssid,
                    channel,
                    station::CAPABILITY_ESS,
                ),
                network.security,
            )
        }
    };

    let passphrase = std::env::var("MT7601U_PSK").ok();
    match security {
        Security::Open => {}
        Security::Wpa | Security::Wpa2 | Security::Wpa3 => {
            if passphrase.is_none() {
                eprintln!(
                    "\"{ssid}\" is {}; set MT7601U_PSK to the passphrase.",
                    security.label()
                );
                return ExitCode::FAILURE;
            }
        }
        other => {
            eprintln!(
                "\"{ssid}\" is {}; only open, WPA-PSK, WPA2-PSK and WPA3-SAE networks are supported.",
                other.label()
            );
            return ExitCode::FAILURE;
        }
    }

    // The scan may have left the radio on another channel: retune and restart
    // the MAC before associating.
    if let Err(error) = chip.phy_set_channel(&eeprom, &mut state, target.channel) {
        eprintln!("could not set channel {}: {error}", target.channel);
        return ExitCode::FAILURE;
    }
    if let Err(error) = chip.mac_start() {
        eprintln!("mac start failed: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = chip.agc_reset(eeprom.lna_gain) {
        eprintln!("agc reset failed: {error}");
        return ExitCode::FAILURE;
    }

    println!(
        "Associating with \"{}\" ({}) on channel {}…",
        target.ssid,
        target
            .bssid
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        target.channel
    );

    let outcome = match security {
        Security::Wpa2 => {
            let passphrase = passphrase.unwrap_or_default();
            let snonce = match station::random_bytes::<32>() {
                Ok(nonce) => nonce,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            station::associate_wpa2(&chip, &eeprom, &target, passphrase.as_bytes(), snonce)
        }
        Security::Wpa => {
            let passphrase = passphrase.unwrap_or_default();
            let snonce = match station::random_bytes::<32>() {
                Ok(nonce) => nonce,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            station::associate_wpa1(&chip, &eeprom, &target, passphrase.as_bytes(), snonce)
        }
        Security::Wpa3 => {
            let passphrase = passphrase.unwrap_or_default();
            let mut nonces = [[0u8; 32]; 3];
            for nonce in &mut nonces {
                *nonce = match station::random_bytes::<32>() {
                    Ok(drawn) => drawn,
                    Err(error) => {
                        eprintln!("{error}");
                        return ExitCode::FAILURE;
                    }
                };
            }
            let [snonce, rand, mask] = nonces;
            station::associate_sae(
                &chip,
                &eeprom,
                &target,
                passphrase.as_bytes(),
                snonce,
                rand,
                mask,
            )
        }
        _ => station::associate(&chip, &eeprom, &target),
    };

    match outcome {
        Ok(association) => {
            println!("\nAssociated (AID {}).", association.aid);
            if matches!(security, Security::Wpa | Security::Wpa2 | Security::Wpa3) {
                println!(
                    "{} keys installed; the hardware will encrypt data frames.",
                    security.label()
                );
            }
            println!("Start the tunnel from the GUI (with sudo) to carry IP traffic.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_usb_error("association failed", &error);
            ExitCode::FAILURE
        }
    }
}

/// Print a USB error, plus a recovery hint when the MCU channel is stuck.
fn print_usb_error(prefix: &str, error: &UsbError) {
    eprintln!("{prefix}: {error}");
    if let Some(hint) = scan::mcu_recovery_hint(error) {
        eprintln!("  hint: {hint}");
    }
}

/// Parse a `aa:bb:cc:dd:ee:ff` MAC address.
fn parse_mac(text: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("not a MAC address: {text}"));
    }
    let mut bytes = [0u8; 6];
    for (byte, part) in bytes.iter_mut().zip(parts) {
        *byte = u8::from_str_radix(part, 16).map_err(|_| format!("not a MAC address: {text}"))?;
    }
    Ok(bytes)
}

/// Bring the device up through the MAC/BBP register-initialization stage.
fn hw_init(firmware_path: Option<&str>) -> ExitCode {
    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    println!("Enabling the WLAN clock (chip_onoff)…");
    if let Err(error) = chip.chip_onoff(true, false) {
        eprintln!("chip_onoff failed: {error}");
        return ExitCode::FAILURE;
    }

    match chip.firmware_running() {
        Ok(true) => println!("Firmware already running."),
        Ok(false) => {
            let Some(path) = firmware_path else {
                eprintln!(
                    "firmware is not running; supply an image: mt7601u-macos --hw-init <path-to-mt7601u.bin>"
                );
                return ExitCode::FAILURE;
            };
            let data = match std::fs::read(path) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("cannot read {path}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            println!("Uploading firmware…");
            if let Err(error) = chip.load_firmware(&data) {
                eprintln!("firmware upload failed: {error}");
                return ExitCode::FAILURE;
            }
            println!("Firmware uploaded and running.");
        }
        Err(error) => {
            eprintln!("could not read MCU state: {error}");
            return ExitCode::FAILURE;
        }
    }

    println!("Running post-firmware initialization…");
    if let Err(error) = chip.init_after_firmware() {
        eprintln!("post-firmware initialization failed: {error}");
        return ExitCode::FAILURE;
    }

    println!("Writing MAC/BBP initvals and WCID/key memory tables…");
    println!("(this issues many MCU register-pair commands)");
    match chip.init_radio_registers() {
        Ok(()) => {
            println!("\nRadio register initialization completed.");
            println!(
                "Note: eeprom_init, phy_init/RF calibration and the RF tables are not implemented yet,"
            );
            println!("so this is not a claim that the radio is operational.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("radio register initialization failed: {error}");
            ExitCode::FAILURE
        }
    }
}
fn init_chip(firmware_path: Option<&str>) -> ExitCode {
    let chip = match open_chip() {
        Ok(chip) => chip,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    match chip.firmware_running() {
        Ok(true) => println!("Firmware already running."),
        Ok(false) => {
            let Some(path) = firmware_path else {
                eprintln!(
                    "firmware is not running; supply an image: mt7601u-macos --init <path-to-mt7601u.bin>"
                );
                return ExitCode::FAILURE;
            };
            let data = match std::fs::read(path) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("cannot read {path}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            println!("Uploading firmware…");
            if let Err(error) = chip.load_firmware(&data) {
                eprintln!("firmware upload failed: {error}");
                return ExitCode::FAILURE;
            }
            println!("Firmware uploaded and running.");
        }
        Err(error) => {
            eprintln!("could not read MCU state: {error}");
            return ExitCode::FAILURE;
        }
    }

    println!("Running post-firmware initialization (DMA reset + USB DMA config)…");
    if let Err(error) = chip.init_after_firmware() {
        eprintln!("post-firmware initialization failed: {error}");
        return ExitCode::FAILURE;
    }

    println!("Sending MCU Q_SELECT command…");
    match chip.mcu_cmd_init() {
        Ok(()) => {
            println!("\nMCU command channel OK — Q_SELECT acknowledged.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("MCU command channel failed: {error}");
            ExitCode::FAILURE
        }
    }
}
