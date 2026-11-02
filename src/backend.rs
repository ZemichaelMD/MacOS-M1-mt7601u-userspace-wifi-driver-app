//! Backend worker: owns the USB transport and services GUI commands off the
//! UI thread, reporting state changes back over a channel.
//!
//! The worker also runs the automatic pipeline the picker depends on: watch for
//! a dongle, open it, scan once, and reconnect to the last network when it is in
//! range. Joining a network and bringing the tunnel up are one action, because
//! the GUI deliberately has no "start tunnel" step.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::commands::{Addressing, Command, Event, LinkDetails, Traffic};
use crate::credentials::{self, Credentials};
use crate::format::format_rate;
use crate::helper::{self, HelperClient, StartRequest};
use crate::logging::{trace_line, LogLevel, LogLine};
use crate::mt7601u::data::{StaLink, StaLinkInfo, RX_BUFFER_LEN};
use crate::mt7601u::scan::DEFAULT_DWELL;
use crate::mt7601u::tx::TX_STATUS_DRAIN_MAX;
use crate::mt7601u::{self, scan, station, Mt7601u};
use crate::net::{arp, arp::ArpCache, dhcp, ipv4};
use crate::paths;
use crate::tunnel::relay::MAX_BATCH;
use crate::tunnel::{self, TunnelLink, TunnelState, Utun};
use crate::usb::{enumerate, DeviceInfo, DeviceStatus, RusbTransport, RxPump, Transport, UsbError};
use crate::wifi::{self, Network, Security, WifiState};

/// Minimum interval between ARP requests for the same address.
const ARP_RETRY: Duration = Duration::from_secs(1);

/// How long the outbound (macOS → Wi-Fi) read may block waiting for a packet,
/// and the `utun`/helper socket read timeout. Small, so the receive direction
/// is never held up by an idle outbound read.
const POLL: Duration = Duration::from_millis(2);

/// Sleep between relay iterations. The relay blocks in the receive read when
/// idle, so this only has to keep the loop from spinning.
const RELAY_TICK: Duration = Duration::from_millis(1);

/// Consecutive send failures after which the rest of an outbound batch is
/// dropped instead of attempted.
///
/// While the device refuses frames (it is full, or its USB engine has
/// wedged), every further send burns a full `TX_TIMEOUT` (one second). A
/// batch of 256 of those would keep the relay from noticing the dead link for
/// minutes, so it gives up after a handful and lets the stall watchdog do its
/// job.
const MAX_SEND_FAILURES: u32 = 3;

/// How often throughput is computed and published to the UI.
const TRAFFIC_INTERVAL: Duration = Duration::from_millis(300);

/// How often a throughput summary is written to the log, so a stalling link can
/// be diagnosed from the numbers rather than guessed at.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(5);

/// Iterations between full `TunnelState` refreshes (the packet counts), i.e.
/// roughly every `4 * TRAFFIC_INTERVAL`.
const STATE_REPORT_EVERY: u32 = 4;

/// How long the relay must keep failing to transfer before the link is judged
/// dead and re-established. `stats.dropped` only rises on a real transfer
/// failure, so a steady climb means frames have stopped getting through even
/// though the association still looks healthy.
const STALL_RECOVER_AFTER: Duration = Duration::from_secs(10);

/// How many failed transfers (with no successful ones) must accumulate before
/// the link is judged dead, so a single transient USB hiccup on an idle link
/// does not trigger a reconnect.
const STALL_MIN_DROPS: u64 = 3;

/// How long downlink writes must keep failing without a single success before
/// the tunnel is judged jammed — the helper has stopped reading its socket.
/// The Wi-Fi link still looks perfect in this state, so only the tunnel is
/// rebuilt, keeping the association and the lease.
const DOWNLINK_STUCK_AFTER: Duration = Duration::from_secs(15);

/// A jam requires failures to still be happening: a burst followed by quiet
/// (the peer catching up) is not a jam, so the last failure must be recent.
const DOWNLINK_STUCK_ACTIVE: Duration = Duration::from_secs(3);

/// How many times to re-establish the link before asking for a replug.
const RECOVERY_ATTEMPTS: u32 = 3;

/// Tick while nothing is relaying: fast enough for the picker to feel alive,
/// slow enough to leave the USB bus alone.
const IDLE_TICK: Duration = Duration::from_millis(200);

/// Idle ticks between USB presence polls (2 s).
const DETECT_TICKS: u32 = 10;

/// How many consecutive MCU failures are recovered by reopening the device —
/// which runs the fresh init and re-uploads the firmware — before the user is
/// asked for a physical replug.
const MCU_RETRIES: u32 = 2;

/// Handle to the running backend worker.
pub struct Backend {
    commands: UnboundedSender<Command>,
    events: UnboundedReceiver<Event>,
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Backend {
    /// Spawn the worker thread and wire up the command/event channels.
    ///
    /// `ctx` is used to wake the GUI when an event is produced, so the UI
    /// never has to poll.
    pub fn spawn(ctx: egui::Context) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let running = Arc::new(AtomicBool::new(true));

        let worker = Worker {
            events: event_tx,
            ctx,
            chip: None,
            rx_pump: None,
            device: None,
            networks: Vec::new(),
            assoc: None,
            link: None,
            tunnel: None,
            stats: tunnel::relay::Stats::default(),
            report_ticks: 0,
            traffic_at: Instant::now(),
            last_to_link_bytes: 0,
            last_to_tun_bytes: 0,
            down_bps: 0.0,
            up_bps: 0.0,
            summary_at: Instant::now(),
            progress_at: Instant::now(),
            last_total_packets: 0,
            drops_at_progress: 0,
            downlink_failed_since: None,
            downlink_failed_last: Instant::now(),
            recovery_attempts: 0,
            credentials: Credentials::default(),
            credentials_path: paths::credentials_file(),
            auto_paused: false,
            auto_scanned: false,
            auto_reconnected: false,
            detect_ticks: 0,
            open_failures: 0,
            replug: None,
            mcu_retries: 0,
            device_problem: None,
            addressing: Addressing::default(),
            arp: ArpCache::default(),
            arp_pending: None,
        };

        let running_flag = Arc::clone(&running);
        let handle = std::thread::Builder::new()
            .name("mt7601u-backend".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        tracing::error!("failed to start backend runtime: {error}");
                        running_flag.store(false, Ordering::SeqCst);
                        return;
                    }
                };
                runtime.block_on(worker.run(command_rx));
                running_flag.store(false, Ordering::SeqCst);
            })
            .ok();

        Self {
            commands: command_tx,
            events: event_rx,
            running,
            handle,
        }
    }

    /// Queue a command for the worker.
    pub fn send(&self, command: Command) {
        if self.commands.send(command).is_err() {
            tracing::warn!("backend command channel is closed");
        }
    }

    /// Take the next pending event, if any.
    pub fn try_recv(&mut self) -> Option<Event> {
        self.events.try_recv().ok()
    }

    /// Take every pending event.
    pub fn drain(&mut self) -> Vec<Event> {
        std::iter::from_fn(|| self.try_recv()).collect()
    }

    /// Whether the worker thread is still alive.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The station addressing captured at association time, reused by the tunnel.
#[derive(Debug, Clone, Copy)]
struct AssocInfo {
    local_mac: [u8; 6],
    bssid: [u8; 6],
    qos: bool,
    /// True once WPA2 keys are installed (the hardware encrypts data frames).
    encrypted: bool,
    /// False when the AP never accepted our 4/4: the station is not registered
    /// with it, so no tunnel can carry traffic.
    handshake_confirmed: bool,
}

/// The single-threaded worker state machine.
struct Worker {
    events: UnboundedSender<Event>,
    ctx: egui::Context,
    chip: Option<Mt7601u<RusbTransport>>,
    /// The receive reader, while a link is relaying. It owns the bulk IN
    /// endpoint for the whole lifetime of the tunnel.
    rx_pump: Option<RxPump>,
    device: Option<DeviceInfo>,
    /// Access points from the most recent scan (used to resolve a connect).
    networks: Vec<Network>,
    assoc: Option<AssocInfo>,
    /// What the current link is doing, mirrored to the GUI.
    link: Option<LinkDetails>,
    tunnel: Option<Box<dyn TunnelLink>>,
    stats: tunnel::relay::Stats,
    /// Relay iterations since the last statistics event.
    report_ticks: u32,
    /// When throughput was last sampled, and the byte totals at that point.
    traffic_at: Instant,
    last_to_link_bytes: u64,
    last_to_tun_bytes: u64,
    /// Smoothed throughput, bytes per second, in each direction.
    down_bps: f64,
    up_bps: f64,
    /// When the last throughput summary line was logged.
    summary_at: Instant,
    /// When a packet last moved, and the totals/drops at that point. A link is
    /// judged dead when nothing has moved for `STALL_RECOVER_AFTER` *despite*
    /// transfer failures — an idle-but-healthy link advances neither counter.
    progress_at: Instant,
    last_total_packets: u64,
    drops_at_progress: u64,
    /// Set when a downlink write to the tunnel fails and cleared by the first
    /// success; a jam is these failures continuing without any success for
    /// `DOWNLINK_STUCK_AFTER`.
    downlink_failed_since: Option<Instant>,
    /// When the most recent downlink write failed.
    downlink_failed_last: Instant,
    /// Link re-establishments attempted since the last healthy join.
    recovery_attempts: u32,
    /// Saved passphrases and preferences.
    credentials: Credentials,
    credentials_path: PathBuf,
    /// Set when the user released the device, so the pipeline stays put.
    auto_paused: bool,
    /// True once the automatic scan has run for the current device session.
    auto_scanned: bool,
    /// True once the automatic reconnect has been attempted for this scan.
    auto_reconnected: bool,
    /// Idle ticks since the last USB presence poll.
    detect_ticks: u32,
    /// Consecutive failed automatic opens, so only the first one is logged.
    open_failures: u32,
    /// Set while the radio needs a physical replug, with the reason.
    replug: Option<String>,
    /// Consecutive MCU failures recovered by reopening, reset on a good scan.
    mcu_retries: u32,
    /// Set while the device cannot be opened, with the reason.
    device_problem: Option<String>,
    /// Address acquisition mode used when the associated link is tunneled.
    addressing: Addressing,
    /// Addresses resolved to MACs for the next hop (gateway/on-link peers).
    arp: ArpCache,
    /// The address whose ARP request is in flight, and when it went out.
    arp_pending: Option<(std::net::Ipv4Addr, Instant)>,
}

impl Worker {
    async fn run(mut self, mut commands: UnboundedReceiver<Command>) {
        self.log(LogLevel::Info, "Backend started");
        self.load_credentials();
        self.refresh_device();

        loop {
            // Service every queued command first so shutdown/stop is prompt.
            let mut shutdown = false;
            while let Ok(command) = commands.try_recv() {
                if matches!(command, Command::Shutdown) {
                    shutdown = true;
                    break;
                }
                self.handle(command);
            }
            if shutdown {
                break;
            }

            if self.tunnel.is_some() {
                self.relay_step();
            }
            self.auto_step();

            let tick = if self.tunnel.is_some() {
                RELAY_TICK
            } else {
                IDLE_TICK
            };
            tokio::select! {
                () = tokio::time::sleep(tick) => {}
                command = commands.recv() => match command {
                    Some(Command::Shutdown) | None => break,
                    Some(command) => self.handle(command),
                }
            }
        }

        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.stop();
        }
        self.log(LogLevel::Info, "Backend shutting down");
        // Dropping `self.chip` releases interfaces and closes the device.
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::RefreshDevice => self.refresh_device(),
            Command::OpenDevice => self.resume(),
            Command::CloseDevice => self.stop(),
            Command::Identify => self.identify(),
            Command::Scan => self.scan(),
            Command::Connect {
                ssid,
                password,
                remember,
            } => self.connect(&ssid, password.as_deref(), remember),
            Command::Disconnect => {
                self.disconnect();
                // A deliberate disconnect must not be undone by auto-reconnect.
                self.auto_reconnected = true;
            }
            Command::ForgetPassphrase { ssid } => self.forget_passphrase(&ssid),
            Command::SetAutoConnect(enabled) => self.set_auto_connect(enabled),
            Command::SetAddressing(addressing) => self.set_addressing(addressing),
            Command::Shutdown => {}
        }
    }

    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
        self.ctx.request_repaint();
    }

    fn log(&self, level: LogLevel, message: impl Into<String>) {
        let line = LogLine::new(level, message);
        trace_line(&line);
        let _ = self.events.send(Event::Log(line));
        self.ctx.request_repaint();
    }

    // ------------------------------------------------------ automatic pipeline

    /// Advance the automatic bring-up: watch, open, scan, reconnect once.
    fn auto_step(&mut self) {
        if self.auto_paused {
            return;
        }

        if self.chip.is_none() {
            self.detect_ticks += 1;
            if self.detect_ticks >= DETECT_TICKS {
                self.detect_ticks = 0;
                self.refresh_device();
            }
            if self.device.is_some() {
                self.open_device();
            }
            return;
        }

        // The MCU is wedged: hold still and wait for the physical replug the
        // UI is asking for, rather than hammering a device that cannot answer.
        if self.replug.is_some() {
            self.detect_ticks += 1;
            if self.detect_ticks >= DETECT_TICKS {
                self.detect_ticks = 0;
                self.watch_for_unplug();
            }
            return;
        }

        if !self.auto_scanned {
            // Set before scanning so a failure cannot loop.
            self.auto_scanned = true;
            self.scan();
            return;
        }

        if self.auto_reconnected || self.assoc.is_some() {
            return;
        }
        self.auto_reconnected = true;
        self.auto_reconnect();
    }

    /// Reconnect to the last network we used, if it is in range and we can.
    fn auto_reconnect(&mut self) {
        if !self.credentials.auto_connect {
            return;
        }
        let Some(ssid) = self.credentials.last_ssid.clone() else {
            return;
        };
        self.reconnect_to(ssid);
    }

    /// Rejoin `ssid` if it came back in the scan results and we can join it.
    ///
    /// Shared by automatic reconnect and the reconnect that follows a manual
    /// scan which had to drop a live link.
    fn reconnect_to(&mut self, ssid: String) {
        let Some(network) = self.network(&ssid) else {
            self.log(
                LogLevel::Info,
                format!("\"{ssid}\" is not in range; pick a network to connect"),
            );
            return;
        };
        if !matches!(
            network.security,
            Security::Open | Security::Wpa | Security::Wpa2 | Security::Wpa3
        ) {
            return;
        }
        if matches!(
            network.security,
            Security::Wpa | Security::Wpa2 | Security::Wpa3
        ) && !self.credentials.has_passphrase(&ssid)
        {
            self.log(
                LogLevel::Info,
                format!("\"{ssid}\" needs a passphrase; pick it from the list"),
            );
            return;
        }
        self.log(LogLevel::Info, format!("Reconnecting to \"{ssid}\"…"));
        self.connect(&ssid, None, true);
    }

    /// Notice the dongle being pulled out while we still hold a dead handle.
    fn watch_for_unplug(&mut self) {
        if !matches!(enumerate::mt7601u_attached(), Ok(false)) {
            return;
        }
        self.log(
            LogLevel::Info,
            "MT7601U unplugged; waiting for it to be plugged back in",
        );
        self.release_device();
        self.set_replug(Some(
            "Plug the dongle back in and the app will reconnect on its own.".to_string(),
        ));
    }

    // ----------------------------------------------------------- device layer

    /// The network with this SSID from the last scan.
    fn network(&self, ssid: &str) -> Option<Network> {
        self.networks
            .iter()
            .find(|network| network.ssid == ssid)
            .cloned()
    }

    fn refresh_device(&mut self) {
        match enumerate::find_mt7601u() {
            Ok(Some(info)) => {
                // Announce the dongle only when its presence actually changed,
                // so the 2 s poll does not repeat itself.
                let changed = self
                    .device
                    .as_ref()
                    .is_none_or(|known| known.bus != info.bus || known.address != info.address);
                if changed {
                    self.log(
                        LogLevel::Info,
                        format!(
                            "Found {} (VID:PID {:04x}:{:04x}) at bus {} address {}",
                            mt7601u::PRODUCT_NAME,
                            info.vid,
                            info.pid,
                            info.bus,
                            info.address
                        ),
                    );
                    self.device = Some(info.clone());
                    self.emit(Event::Device(DeviceStatus::Present(info)));
                }
            }
            Ok(None) => {
                if self.device.is_some() {
                    self.log(
                        LogLevel::Info,
                        format!("{} not detected", mt7601u::PRODUCT_NAME),
                    );
                }
                self.device = None;
                self.emit(Event::Device(DeviceStatus::Absent));
            }
            Err(error) => {
                self.log(LogLevel::Error, format!("USB enumeration failed: {error}"));
                self.emit(Event::Device(DeviceStatus::Error(error.to_string())));
            }
        }
    }

    /// Open the device and claim its interface, then let the pipeline scan.
    ///
    /// A failure is reported once and then retried quietly: the usual cause is
    /// another process holding the interface, which clears on its own.
    fn open_device(&mut self) -> bool {
        if self.chip.is_some() {
            return true;
        }
        let Some(info) = self.device.clone() else {
            return false;
        };

        match RusbTransport::open(&info) {
            Ok(mut transport) => match transport.claim_interface(mt7601u::DEFAULT_INTERFACE) {
                Ok(()) => {
                    self.log(
                        LogLevel::Info,
                        format!(
                            "Opened {}; claimed interface {}",
                            mt7601u::PRODUCT_NAME,
                            mt7601u::DEFAULT_INTERFACE
                        ),
                    );
                    self.chip = Some(Mt7601u::new(transport, info.clone()));
                    self.auto_scanned = false;
                    self.auto_reconnected = false;
                    self.open_failures = 0;
                    // The dongle is back, so the replug request is satisfied.
                    self.set_replug(None);
                    self.set_device_problem(None);
                    self.emit(Event::Device(DeviceStatus::Open(info)));
                    true
                }
                Err(error) => {
                    self.report_open_failure(&format!(
                        "Could not claim interface {}: {error}",
                        mt7601u::DEFAULT_INTERFACE
                    ));
                    false
                }
            },
            Err(error) => {
                self.report_open_failure(&format!("Could not open device: {error}"));
                false
            }
        }
    }

    fn report_open_failure(&mut self, message: &str) {
        self.open_failures += 1;
        if self.open_failures == 1 {
            self.log(LogLevel::Error, message);
        } else {
            self.log(LogLevel::Debug, message);
        }
        self.set_device_problem(Some(format!(
            "{message}. Another program is probably holding the MT7601U, and only one can. \
             Quit it (or press Stop in it) and this will take over on its own."
        )));
    }

    /// Publish (or clear) the reason the device cannot be opened.
    fn set_device_problem(&mut self, problem: Option<String>) {
        if self.device_problem == problem {
            return;
        }
        self.device_problem = problem.clone();
        self.emit(Event::DeviceProblem(problem));
    }

    /// Stop: release the device and hold the automatic pipeline.
    fn stop(&mut self) {
        self.auto_paused = true;
        self.emit(Event::Paused(true));
        if self.chip.is_none() {
            self.log(LogLevel::Warn, "The device is already stopped");
            return;
        }
        // Quiesce the radio before the handle is closed. A MAC still running
        // while the host drops the USB pipes is what leaves the chip unable to
        // answer MCU commands the next time it is opened, so a dongle is put
        // down the same way a driver puts one down before unbinding.
        if let Some(chip) = self.chip.as_ref() {
            chip.mac_stop();
        }
        self.release_device();
        self.log(
            LogLevel::Info,
            "Stopped: released the device and its interface",
        );
    }

    /// Start again after a stop.
    fn resume(&mut self) {
        self.auto_paused = false;
        self.emit(Event::Paused(false));
        self.set_device_problem(None);
        // An explicit Start means "try again now", and `bringup` re-arms the
        // device on reopen, so drop a replug hint left by an earlier failure.
        // Otherwise the pipeline would hold still waiting for a physical replug
        // the user is not going to give it.
        self.set_replug(None);
        self.log(LogLevel::Info, "Starting again");
        self.refresh_device();
    }

    /// Release the device and everything on it, without touching the pause.
    fn release_device(&mut self) {
        self.drop_link();
        // Dropping the chip releases the interface and closes the handle.
        self.chip = None;
        self.networks.clear();
        self.auto_scanned = false;
        self.auto_reconnected = false;
        self.emit(Event::ScanResults(Vec::new()));
        self.emit(Event::Wifi(WifiState::Idle));
        // The handle is closed but the dongle is still plugged in: report it as
        // detected-but-closed so the UI stops showing it as open (the power
        // switch would otherwise stay on and Stop would report "already
        // stopped").
        if let Some(info) = self.device.clone() {
            self.emit(Event::Device(DeviceStatus::Present(info)));
        }
    }

    fn identify(&mut self) {
        if self.chip.is_none() {
            self.log(LogLevel::Warn, "The device is not open");
            return;
        }
        let result = self.chip.as_ref().map(|chip| chip.identify());
        match result {
            Some(Ok(ident)) => self.log(
                LogLevel::Info,
                format!(
                    "ASIC version 0x{:08x} ({}), MAC CSR0 0x{:08x}, eFuse {}",
                    ident.asic_version,
                    if ident.is_mt7601() {
                        "MT7601"
                    } else {
                        "unexpected id"
                    },
                    ident.mac_csr0,
                    if ident.efuse_present() {
                        "present"
                    } else {
                        "absent"
                    }
                ),
            ),
            Some(Err(error)) => self.log(LogLevel::Error, format!("Identify failed: {error}")),
            None => {}
        }
    }

    /// Bring the radio up and run a passive scan on the open device.
    ///
    /// A scan retunes the radio and restarts the MAC, so it cannot run on top of
    /// a live link. Rather than refuse while connected, tear the link and tunnel
    /// down (releasing the device so the reopen gives a fresh bring-up), scan,
    /// and rejoin the same network from the fresh results.
    fn scan(&mut self) {
        let mut reconnect_to = None;
        if self.assoc.is_some() || self.tunnel.is_some() {
            reconnect_to = self.credentials.last_ssid.clone();
            self.log(
                LogLevel::Info,
                "Disconnecting to scan; reconnecting when it finishes…",
            );
            self.drop_link();
            if let Some(chip) = self.chip.as_ref() {
                chip.mac_stop();
            }
            self.release_device();
        }
        if self.chip.is_none() {
            // A scan right after a disconnect finds the device released. Reopen
            // it here rather than making the user press Start (or replug): the
            // reopen runs the full bring-up, which is the recovery that works.
            // A deliberate Stop (auto_paused) is respected and not undone.
            if self.auto_paused || !self.open_device() {
                self.log(LogLevel::Warn, "The device is not open");
                return;
            }
        }

        self.log(LogLevel::Info, "Scanning for networks…");
        self.emit(Event::Wifi(WifiState::Scanning));

        let firmware = paths::find_firmware();
        if firmware.is_none() {
            self.log(
                LogLevel::Warn,
                "Firmware not found; set MT7601U_FIRMWARE or place mt7601u.bin next to the app",
            );
        }

        let result = self
            .chip
            .as_ref()
            .map(|chip| scan::bringup_and_scan(chip, firmware.as_deref(), DEFAULT_DWELL));

        match result {
            Some(Ok(networks)) => {
                // `scan` already logs the count when it finishes.
                self.networks = networks.clone();
                self.mcu_retries = 0;
                self.set_replug(None);
                self.emit(Event::ScanResults(networks));
                // A scan that dropped a live link rejoins the same network now
                // that the fresh results are in.
                if let Some(ssid) = reconnect_to {
                    self.reconnect_to(ssid);
                }
            }
            Some(Err(error)) => {
                self.log(LogLevel::Error, format!("Scan failed: {error}"));

                // A radio that stops answering MCU commands is usually
                // recoverable without a replug: a wedged MCU reads as "firmware
                // not running", so releasing and reopening runs the fresh init,
                // which re-uploads the firmware and re-arms everything. Do that
                // before asking the user for a physical replug — and if another
                // program really does hold the device, that reopen is what turns
                // the failure into the ("cannot open") message that says so.
                if self.should_retry_mcu(&error) {
                    self.mcu_retries += 1;
                    self.log(
                        LogLevel::Info,
                        format!(
                            "Restarting the device to recover (attempt {} of {})",
                            self.mcu_retries, MCU_RETRIES
                        ),
                    );
                    self.release_device();
                    return;
                }

                self.report_mcu_hint(&error);
                self.emit(Event::Wifi(WifiState::Error(error.to_string())));
            }
            None => {}
        }
    }

    // ------------------------------------------------------------ credentials

    fn load_credentials(&mut self) {
        match Credentials::load(&self.credentials_path) {
            Ok(credentials) => {
                let count = credentials.known_ssids().len();
                if count > 0 {
                    self.log(LogLevel::Info, format!("Loaded {count} saved network(s)"));
                }
                self.credentials = credentials;
            }
            Err(error) => self.log(
                LogLevel::Warn,
                format!("Could not read saved networks: {error}"),
            ),
        }
        if !credentials::is_private(&self.credentials_path) {
            self.log(
                LogLevel::Warn,
                format!(
                    "{} is readable by other users; saved passphrases should be private",
                    self.credentials_path.display()
                ),
            );
        }
        self.emit(Event::SavedNetworks(self.credentials.known_ssids()));
        self.emit(Event::AutoConnect(self.credentials.auto_connect));
    }

    fn save_credentials(&mut self) {
        if let Err(error) = self.credentials.save(&self.credentials_path) {
            self.log(LogLevel::Warn, format!("Could not save networks: {error}"));
        }
        self.emit(Event::SavedNetworks(self.credentials.known_ssids()));
        self.emit(Event::AutoConnect(self.credentials.auto_connect));
    }

    /// Store a passphrase so this network connects with one click next time.
    /// The passphrase itself is never logged.
    fn remember_passphrase(&mut self, ssid: &str, passphrase: &str) {
        if passphrase.is_empty() || self.credentials.passphrase(ssid) == Some(passphrase) {
            return;
        }
        self.credentials.remember(ssid, passphrase);
        self.save_credentials();
        self.log(
            LogLevel::Info,
            format!(
                "Saved the passphrase for \"{ssid}\" in {}",
                self.credentials_path.display()
            ),
        );
    }

    fn forget_passphrase(&mut self, ssid: &str) {
        if self.credentials.forget(ssid) {
            self.save_credentials();
            self.log(
                LogLevel::Info,
                format!("Forgot the saved passphrase for \"{ssid}\""),
            );
        }
    }

    fn set_auto_connect(&mut self, enabled: bool) {
        if self.credentials.auto_connect == enabled {
            return;
        }
        self.credentials.auto_connect = enabled;
        self.save_credentials();
        self.log(
            LogLevel::Info,
            if enabled {
                "Reconnect to the last network automatically"
            } else {
                "Reconnect automatically turned off"
            },
        );
    }

    /// Set the addressing policy, and re-apply it when a link is already up.
    ///
    /// Without the re-apply, choosing a new address (or trying again after a
    /// failed DHCP) would do nothing until the user disconnected and
    /// reconnected — which is exactly the "cannot retry" dead end.
    fn set_addressing(&mut self, addressing: Addressing) {
        let changed = self.addressing != addressing;
        self.addressing = addressing.clone();
        if changed {
            self.save_credentials();
            self.emit(Event::Addressing(addressing));
        }
        if self.assoc.is_none() {
            return;
        }
        self.log(
            LogLevel::Info,
            format!(
                "Re-configuring the tunnel ({} addressing)",
                self.addressing.label()
            ),
        );
        self.tunnel_stop();
        self.tunnel_start();
    }

    // ------------------------------------------------------------- join a link

    /// Join `ssid`, save the passphrase and bring the tunnel up.
    ///
    /// This is the whole user action in the picker. `supplied` is the passphrase
    /// the user typed, or `None` to use the saved one.
    fn connect(&mut self, ssid: &str, supplied: Option<&str>, remember: bool) {
        let Some(network) = self.network(ssid) else {
            self.fail_wifi(&format!(
                "\"{ssid}\" is not in the last scan results; scan again"
            ));
            return;
        };

        let security = network.security.clone();
        if !matches!(
            security,
            Security::Open | Security::Wpa | Security::Wpa2 | Security::Wpa3
        ) {
            self.fail_wifi(&format!(
                "\"{ssid}\" is {}; only open, WPA-PSK, WPA2-PSK and WPA3-SAE networks are supported",
                security.label()
            ));
            return;
        }

        let using_saved = supplied.is_none();
        let passphrase = match security {
            Security::Open => String::new(),
            _ => match supplied {
                Some(passphrase) if !passphrase.is_empty() => passphrase.to_string(),
                _ => match self.credentials.passphrase(ssid) {
                    Some(saved) => saved.to_string(),
                    None => {
                        self.fail_wifi(&format!(
                            "\"{ssid}\" is {}; enter the passphrase",
                            security.label()
                        ));
                        return;
                    }
                },
            },
        };

        if self.chip.is_none() {
            self.fail_wifi("The device is not open yet");
            return;
        }

        // Clicking another network in the picker switches to it.
        if self.assoc.is_some() {
            if self.link.as_ref().is_some_and(|link| link.ssid == ssid) {
                return;
            }
            self.drop_link();
        }

        let (Some(bssid), Some(channel)) = (network.bssid, network.channel) else {
            self.fail_wifi(&format!(
                "\"{ssid}\" has no BSSID/channel in the scan results"
            ));
            return;
        };

        self.log(
            LogLevel::Info,
            format!("Connecting to \"{ssid}\" ({})…", security.label()),
        );
        self.emit(Event::Wifi(WifiState::Connecting {
            ssid: ssid.to_string(),
        }));

        let firmware = paths::find_firmware();
        let result = self.chip.as_ref().map(|chip| {
            let (eeprom, mut state) = scan::bringup(chip, firmware.as_deref())?;
            chip.phy_set_channel(&eeprom, &mut state, channel)?;
            chip.mac_start()?;
            chip.agc_reset(eeprom.lna_gain)?;
            let target = station::BssTarget::infrastructure(
                ssid.to_string(),
                bssid,
                channel,
                station::CAPABILITY_ESS,
            );
            let (association, encrypted) = match security {
                Security::Wpa2 => {
                    let snonce = station::random_bytes::<32>()?;
                    let association = station::associate_wpa2(
                        chip,
                        &eeprom,
                        &target,
                        passphrase.as_bytes(),
                        snonce,
                    )?;
                    (association, true)
                }
                Security::Wpa => {
                    let snonce = station::random_bytes::<32>()?;
                    let association = station::associate_wpa1(
                        chip,
                        &eeprom,
                        &target,
                        passphrase.as_bytes(),
                        snonce,
                    )?;
                    (association, true)
                }
                Security::Wpa3 => {
                    let snonce = station::random_bytes::<32>()?;
                    let rand = station::random_bytes::<32>()?;
                    let mask = station::random_bytes::<32>()?;
                    let association = station::associate_sae(
                        chip,
                        &eeprom,
                        &target,
                        passphrase.as_bytes(),
                        snonce,
                        rand,
                        mask,
                    )?;
                    (association, true)
                }
                _ => (station::associate(chip, &eeprom, &target)?, false),
            };
            Ok::<_, UsbError>((eeprom, association, encrypted))
        });

        let Some(result) = result else {
            return;
        };

        match result {
            Ok((eeprom, association, encrypted)) => {
                self.assoc = Some(AssocInfo {
                    local_mac: eeprom.mac_addr,
                    bssid,
                    qos: false,
                    encrypted,
                    handshake_confirmed: association.handshake_confirmed,
                });
                if association.handshake_confirmed {
                    self.log(
                        LogLevel::Info,
                        format!("Connected to \"{ssid}\" (AID {}).", association.aid),
                    );
                } else {
                    // The AP kept retransmitting 3/4: it never accepted our 4/4,
                    // so the station is not registered with it. Say so rather
                    // than letting the UI claim a working connection.
                    self.log(
                        LogLevel::Error,
                        format!(
                            "Joined \"{ssid}\" (AID {}) but the AP never accepted our WPA2 key \
                             reply — it is still retransmitting message 3/4. This device is NOT \
                             registered with the AP, will not appear in its client list, and \
                             nothing is bridged for it.",
                            association.aid
                        ),
                    );
                }
                if encrypted {
                    self.log(
                        LogLevel::Info,
                        "WPA2 keys installed; the hardware now encrypts/decrypts data frames.",
                    );
                    if remember {
                        self.remember_passphrase(ssid, &passphrase);
                    } else {
                        self.forget_passphrase(ssid);
                    }
                }
                self.credentials.mark_connected(ssid);
                self.save_credentials();

                // A fresh association starts with a clean recovery budget.
                self.recovery_attempts = 0;
                self.link = Some(LinkDetails::associated(&network));
                // Only report "Connected" when the AP actually confirmed the
                // handshake; otherwise the status must show the failure.
                if association.handshake_confirmed {
                    self.emit(Event::Wifi(WifiState::Connected {
                        ssid: ssid.to_string(),
                    }));
                } else {
                    self.emit(Event::Wifi(WifiState::Error(format!(
                        "the AP did not accept the WPA2 key exchange for \"{ssid}\"; this device \
                         is not registered with it"
                    ))));
                }
                self.emit(Event::Link(self.link.clone()));

                // One click joins and tunnels: no separate step for the user.
                self.tunnel_start();
            }
            Err(error) => {
                self.log(LogLevel::Error, format!("Could not connect: {error}"));
                if using_saved {
                    self.log(
                        LogLevel::Warn,
                        format!(
                            "The saved passphrase for \"{ssid}\" may be wrong; \
                             forget it and enter it again"
                        ),
                    );
                }
                self.report_mcu_hint(&error);
                self.emit(Event::Wifi(WifiState::Error(error.to_string())));
            }
        }
    }

    /// Leave the network, tear the tunnel down, and release the device.
    ///
    /// Releasing here — rather than leaving a half-torn-down radio behind — is
    /// what makes a rescan work without a physical replug. After a connection
    /// the MAC is still running when the host cancels its receive transfers,
    /// which is exactly the state that wedges the MCU command channel; the only
    /// cure is a fresh bring-up, and a released-then-reopened device gets one.
    /// The automatic pipeline reopens and rescans on its own, so the picker
    /// repopulates by itself.
    fn disconnect(&mut self) {
        if self.assoc.is_none() && self.tunnel.is_none() {
            self.log(LogLevel::Warn, "Not connected");
            return;
        }
        self.drop_link();
        // The same courtesy `stop` extends: quiesce the MAC before the handle
        // drops, so a MAC is never left running with no host-side receive path.
        if let Some(chip) = self.chip.as_ref() {
            chip.mac_stop();
        }
        self.release_device();
        self.log(
            LogLevel::Info,
            "Disconnected; released the device so the next scan can reopen it cleanly \
             (no replug needed)",
        );
    }

    /// Drop the link without logging anything.
    fn drop_link(&mut self) {
        // Stop the receive reader first: its transfer must not be left in
        // flight while the link is torn down (dropping the pump joins it).
        self.rx_pump = None;
        self.tunnel_stop();
        // The next-hop resolution belongs to the link that is going away.
        self.arp.clear();
        self.arp_pending = None;
        if self.assoc.take().is_some() || self.link.take().is_some() {
            self.emit(Event::Wifi(WifiState::Idle));
            self.emit(Event::Link(None));
        }
    }

    /// Report a failure that belongs to the Wi-Fi plane.
    fn fail_wifi(&mut self, message: &str) {
        self.log(LogLevel::Error, message);
        self.emit(Event::Wifi(WifiState::Error(message.to_string())));
    }

    /// Whether an MCU failure should be recovered by reopening the device
    /// rather than reported to the user straight away.
    fn should_retry_mcu(&self, error: &UsbError) -> bool {
        scan::mcu_recovery_hint(error).is_some() && self.mcu_retries < MCU_RETRIES
    }

    /// Turn a wedged MCU into an instruction the user can act on.
    fn report_mcu_hint(&mut self, error: &UsbError) {
        if let Some(hint) = scan::mcu_recovery_hint(error) {
            self.log(LogLevel::Warn, hint);
            self.set_replug(Some(hint.to_string()));
        }
    }

    fn set_replug(&mut self, hint: Option<String>) {
        if self.replug == hint {
            return;
        }
        self.replug = hint.clone();
        self.detect_ticks = 0;
        self.emit(Event::Replug(hint));
    }

    // ---------------------------------------------------------------- tunnel

    /// Obtain an address over the link, bring the interface up and relay.
    ///
    /// The interface is created in-process when this is root, otherwise the
    /// privileged helper daemon is asked to create and configure it. Either way
    /// DHCP runs over the Wi-Fi link in this process, because the helper cannot
    /// touch the USB device.
    fn tunnel_start(&mut self) {
        if self.tunnel.is_some() {
            return;
        }
        let Some(assoc) = self.assoc else {
            self.emit(Event::Tunnel(TunnelState::Error(
                "Not connected".to_string(),
            )));
            return;
        };

        // The AP never accepted our half of the handshake, so it has not
        // registered this station: it appears in neither the AP's client list
        // nor its bridge, and every frame we send is discarded. Starting a
        // tunnel here would only produce "sent N, received 0", so say what is
        // actually wrong instead.
        if !assoc.handshake_confirmed {
            let message = "The AP is still retransmitting the WPA2 handshake (message 3/4): \
                           it never accepted our reply, so this device is not registered with \
                           it and cannot reach anything. Nothing was started."
                .to_string();
            self.log(LogLevel::Error, message.clone());
            self.emit(Event::Tunnel(TunnelState::Error(message)));
            return;
        }

        self.emit(Event::Tunnel(TunnelState::Starting));

        // 1. Obtain an address from the AP's DHCP server over the Wi-Fi link.
        //    This needs no privilege — it is just IP packets on the link.
        let lease = match self.addressing.clone() {
            Addressing::Manual {
                address,
                gateway,
                dns,
            } => dhcp::Lease {
                address,
                subnet_mask: std::net::Ipv4Addr::new(255, 255, 255, 0),
                router: gateway,
                dns,
                server: gateway,
                lease_secs: 0,
            },
            Addressing::Dhcp => {
                let mut info = StaLinkInfo::new(assoc.local_mac, assoc.bssid, assoc.qos);
                if assoc.encrypted {
                    // After the WPA2 handshake the AP only sends encrypted frames,
                    // so the DHCP exchange must accept hardware-decrypted ones.
                    info = info.encrypted();
                }
                let Some(chip) = self.chip.as_ref() else {
                    self.log(
                        LogLevel::Error,
                        "The device was released during tunnel setup",
                    );
                    return;
                };
                let link = StaLink::new(chip, info);
                let xid = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0x5eed);
                // Record every data frame the exchange sees, from this same
                // receive loop: a reply the client rejects is gone by the time a
                // later diagnostic pass could look for it.
                chip.start_frame_trace();
                let exchanged = dhcp::obtain(&link, &assoc.local_mac, xid);
                chip.stop_frame_trace();
                match exchanged {
                    Ok(lease) => lease,
                    Err(error) => {
                        let message = format!("Could not get an address (DHCP): {error}");
                        self.log(LogLevel::Error, message.clone());
                        self.log_rx_diagnostics(chip);
                        self.emit(Event::Tunnel(TunnelState::Error(message)));
                        return;
                    }
                }
            }
        };
        self.log(
            LogLevel::Info,
            format!(
                "Address {} from the network (router {}, dns {:?})",
                lease.address,
                lease.router,
                lease
                    .dns
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
            ),
        );
        if let Some(link) = self.link.as_mut() {
            link.ip = Some(lease.address);
            link.subnet_mask = Some(lease.subnet_mask);
            link.router = Some(lease.router);
            link.dns = lease.dns.clone();
        }
        // A new lease invalidates every resolved next hop.
        self.arp.clear();
        self.arp_pending = None;
        self.emit(Event::Link(self.link.clone()));

        // 2. Bring the interface up: directly as root, or via the helper.
        let tunnel: Box<dyn TunnelLink> = if tunnel::is_root() {
            match local_tunnel(&lease) {
                Ok(tunnel) => tunnel,
                Err(message) => {
                    self.log(LogLevel::Error, message.clone());
                    self.emit(Event::Tunnel(TunnelState::Error(message)));
                    return;
                }
            }
        } else {
            match helper_tunnel(&lease) {
                Ok(tunnel) => tunnel,
                Err(message) => {
                    self.log(LogLevel::Error, message.clone());
                    self.emit(Event::Tunnel(TunnelState::Error(message)));
                    return;
                }
            }
        };

        let name = tunnel.name();
        self.log(LogLevel::Info, format!("Tunnel {name} is up"));
        if let Some(link) = self.link.as_mut() {
            link.interface = Some(name);
        }
        self.emit(Event::Link(self.link.clone()));

        self.stats = tunnel::relay::Stats::default();
        self.report_ticks = 0;
        self.traffic_at = Instant::now();
        self.last_to_link_bytes = 0;
        self.last_to_tun_bytes = 0;
        self.down_bps = 0.0;
        self.up_bps = 0.0;
        crate::menu_bar::set_rates(None);
        self.progress_at = Instant::now();
        self.last_total_packets = 0;
        self.drops_at_progress = 0;

        // Start the receive reader before the relay runs. From here on it
        // owns the bulk IN endpoint, keeping one transfer armed at all times;
        // `relay_step` collects its buffers instead of reading USB itself
        // (see `usb::rx_pump` for why a host must never leave this device's
        // receive path unarmed or cancel its transfers while a link is up).
        let mut pump_error = None;
        if let Some(chip) = self.chip.as_ref() {
            match chip.rx_endpoint() {
                Ok(endpoint) => {
                    let transport = chip.transport().clone();
                    self.rx_pump = Some(RxPump::start(transport, endpoint, RX_BUFFER_LEN));
                }
                Err(error) => pump_error = Some(error),
            }
        }
        if let Some(error) = pump_error {
            self.log(
                LogLevel::Error,
                format!("Could not start the receive reader: {error}"),
            );
        }

        self.tunnel = Some(tunnel);
        self.log(
            LogLevel::Info,
            "Traffic is now relaying. On macOS 15+ only apps that resolve their own DNS use \
             a virtual interface reliably without a signed system extension.",
        );
        self.emit(Event::Tunnel(TunnelState::Running {
            to_link_packets: 0,
            to_tun_packets: 0,
        }));
    }

    /// Stop relaying and tear the tunnel down (routes/DNS are rolled back).
    fn tunnel_stop(&mut self) {
        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.stop();
            self.log(LogLevel::Info, "Tunnel stopped; routes and DNS restored");
            self.emit(Event::Tunnel(TunnelState::Stopped));
            if let Some(link) = self.link.as_mut() {
                link.ip = None;
                link.router = None;
                link.dns.clear();
                link.interface = None;
            }
        }
    }

    /// After a failed DHCP exchange, report what the AP actually sent.
    ///
    /// These are the frames recorded by the DHCP client's own receive loop while
    /// it was waiting, so nothing the client consumed and rejected is missing.
    /// "The AP answered but we dropped the reply" shows up as a listed frame; an
    /// empty list means the AP sent nothing at all, which points at the uplink.
    fn log_rx_diagnostics(&self, chip: &Mt7601u<RusbTransport>) {
        let frames = chip.frame_trace();
        if frames.is_empty() {
            self.log(
                LogLevel::Warn,
                "No 802.11 data frame arrived during the whole DHCP exchange: the AP is not \
                 answering the DISCOVER, or its reply never reached the radio.",
            );
            return;
        }
        self.log(
            LogLevel::Info,
            format!("Frames seen during the DHCP exchange ({}):", frames.len()),
        );
        for frame in frames {
            self.log(LogLevel::Info, format!("  {}", frame.line()));
        }
    }

    /// One relay iteration: move packets in both directions.
    ///
    /// The relay is layer 3, but the air side is not: an outbound frame has to
    /// name a next-hop MAC, so the gateway (or an on-link peer) is resolved with
    /// ARP first, and ARP requests for our own address are answered so the
    /// gateway can deliver anything back to us.
    fn relay_step(&mut self) {
        let Some(assoc) = self.assoc else {
            return;
        };
        // A dead tunnel peer (the helper daemon stopped or was restarted, the
        // socket broke) cannot be revived by anything the Wi-Fi link does; the
        // stall watchdog would take ten seconds to notice, so rebuild the
        // tunnel now instead of relaying into the void.
        let tunnel_problem = self.tunnel.as_ref().and_then(|tunnel| tunnel.health());
        if let Some(problem) = tunnel_problem {
            self.log(
                LogLevel::Warn,
                format!("The tunnel connection failed ({problem}); restarting the tunnel"),
            );
            self.restart_tunnel();
            return;
        }
        // Set when an inbound ARP frame was received, so it can be logged once
        // the borrow of `self` below has ended.
        let mut arp_note: Option<String> = None;
        // Set when the receive reader has failed and the link needs rebuilding.
        let mut pump_failure: Option<String> = None;

        {
            let Self {
                chip,
                tunnel,
                stats,
                link: link_details,
                arp,
                arp_pending,
                rx_pump,
                downlink_failed_since,
                downlink_failed_last,
                ..
            } = self;
            let (Some(chip), Some(tunnel)) = (chip.as_ref(), tunnel.as_mut()) else {
                return;
            };
            let mut link_info = StaLinkInfo::new(assoc.local_mac, assoc.bssid, assoc.qos);
            if assoc.encrypted {
                link_info = link_info.encrypted();
            }

            // Drain the hardware's TX retirement FIFO. The MAC queues one entry
            // per transmitted frame and stops retiring frames once the FIFO is
            // full (about a thousand entries); the kernel driver reads it after
            // every completed transfer. Left unread, a loaded link transmits
            // for a short while and then goes dead until it is re-established.
            if let Ok(totals) = chip.drain_tx_status(TX_STATUS_DRAIN_MAX) {
                stats.tx_status_drained += u64::from(totals.drained);
                stats.tx_status_failed += u64::from(totals.failed);
            }

            // Our own address, the gateway and the mask, as configured.
            let configured = link_details.as_ref().and_then(|link| {
                Some((
                    link.ip?,
                    link.router?,
                    link.subnet_mask
                        .unwrap_or(std::net::Ipv4Addr::new(255, 255, 255, 0)),
                ))
            });
            let Some((our_ip, gateway, mask)) = configured else {
                return;
            };

            // Wi-Fi → macOS: take everything the receive reader has collected.
            // The reader owns the bulk IN endpoint (see `usb::rx_pump`), so
            // this loop never touches USB — it cannot stall the device by
            // leaving the receive path unarmed while a transmit batch runs,
            // and the short read timeout that cancelled transfers many times
            // a second is gone with it.
            //
            // Counts tunnel write failures so at most the first one per
            // iteration is logged: a dying helper would otherwise repeat the
            // same line for every frame of the batch.
            let mut write_failures = 0u32;
            if let Some(pump) = rx_pump.as_ref() {
                if let Some(failure) = pump.take_failure() {
                    pump_failure = Some(failure);
                }
                let mut payloads = 0usize;
                'buffers: for buffer in pump.drain(MAX_BATCH) {
                    for frame in chip.parse_rx_buffer(&buffer, &link_info) {
                        payloads += 1;
                        match frame.ethertype {
                            arp::ETHERTYPE_ARP => {
                                arp_note =
                                    answer_arp(chip, &link_info, &frame.payload, our_ip, arp);
                            }
                            wifi::data::ETHERTYPE_IPV4 => match tunnel.write_packet(&frame.payload)
                            {
                                Ok(()) => {
                                    stats.to_tun_packets += 1;
                                    stats.to_tun_bytes += frame.payload.len() as u64;
                                    *downlink_failed_since = None;
                                }
                                Err(error) => {
                                    stats.dropped += 1;
                                    write_failures += 1;
                                    let now = Instant::now();
                                    if downlink_failed_since.is_none() {
                                        *downlink_failed_since = Some(now);
                                    }
                                    *downlink_failed_last = now;
                                    if write_failures == 1 {
                                        tracing::info!("relay tun write failed: {error}");
                                    }
                                }
                            },
                            _ => {}
                        }
                        if payloads >= MAX_BATCH {
                            break 'buffers;
                        }
                    }
                }
            }

            // Give the tunnel a chance to push out any packet it still holds
            // (accepted without room on the socket). With the downlink quiet
            // this is the only path that drains that backlog, and a queue
            // that stays full would drop every later packet until the tunnel
            // was rebuilt.
            tunnel.flush();

            // macOS → Wi-Fi: move a whole batch of small outbound packets, not
            // one per round trip. When the device stops accepting frames the
            // rest of the batch is dropped rather than attempted: each further
            // send would burn a full timeout and a batch of them would keep
            // the relay from noticing the dead link for minutes.
            let packets = tunnel.read_batch(POLL, MAX_BATCH);
            let queued = packets.len();
            let mut failures = 0u32;
            for (index, packet) in packets.iter().enumerate() {
                match send_ipv4(
                    chip,
                    &link_info,
                    packet,
                    our_ip,
                    mask,
                    gateway,
                    arp,
                    arp_pending,
                ) {
                    Ok(()) => {
                        stats.to_link_packets += 1;
                        stats.to_link_bytes += packet.len() as u64;
                        failures = 0;
                    }
                    Err(_) => {
                        stats.dropped += 1;
                        failures += 1;
                        if failures >= MAX_SEND_FAILURES {
                            // Not attempted; count them so the totals balance.
                            stats.dropped += (queued - index - 1) as u64;
                            break;
                        }
                    }
                }
            }
        }

        if let Some(failure) = pump_failure {
            self.log(
                LogLevel::Error,
                format!("The receive path failed ({failure}); re-establishing the link"),
            );
            self.recover_link();
            return;
        }

        // An inbound ARP frame is the clearest sign the unicast receive path
        // works: until the next hop's reply arrives the relay has no MAC to
        // address outbound packets to, and drops every one of them.
        if let Some(note) = arp_note {
            self.log(
                LogLevel::Info,
                format!("{note}: inbound unicast receive is working"),
            );
        }

        // A tunnel that has refused every downlink write for a while without a
        // single success is jammed: its peer has stopped reading. Nothing on
        // the Wi-Fi side can unblock it — only a fresh session can — so rebuild
        // the tunnel while keeping the association.
        let downlink_stuck = match self.downlink_failed_since {
            Some(since) => {
                since.elapsed() >= DOWNLINK_STUCK_AFTER
                    && self.downlink_failed_last.elapsed() <= DOWNLINK_STUCK_ACTIVE
            }
            None => false,
        };
        if downlink_stuck {
            self.log(
                LogLevel::Warn,
                format!(
                    "no packet reached macOS through the tunnel for {}s; restarting the tunnel",
                    DOWNLINK_STUCK_AFTER.as_secs()
                ),
            );
            self.restart_tunnel();
            return;
        }

        self.report_relay();
    }

    /// Publish throughput — and, occasionally, the packet totals — to the UI.
    fn report_relay(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.traffic_at);
        if elapsed < TRAFFIC_INTERVAL {
            return;
        }
        let secs = elapsed.as_secs_f64().max(0.001);
        let down = self
            .stats
            .to_tun_bytes
            .saturating_sub(self.last_to_tun_bytes) as f64
            / secs;
        let up = self
            .stats
            .to_link_bytes
            .saturating_sub(self.last_to_link_bytes) as f64
            / secs;
        // Smooth so the readout does not flicker on a bursty link. It also
        // decays back to zero once the link goes quiet.
        let smooth = |new: f64, previous: f64| {
            if previous == 0.0 {
                new
            } else {
                0.35 * new + 0.65 * previous
            }
        };
        self.down_bps = smooth(down, self.down_bps);
        self.up_bps = smooth(up, self.up_bps);
        self.last_to_tun_bytes = self.stats.to_tun_bytes;
        self.last_to_link_bytes = self.stats.to_link_bytes;
        self.traffic_at = now;

        // Keep the menu bar's readout in step with the relay.
        crate::menu_bar::set_rates(Some((self.up_bps, self.down_bps)));

        self.emit(Event::Traffic(Traffic {
            to_tun_bytes: self.stats.to_tun_bytes,
            to_tun_packets: self.stats.to_tun_packets,
            to_link_bytes: self.stats.to_link_bytes,
            to_link_packets: self.stats.to_link_packets,
            down_bytes_per_sec: self.down_bps,
            up_bytes_per_sec: self.up_bps,
        }));

        self.report_ticks += 1;
        if self.report_ticks.is_multiple_of(STATE_REPORT_EVERY) {
            self.emit(Event::Tunnel(TunnelState::Running {
                to_link_packets: self.stats.to_link_packets,
                to_tun_packets: self.stats.to_tun_packets,
            }));
        }

        // A periodic summary so a link that bursts and then stalls can be read
        // off the numbers: steady rates mean the air link is the limit, while
        // sawtooth rates with a rising `dropped` count point at the relay.
        if now.duration_since(self.summary_at) >= SUMMARY_INTERVAL {
            self.summary_at = now;
            self.log(
                LogLevel::Info,
                format!(
                    "link: {} down / {} up, {} in / {} out frames, {} dropped, {} tx-status ({} failed)",
                    format_rate(self.down_bps),
                    format_rate(self.up_bps),
                    self.stats.to_tun_packets,
                    self.stats.to_link_packets,
                    self.stats.dropped,
                    self.stats.tx_status_drained,
                    self.stats.tx_status_failed,
                ),
            );
        }

        // Liveness: a healthy link advances a packet counter; a dead one keeps
        // failing to transfer while moving nothing. Re-establish the link when
        // nothing has moved for a while *despite* transfer failures — an
        // idle-but-healthy link fails nothing, so this does not false-alarm.
        let total = self.stats.to_tun_packets + self.stats.to_link_packets;
        if total > self.last_total_packets {
            self.last_total_packets = total;
            self.drops_at_progress = self.stats.dropped;
            self.progress_at = now;
        } else if now.duration_since(self.progress_at) >= STALL_RECOVER_AFTER
            && self.stats.dropped >= self.drops_at_progress + STALL_MIN_DROPS
        {
            self.progress_at = now;
            self.drops_at_progress = self.stats.dropped;
            self.recover_link();
        }
    }

    /// Build a fresh tunnel (a new helper session) on the existing
    /// association. Cheaper than [`Self::recover_link`]: the Wi-Fi link, the
    /// association and the lease are kept, and only the relay connection is
    /// rebuilt. Falls back to a full re-establishment when the tunnel cannot
    /// come up at all.
    fn restart_tunnel(&mut self) {
        self.tunnel_stop();
        self.downlink_failed_since = None;
        self.tunnel_start();
        if self.tunnel.is_none() {
            self.recover_link();
        }
    }

    /// Re-establish a link whose association still looks up but has stopped
    /// carrying traffic (the AP deauthenticated us, or the device wedged).
    fn recover_link(&mut self) {
        let Some(ssid) = self.link.as_ref().map(|link| link.ssid.clone()) else {
            return;
        };
        if self.recovery_attempts >= RECOVERY_ATTEMPTS {
            self.fail_wifi(&format!(
                "the link to \"{ssid}\" kept failing to pass traffic and could not be \
                 re-established; the radio may need a replug"
            ));
            return;
        }
        self.recovery_attempts += 1;
        self.log(
            LogLevel::Warn,
            format!(
                "no traffic through the tunnel for {}s; re-establishing \"{ssid}\" (attempt {})…",
                STALL_RECOVER_AFTER.as_secs(),
                self.recovery_attempts
            ),
        );
        // `connect` refuses to touch a live link for the same SSID, so drop it
        // first; the tunnel goes down with it.
        self.drop_link();
        self.connect(&ssid, None, true);
    }
}

/// Transmit one IP packet, resolving the next hop with ARP first.
///
/// Broadcast/multicast (DHCP, mDNS) goes out as-is; a unicast packet is
/// addressed to the resolved next-hop MAC, and while that is unknown an ARP
/// request is sent (rate-limited) and this packet is dropped — the sender's
/// retransmit goes out once the reply lands.
#[allow(clippy::too_many_arguments)]
fn send_ipv4(
    chip: &Mt7601u<RusbTransport>,
    info: &StaLinkInfo,
    packet: &[u8],
    our_ip: std::net::Ipv4Addr,
    mask: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
    arp: &mut ArpCache,
    pending: &mut Option<(std::net::Ipv4Addr, Instant)>,
) -> Result<(), UsbError> {
    let Some(ip) = ipv4::parse(packet) else {
        return Ok(());
    };
    if ip.destination.is_broadcast() || ip.destination.is_multicast() {
        return chip.tx_ipv4(info, packet);
    }

    let next_hop = arp::next_hop(ip.destination, our_ip, mask, gateway);
    match arp.mac(next_hop) {
        Some(mac) => chip.tx_payload_to(info, &mac, wifi::data::ETHERTYPE_IPV4, packet),
        None => {
            request_arp(chip, info, our_ip, next_hop, pending);
            Ok(())
        }
    }
}

/// Send an ARP request for `target`, at most once a second.
fn request_arp(
    chip: &Mt7601u<RusbTransport>,
    info: &StaLinkInfo,
    our_ip: std::net::Ipv4Addr,
    target: std::net::Ipv4Addr,
    pending: &mut Option<(std::net::Ipv4Addr, Instant)>,
) {
    let now = Instant::now();
    if let Some((last, sent)) = pending {
        if *last == target && now.duration_since(*sent) < ARP_RETRY {
            return;
        }
    }
    let packet = arp::request(&info.local_mac, our_ip, target);
    // Addressed to the AP rather than to the broadcast MAC: the next hop of an
    // on-link address is the AP itself (it is the gateway), and a group-key
    // frame is not delivered by this AP — see `Mt7601u::tx_ipv4`.
    let _ = chip.tx_payload_to(info, &info.bssid, arp::ETHERTYPE_ARP, &packet);
    *pending = Some((target, now));
}

/// Answer an ARP request for our address, and learn the next hop from replies.
///
/// Returns a note when an inbound ARP frame was received and acted on. Any
/// inbound ARP is proof the link's unicast receive path works — the next hop's
/// reply is a unicast frame, and without it the relay never learns the
/// gateway's MAC and drops every packet.
fn answer_arp(
    chip: &Mt7601u<RusbTransport>,
    info: &StaLinkInfo,
    payload: &[u8],
    our_ip: std::net::Ipv4Addr,
    arp: &mut ArpCache,
) -> Option<String> {
    let packet = arp::parse(payload)?;
    match packet.operation {
        arp::OP_REQUEST if packet.target_ip == our_ip => {
            let reply = arp::reply(
                &info.local_mac,
                our_ip,
                &packet.sender_mac,
                packet.sender_ip,
            );
            let _ = chip.tx_payload_to(info, &packet.sender_mac, arp::ETHERTYPE_ARP, &reply);
            arp.learn(packet.sender_ip, packet.sender_mac);
            Some(format!(
                "ARP request for {our_ip} from {}",
                packet.sender_ip
            ))
        }
        arp::OP_REQUEST => None,
        arp::OP_REPLY => {
            arp.learn(packet.sender_ip, packet.sender_mac);
            Some(format!("ARP reply from {}", packet.sender_ip))
        }
        _ => None,
    }
}

/// Create and configure the in-process `utun` interface. Needs root.
fn local_tunnel(lease: &dhcp::Lease) -> Result<Box<dyn TunnelLink>, String> {
    let mut utun = Utun::open().map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            "could not create a utun interface (permission denied); install the helper with \
             `sudo mt7601u-macos --install-helper` or run the GUI with sudo"
                .to_string()
        } else {
            format!("could not create a utun interface: {error}")
        }
    })?;
    utun.set_read_timeout(POLL)
        .map_err(|error| format!("could not set the utun read timeout: {error}"))?;
    utun.configure(lease.address, lease.router, 1500)
        .map_err(|error| format!("ifconfig failed: {error}"))?;
    utun.add_default_route()
        .map_err(|error| format!("adding routes failed: {error}"))?;
    if !lease.dns.is_empty() {
        if let Err(error) = utun.set_dns(&lease.dns, lease.router) {
            tracing::warn!("setting DNS failed: {error}");
        }
    }
    Ok(Box::new(utun))
}

/// Ask the privileged helper to create and configure the interface.
fn helper_tunnel(lease: &dhcp::Lease) -> Result<Box<dyn TunnelLink>, String> {
    let mut client =
        HelperClient::connect().map_err(|error| helper::client::unavailable_message(&error))?;
    client.start(&StartRequest {
        local: lease.address,
        peer: lease.router,
        mtu: 1500,
        router: lease.router,
        dns: lease.dns.clone(),
    })?;
    Ok(Box::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A distinct credentials file per worker, so parallel tests cannot read
    /// each other's saved networks.
    fn next_credentials_path() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("mt7601u-backend-test-{}-{id}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn worker() -> (Worker, UnboundedReceiver<Event>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let worker = Worker {
            events: tx,
            ctx: egui::Context::default(),
            chip: None,
            rx_pump: None,
            device: None,
            networks: Vec::new(),
            assoc: None,
            link: None,
            tunnel: None,
            stats: tunnel::relay::Stats::default(),
            report_ticks: 0,
            traffic_at: Instant::now(),
            last_to_link_bytes: 0,
            last_to_tun_bytes: 0,
            down_bps: 0.0,
            up_bps: 0.0,
            summary_at: Instant::now(),
            progress_at: Instant::now(),
            last_total_packets: 0,
            drops_at_progress: 0,
            downlink_failed_since: None,
            downlink_failed_last: Instant::now(),
            recovery_attempts: 0,
            credentials: Credentials::default(),
            credentials_path: next_credentials_path(),
            auto_paused: false,
            auto_scanned: false,
            auto_reconnected: false,
            detect_ticks: 0,
            open_failures: 0,
            replug: None,
            mcu_retries: 0,
            device_problem: None,
            addressing: Addressing::default(),
            arp: ArpCache::default(),
            arp_pending: None,
        };
        (worker, rx)
    }

    fn events(rx: &mut UnboundedReceiver<Event>) -> Vec<Event> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    }

    fn log_messages(rx: &mut UnboundedReceiver<Event>) -> Vec<String> {
        events(rx)
            .into_iter()
            .filter_map(|event| match event {
                Event::Log(line) => Some(line.message),
                _ => None,
            })
            .collect()
    }

    fn wifi_errors(rx: &mut UnboundedReceiver<Event>) -> Vec<String> {
        events(rx)
            .into_iter()
            .filter_map(|event| match event {
                Event::Wifi(WifiState::Error(message)) => Some(message),
                _ => None,
            })
            .collect()
    }

    fn scan_result(ssid: &str, security: Security) -> Network {
        Network {
            ssid: ssid.into(),
            bssid: Some([1, 2, 3, 4, 5, 6]),
            signal_dbm: None,
            channel: Some(6),
            security,
        }
    }

    #[test]
    fn log_emits_event() {
        let (worker, mut rx) = worker();
        worker.log(LogLevel::Info, "hello");
        match rx.try_recv() {
            Ok(Event::Log(line)) => {
                assert_eq!(line.level, LogLevel::Info);
                assert_eq!(line.message, "hello");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn stopping_pauses_the_pipeline_and_reports_it() {
        let (mut worker, mut rx) = worker();
        worker.stop();
        let paused = events(&mut rx)
            .into_iter()
            .any(|event| matches!(event, Event::Paused(true)));
        assert!(paused);
        assert!(worker.auto_paused);

        // A paused worker must not touch the USB bus at all.
        worker.auto_step();
        assert!(events(&mut rx).is_empty());

        worker.resume();
        assert!(!worker.auto_paused);
    }

    #[test]
    fn an_mcu_failure_is_recovered_by_reopening_before_a_replug_is_asked_for() {
        let (mut worker, _rx) = worker();
        let stuck = UsbError::Other("MCU response for seq 1 not received".into());

        assert!(worker.should_retry_mcu(&stuck));
        worker.mcu_retries = MCU_RETRIES;
        assert!(
            !worker.should_retry_mcu(&stuck),
            "a device that keeps failing must stop being retried"
        );

        // Anything that is not the MCU-channel failure is reported as-is.
        worker.mcu_retries = 0;
        let out_of_range = UsbError::Other("channel 15 out of range".into());
        assert!(!worker.should_retry_mcu(&out_of_range));
    }

    #[test]
    fn starting_again_clears_a_stale_replug_request() {
        let (mut worker, mut rx) = worker();
        worker.set_replug(Some("unplug and replug".into()));
        worker.resume();

        assert!(
            worker.replug.is_none(),
            "an explicit Start must clear the replug dead-end"
        );
        assert!(events(&mut rx)
            .into_iter()
            .any(|event| matches!(event, Event::Replug(None))));
    }

    #[test]
    fn connecting_to_an_unknown_network_is_refused() {
        let (mut worker, mut rx) = worker();
        worker.connect("net", None, true);
        assert!(wifi_errors(&mut rx)
            .iter()
            .any(|message| message.contains("not in the last scan")));
    }

    #[test]
    fn connecting_without_a_device_reports_an_error() {
        let (mut worker, mut rx) = worker();
        worker.networks = vec![scan_result("cafe", Security::Open)];
        worker.connect("cafe", None, true);
        assert!(wifi_errors(&mut rx)
            .iter()
            .any(|message| message.contains("not open")));
    }

    #[test]
    fn unsupported_security_is_refused_with_the_reason() {
        let (mut worker, mut rx) = worker();
        worker.networks = vec![scan_result("legacy", Security::Unknown)];
        worker.connect("legacy", Some("hunter2"), true);
        assert!(wifi_errors(&mut rx)
            .iter()
            .any(|message| message.contains("only open, WPA-PSK, WPA2-PSK and WPA3-SAE")));
    }

    #[test]
    fn a_wpa2_network_without_a_saved_passphrase_asks_for_one() {
        let (mut worker, mut rx) = worker();
        worker.networks = vec![scan_result("home", Security::Wpa2)];
        worker.connect("home", None, true);
        assert!(wifi_errors(&mut rx)
            .iter()
            .any(|message| message.contains("enter the passphrase")));
    }

    #[test]
    fn a_saved_passphrase_is_reused_without_being_logged() {
        let (mut worker, mut rx) = worker();
        worker.networks = vec![scan_result("home", Security::Wpa2)];
        worker.credentials.remember("home", "hunter2");
        worker.connect("home", None, true);

        // It got past the passphrase check and failed on the missing device.
        let errors = wifi_errors(&mut rx);
        assert!(errors.iter().any(|message| message.contains("not open")));
        let mut transcript = log_messages(&mut rx);
        transcript.extend(errors);
        assert!(
            !transcript.iter().any(|line| line.contains("hunter2")),
            "the passphrase must never reach a log line"
        );
    }

    #[test]
    fn remembering_a_passphrase_publishes_the_network_names_only() {
        let (mut worker, mut rx) = worker();
        worker.remember_passphrase("home", "hunter2");
        assert_eq!(worker.credentials.passphrase("home"), Some("hunter2"));

        let published = events(&mut rx);
        assert!(published.iter().any(|event| matches!(
            event,
            Event::SavedNetworks(names) if names == &vec!["home".to_string()]
        )));
        assert!(!format!("{published:?}").contains("hunter2"));

        let reloaded = Credentials::load(&worker.credentials_path).expect("reload");
        assert!(reloaded.has_passphrase("home"));
        let _ = std::fs::remove_file(&worker.credentials_path);
    }

    #[test]
    fn forgetting_a_passphrase_removes_it_from_disk() {
        let (mut worker, mut rx) = worker();
        worker.remember_passphrase("home", "hunter2");
        worker.forget_passphrase("home");
        assert!(!worker.credentials.has_passphrase("home"));
        assert!(events(&mut rx).into_iter().any(|event| matches!(
            event,
            Event::SavedNetworks(names) if names.is_empty()
        )));

        let reloaded = Credentials::load(&worker.credentials_path).expect("reload");
        assert!(!reloaded.has_passphrase("home"));
        let _ = std::fs::remove_file(&worker.credentials_path);
    }

    #[test]
    fn auto_connect_preference_round_trips_to_disk() {
        let (mut worker, _rx) = worker();
        worker.set_auto_connect(false);
        assert!(!worker.credentials.auto_connect);
        let reloaded = Credentials::load(&worker.credentials_path).expect("reload");
        assert!(!reloaded.auto_connect);
        let _ = std::fs::remove_file(&worker.credentials_path);
    }

    #[test]
    fn auto_reconnect_does_nothing_when_it_is_switched_off() {
        let (mut worker, mut rx) = worker();
        worker.credentials.auto_connect = false;
        worker.credentials.mark_connected("home");
        worker.networks = vec![scan_result("home", Security::Wpa2)];
        worker.credentials.remember("home", "hunter2");
        worker.auto_reconnect();
        assert!(events(&mut rx).is_empty());
    }

    #[test]
    fn auto_reconnect_says_so_when_the_network_is_out_of_range() {
        let (mut worker, mut rx) = worker();
        worker.credentials.mark_connected("home");
        worker.networks = vec![scan_result("cafe", Security::Open)];
        worker.auto_reconnect();
        assert!(log_messages(&mut rx)
            .iter()
            .any(|line| line.contains("not in range")));
    }

    #[test]
    fn auto_reconnect_asks_for_a_passphrase_instead_of_failing_silently() {
        let (mut worker, mut rx) = worker();
        worker.credentials.mark_connected("home");
        worker.networks = vec![scan_result("home", Security::Wpa2)];
        worker.auto_reconnect();
        assert!(log_messages(&mut rx)
            .iter()
            .any(|line| line.contains("needs a passphrase")));
    }

    #[test]
    fn auto_reconnect_actually_joins_a_saved_network() {
        let (mut worker, mut rx) = worker();
        worker.credentials.mark_connected("home");
        worker.networks = vec![scan_result("home", Security::Wpa2)];
        worker.credentials.remember("home", "hunter2");
        worker.auto_reconnect();
        // Without a chip the join cannot complete, which proves it was tried.
        assert!(wifi_errors(&mut rx)
            .iter()
            .any(|message| message.contains("not open")));
    }

    #[test]
    fn an_open_network_needs_no_passphrase() {
        let (mut worker, mut rx) = worker();
        worker.credentials.mark_connected("cafe");
        worker.networks = vec![scan_result("cafe", Security::Open)];
        worker.auto_reconnect();
        assert!(wifi_errors(&mut rx)
            .iter()
            .any(|message| message.contains("not open")));
    }

    #[test]
    fn a_failed_open_is_reported_once_and_published_to_the_ui() {
        let (mut worker, mut rx) = worker();
        for _ in 0..3 {
            worker.report_open_failure("Could not claim interface 0: Access denied");
        }

        let published = events(&mut rx);
        let errors = published
            .iter()
            .filter(|event| matches!(event, Event::Log(line) if line.level == LogLevel::Error))
            .count();
        assert_eq!(errors, 1, "a repeated failure must not spam the log");
        assert!(published
            .iter()
            .any(|event| matches!(event, Event::DeviceProblem(Some(_)))));

        worker.set_device_problem(None);
        assert!(events(&mut rx)
            .iter()
            .any(|event| matches!(event, Event::DeviceProblem(None))));
    }

    #[test]
    fn a_successful_open_clears_the_open_failure() {
        let (mut worker, mut rx) = worker();
        worker.report_open_failure("Access denied");
        assert!(worker.device_problem.is_some());
        worker.open_failures = 0;
        worker.set_device_problem(None);
        assert!(worker.device_problem.is_none());
        let _ = events(&mut rx);
    }

    #[test]
    fn scanning_while_connected_drops_the_link_to_scan_and_rejoin() {
        let (mut worker, mut rx) = worker();
        // A live link: a scan cannot run on top of it, but it is no longer a
        // reason to refuse — the link is dropped and rejoined after the scan.
        worker.assoc = Some(AssocInfo {
            local_mac: [1, 2, 3, 4, 5, 6],
            bssid: [7, 8, 9, 10, 11, 12],
            qos: false,
            encrypted: true,
            handshake_confirmed: true,
        });
        worker.link = Some(LinkDetails::associated(&scan_result(
            "home",
            Security::Wpa2,
        )));
        worker.credentials.mark_connected("home");

        worker.scan();

        assert!(
            worker.assoc.is_none(),
            "the live link must be dropped to scan"
        );
        assert!(worker.link.is_none());
        assert!(
            worker.chip.is_none(),
            "the device is released so the reopen runs a fresh bring-up"
        );
        let messages = log_messages(&mut rx);
        assert!(messages
            .iter()
            .any(|line| line.contains("Disconnecting to scan")));
        assert!(
            !messages
                .iter()
                .any(|line| line.contains("would break the link")),
            "a live link is no longer a reason to refuse a scan"
        );
    }

    #[test]
    fn disconnect_without_a_link_warns_instead_of_lying() {
        let (mut worker, mut rx) = worker();
        worker.disconnect();
        match rx.try_recv() {
            Ok(Event::Log(line)) => assert_eq!(line.level, LogLevel::Warn),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn disconnect_parks_the_device_for_a_reopen_and_rescan() {
        let (mut worker, mut rx) = worker();
        // Pretend a link and a finished scan are in place.
        worker.assoc = Some(AssocInfo {
            local_mac: [1, 2, 3, 4, 5, 6],
            bssid: [7, 8, 9, 10, 11, 12],
            qos: false,
            encrypted: true,
            handshake_confirmed: true,
        });
        worker.link = Some(LinkDetails::associated(&scan_result(
            "home",
            Security::Wpa2,
        )));
        worker.networks = vec![scan_result("home", Security::Wpa2)];
        worker.auto_scanned = true;

        worker.disconnect();

        // The device is released and the pipeline is armed to reopen and rescan,
        // so the next scan runs on a freshly initialised radio — no replug.
        assert!(worker.chip.is_none(), "disconnect must release the device");
        assert!(worker.assoc.is_none());
        assert!(worker.link.is_none());
        assert!(worker.tunnel.is_none());
        assert!(
            !worker.auto_scanned,
            "a reopen must run a fresh scan instead of being skipped"
        );
        assert!(
            !worker.auto_paused,
            "a disconnect is not a Stop: the pipeline keeps running"
        );
        assert!(log_messages(&mut rx)
            .iter()
            .any(|line| line.contains("released the device")));
    }

    #[test]
    fn a_stalled_link_is_re_established() {
        let (mut worker, mut rx) = worker();
        worker.link = Some(LinkDetails::associated(&scan_result(
            "home",
            Security::Wpa2,
        )));
        worker.networks = vec![scan_result("home", Security::Wpa2)];
        worker.recover_link();

        assert!(log_messages(&mut rx)
            .iter()
            .any(|line| line.contains("re-establishing")));
        assert_eq!(worker.recovery_attempts, 1);
        assert!(worker.link.is_none(), "the dead link must be dropped first");
    }

    #[test]
    fn recovering_a_dead_link_gives_up_after_the_attempt_cap() {
        let (mut worker, mut rx) = worker();
        worker.link = Some(LinkDetails::associated(&scan_result(
            "home",
            Security::Wpa2,
        )));
        worker.recovery_attempts = RECOVERY_ATTEMPTS;
        worker.recover_link();

        assert!(wifi_errors(&mut rx)
            .iter()
            .any(|message| message.contains("could not be re-established")));
        assert_eq!(worker.recovery_attempts, RECOVERY_ATTEMPTS);
    }

    #[test]
    fn tunnel_start_without_a_link_reports_an_error() {
        let (mut worker, mut rx) = worker();
        worker.tunnel_start();
        let state = events(&mut rx).into_iter().find_map(|event| match event {
            Event::Tunnel(state) => Some(state),
            _ => None,
        });
        assert!(state.expect("tunnel event").is_error());
    }

    #[test]
    fn a_replug_request_is_published_once_and_cleared_when_satisfied() {
        let (mut worker, mut rx) = worker();
        worker.set_replug(Some("replug it".into()));
        worker.set_replug(Some("replug it".into()));
        let published = events(&mut rx)
            .into_iter()
            .filter(|event| matches!(event, Event::Replug(Some(_))))
            .count();
        assert_eq!(published, 1, "the same hint must not be republished");

        worker.set_replug(None);
        assert!(events(&mut rx)
            .into_iter()
            .any(|event| matches!(event, Event::Replug(None))));
    }
}
