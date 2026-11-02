//! `eframe`/`egui` GUI shell.
//!
//! The window is a native-looking macOS utility: a slim self-drawn title bar,
//! a single scrolling page of compact grouped cards, and a bottom tab strip
//! (Networks · Device · Logs) that stands in for a sidebar.
//!
//! The first surface is the Wi-Fi picker with the live link status above it. It
//! follows the states the radio can be in — connected, scanning, disconnected
//! and fault — and shows only what belongs to the state it is in, so nothing is
//! duplicated between panels. Connecting also brings the tunnel up, so there is
//! no separate "start tunnel" step. The device is detected, opened and scanned
//! automatically; the user only ever stops it.
//!
//! The look is token-driven: every colour, radius and type size comes from
//! `theme.rs`, which carries the macOS dark system palette. The status glyphs —
//! radar, spinner, signal arcs — are painted by hand so the state of the radio
//! is legible at a glance. A fault opens a standard macOS alert sheet rather
//! than filling the page.

use std::time::{Duration, Instant};

use eframe::egui;
use egui::{
    pos2, vec2, Align, Align2, Color32, CornerRadius, FontId, Frame, Key, Label, Layout, Margin,
    Modal, Rect, Response, RichText, Sense, Stroke, StrokeKind, Vec2,
};

use crate::app_state::AppState;
use crate::backend::Backend;
use crate::commands::{Addressing, Command};
use crate::format::{format_bytes, format_count, format_rate};
use crate::helper;
use crate::logging::{LogLevel, LogLine};
use crate::theme::{
    color, with_alpha, Tone, RADIUS_LG, RADIUS_MD, RADIUS_PILL, RADIUS_SM, SPACE_1, SPACE_2,
    SPACE_3, SPACE_4, TEXT_BODY, TEXT_DISPLAY, TEXT_HEAD, TEXT_MICRO, TEXT_SMALL, TEXT_TITLE,
};
use crate::tunnel::TunnelState;
use crate::wifi::{Network, Security, WifiState};

/// Height of the self-drawn title bar and of the bottom tab strip.
const TITLEBAR_HEIGHT: f32 = 46.0;
const TABBAR_HEIGHT: f32 = 56.0;
/// Height of the in-page action bar that sits above the tab strip.
const ACTIONBAR_HEIGHT: f32 = 48.0;
/// Height of one network row and of the custom controls.
const ROW_HEIGHT: f32 = 54.0;
const CONTROL_HEIGHT: f32 = 28.0;
/// The page is one centred column so rows do not stretch across a huge display.
const CONTENT_MAX_WIDTH: f32 = 620.0;
/// The status glyph on the Networks hero.
const HERO_GLYPH: f32 = 44.0;

/// The operational surfaces, chosen from the bottom tab strip. The live
/// throughput and the network picker share one page, so "Networks" is both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Networks,
    Device,
}

impl Tab {
    const ALL: [Self; 2] = [Self::Networks, Self::Device];

    fn label(self) -> &'static str {
        match self {
            Self::Networks => "Networks",
            Self::Device => "Device",
        }
    }
}

// The log console is hidden from users (kept here so it can be restored).
//
// /// Severity filter for the log console.
// #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
// enum LogFilter {
//     #[default]
//     All,
//     Info,
//     Warn,
//     Error,
// }
//
// impl LogFilter {
//     const ALL: [Self; 4] = [Self::All, Self::Info, Self::Warn, Self::Error];
//
//     fn label(self) -> &'static str {
//         match self {
//             Self::All => "All",
//             Self::Info => "Info",
//             Self::Warn => "Warn",
//             Self::Error => "Error",
//         }
//     }
//
//     fn accepts(self, level: LogLevel) -> bool {
//         match self {
//             Self::All => true,
//             Self::Info => level == LogLevel::Info,
//             Self::Warn => level == LogLevel::Warn,
//             Self::Error => level == LogLevel::Error,
//         }
//     }
// }

/// A privileged helper operation the GUI starts and must poll for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperJob {
    Install,
    Uninstall,
}

/// Root application object.
pub struct Mt7601uApp {
    state: AppState,
    backend: Backend,
    // export_status: Option<String>,
    /// Whether the privileged helper answered the last probe.
    helper_available: bool,
    /// When the helper was last probed (re-checked at most every few seconds).
    helper_checked: Instant,
    /// The helper install/uninstall in flight, if any.
    helper_job: Option<HelperJob>,
    /// Result channel for the running helper job.
    helper_job_rx: Option<std::sync::mpsc::Receiver<Result<(), String>>>,
    // log_filter: LogFilter,
    show_password: bool,
    /// The passphrase field should take focus on the next frame.
    focus_password: bool,
    /// The network the last join attempt was for, so a failure can offer a retry.
    last_attempt: Option<String>,
    /// Which bottom-tab surface is showing.
    tab: Tab,
    /// "Remember this network" in the inline join control.
    remember: bool,
    /// The fault sheet the user has dismissed, so it does not nag.
    alert_dismissed: Option<String>,
    /// "Join Other…" sheet state.
    join_other_open: bool,
    join_other_ssid: String,
    join_other_note: Option<String>,
    /// The addressing switch is off: the user wants manual addressing. This is
    /// GUI state because the choice only reaches the backend on Save.
    manual_mode: bool,
    /// The manual-addressing editor is expanded for typing.
    manual_editor: bool,
    /// Left inset reserved for the native traffic lights, in points.
    titlebar_inset: f32,
    /// The platform window handle, kept for the macOS menu bar item.
    window_handle: Option<raw_window_handle::RawWindowHandle>,
}

impl Mt7601uApp {
    /// Create the app, install the theme and start the backend worker.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::theme::apply(&cc.egui_ctx);
        // The Dock shows the bundled AppIcon rather than the default binary icon.
        crate::icon::set_dock_icon();
        let backend = Backend::spawn(cc.egui_ctx.clone());
        Self {
            state: AppState::default(),
            backend,
            // export_status: None,
            helper_available: helper::server::is_running(),
            helper_checked: Instant::now(),
            helper_job: None,
            helper_job_rx: None,
            // log_filter: LogFilter::default(),
            show_password: false,
            focus_password: false,
            last_attempt: None,
            tab: Tab::default(),
            remember: true,
            alert_dismissed: None,
            join_other_open: false,
            join_other_ssid: String::new(),
            join_other_note: None,
            manual_mode: false,
            manual_editor: false,
            titlebar_inset: titlebar_inset(cc),
            window_handle: platform_window_handle(cc),
        }
    }

    /// Re-probe the helper occasionally so installing it while the GUI is open
    /// is picked up without a restart.
    fn refresh_helper_status(&mut self) {
        if self.helper_checked.elapsed() >= Duration::from_secs(2) {
            self.helper_available = helper::server::is_running();
            self.helper_checked = Instant::now();
        }
    }

    /// Install or remove the helper through the macOS administrator prompt.
    fn start_helper_job(&mut self, job: HelperJob, ctx: &egui::Context) {
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(error) => {
                self.state.logs.push(LogLine::error(format!(
                    "Cannot locate the app binary to reach the helper: {error}"
                )));
                return;
            }
        };

        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = match job {
                HelperJob::Install => helper::install_with_prompt(&exe),
                HelperJob::Uninstall => helper::uninstall_with_prompt(&exe),
            };
            let _ = tx.send(result);
            ctx.request_repaint();
        });

        let verb = match job {
            HelperJob::Install => "install",
            HelperJob::Uninstall => "remove",
        };
        self.helper_job_rx = Some(rx);
        self.helper_job = Some(job);
        self.state.logs.push(LogLine::new(
            LogLevel::Info,
            format!("Requesting administrator privileges to {verb} the helper…"),
        ));
    }

    /// Collect the outcome of a running helper job, if it has finished.
    fn poll_helper_job(&mut self) {
        let Some(rx) = self.helper_job_rx.take() else {
            return;
        };
        let job = self.helper_job;
        match rx.try_recv() {
            Ok(result) => {
                self.helper_job = None;
                self.helper_available = helper::server::is_running();
                self.helper_checked = Instant::now();
                match result {
                    Ok(()) if job == Some(HelperJob::Uninstall) => self
                        .state
                        .logs
                        .push(LogLine::new(LogLevel::Info, "Privileged helper removed.")),
                    Ok(()) if job == Some(HelperJob::Install) && self.helper_available => self
                        .state
                        .logs
                        .push(LogLine::new(LogLevel::Info, "Privileged helper installed.")),
                    Ok(()) => self.state.logs.push(LogLine::new(
                        LogLevel::Warn,
                        "The helper is not reachable yet; it may need a moment.",
                    )),
                    Err(error) => self
                        .state
                        .logs
                        .push(LogLine::error(format!("Helper change failed: {error}"))),
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => self.helper_job_rx = Some(rx),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.helper_job = None,
        }
    }

    /// Start joining a network. A passphrase is only asked for when needed.
    fn join(&mut self, ssid: &str) {
        let Some(network) = self.state.network(ssid).cloned() else {
            return;
        };
        self.tab = Tab::Networks;
        self.last_attempt = Some(network.ssid.clone());

        // Clicking the network we are already on leaves it, as the system
        // Wi-Fi menu does.
        if self.state.connected_ssid() == Some(network.ssid.as_str()) {
            self.backend.send(Command::Disconnect);
            return;
        }
        if !security_supported(&network.security) {
            return;
        }
        if matches!(
            network.security,
            Security::Wpa2 | Security::Wpa | Security::Wpa3
        ) && !self.state.is_saved(&network.ssid)
        {
            // The inline password control opens under this row.
            self.show_password = false;
            self.focus_password = true;
            self.state.password_input.clear();
            self.state.awaiting_password = Some(network.ssid);
            return;
        }
        self.backend.send(Command::Connect {
            ssid: network.ssid,
            password: None,
            remember: true,
        });
    }

    /// Toggle the inline join control for a network row.
    fn toggle_inline_join(&mut self, ssid: &str) {
        if self.state.awaiting_password.as_deref() == Some(ssid) {
            self.state.awaiting_password = None;
            self.state.password_input.clear();
            return;
        }
        self.join(ssid);
    }

    /// Ask for the passphrase again, discarding a saved one the AP rejected.
    fn ask_for_a_new_passphrase(&mut self, ssid: &str) {
        self.backend.send(Command::ForgetPassphrase {
            ssid: ssid.to_string(),
        });
        self.show_password = false;
        self.focus_password = true;
        self.state.password_input.clear();
        self.state.awaiting_password = Some(ssid.to_string());
    }

    /// Keyboard shortcuts, macOS-flavoured: ⌘R rescan, ⌘D device.
    fn shortcuts(&mut self, ctx: &egui::Context) {
        if self.state.awaiting_password.is_some() {
            // The inline passphrase control owns the keyboard.
            return;
        }
        let (rescan, device) = ctx.input_mut(|input| {
            (
                input.consume_key(egui::Modifiers::COMMAND, Key::R),
                input.consume_key(egui::Modifiers::COMMAND, Key::D),
            )
        });
        if rescan && scan_blocker(&self.state).is_none() {
            self.backend.send(Command::Scan);
        }
        if device {
            self.tab = Tab::Device;
        }
    }

    /// Apply picks made from the macOS menu bar item this frame.
    fn menu_actions(&mut self) {
        for action in crate::menu_bar::take_actions() {
            match action {
                crate::menu_bar::MenuAction::OpenDevice => {
                    self.backend.send(Command::OpenDevice);
                }
                crate::menu_bar::MenuAction::CloseDevice => {
                    self.backend.send(Command::CloseDevice);
                }
                crate::menu_bar::MenuAction::Rescan => {
                    if scan_blocker(&self.state).is_none() {
                        self.backend.send(Command::Scan);
                    }
                }
                crate::menu_bar::MenuAction::Identify => {
                    self.backend.send(Command::Identify);
                }
                crate::menu_bar::MenuAction::ToggleDetails => {
                    self.tab = Tab::Device;
                }
                // The log surface is hidden from users; ignore the menu pick.
                crate::menu_bar::MenuAction::ToggleLogs => {}
            }
        }
    }
}

/// Space the native window buttons take at the top left of the window.
#[cfg(target_os = "macos")]
fn titlebar_inset(cc: &eframe::CreationContext<'_>) -> f32 {
    use raw_window_handle::HasWindowHandle;

    const FALLBACK: f32 = 76.0;

    cc.window_handle()
        .ok()
        .and_then(|handle| eframe::WindowChromeMetrics::from_window_handle(&handle.as_raw()))
        .map(|metrics| metrics.traffic_lights_size.x / cc.egui_ctx.zoom_factor())
        .filter(|width| width.is_finite() && *width > 0.0)
        .unwrap_or(FALLBACK)
}

/// On platforms without traffic lights the header owns the whole corner.
#[cfg(not(target_os = "macos"))]
fn titlebar_inset(_cc: &eframe::CreationContext<'_>) -> f32 {
    0.0
}

/// The raw platform window handle, handed to the macOS menu bar item so it
/// can order the window back to the front.
fn platform_window_handle(
    cc: &eframe::CreationContext<'_>,
) -> Option<raw_window_handle::RawWindowHandle> {
    use raw_window_handle::HasWindowHandle;

    cc.window_handle().ok().map(|handle| handle.as_raw())
}

// --------------------------------------------------------------- application

impl eframe::App for Mt7601uApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Runs every frame, also while the window is minimized or occluded.
        crate::menu_bar::install(ctx, self.window_handle);

        // Menu-bar picks must land even when the window is hidden.
        self.menu_actions();

        if ctx.input(|input| input.viewport().close_requested()) {
            // Closing the window keeps the relay alive: cancel the close and
            // tuck the app away; the menu bar item brings it back. ⌘Q exits.
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            crate::menu_bar::hide_app();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.state.apply_all(self.backend.drain());
        self.refresh_helper_status();
        self.poll_helper_job();
        let ctx = ui.ctx().clone();
        self.shortcuts(&ctx);

        // ── Slim title bar ─────────────────────────────────────────────────
        let header_frame = Frame::new()
            .fill(color::PANEL)
            .inner_margin(Margin::symmetric(SPACE_4 as i8, 0));
        egui::Panel::top("titlebar")
            .frame(header_frame)
            .show_separator_line(false)
            .exact_size(TITLEBAR_HEIGHT)
            .show(ui, |ui| self.title_bar(ui));

        // ── Bottom tab strip ───────────────────────────────────────────────
        let tab_frame = Frame::new()
            .fill(color::PANEL)
            .inner_margin(Margin::symmetric(SPACE_2 as i8, 0));
        egui::Panel::bottom("tabbar")
            .frame(tab_frame)
            .show_separator_line(true)
            .exact_size(TABBAR_HEIGHT)
            .show(ui, |ui| self.tab_bar(ui));

        // ── Action bar, sitting just above the tab strip ───────────────────
        if self.tab == Tab::Networks {
            let action_frame = Frame::new()
                .fill(color::PANEL)
                .inner_margin(Margin::symmetric(SPACE_4 as i8, 0));
            egui::Panel::bottom("actionbar")
                .frame(action_frame)
                .show_separator_line(false)
                .exact_size(ACTIONBAR_HEIGHT)
                .show(ui, |ui| self.action_bar(ui));
        }

        // ── Page ───────────────────────────────────────────────────────────
        let main_frame = Frame::new()
            .fill(color::CANVAS)
            .inner_margin(Margin::symmetric(SPACE_4 as i8, SPACE_3 as i8));
        egui::CentralPanel::default()
            .frame(main_frame)
            .show(ui, |ui| match self.tab {
                Tab::Networks => self.scrolling_page(ui, |app, ui| app.networks_page(ui)),
                Tab::Device => self.scrolling_page(ui, |app, ui| app.device_page(ui)),
            });

        // The fault sheet floats above everything, like a macOS alert.
        self.fault_sheet(&ctx);
        self.join_other_sheet(&ctx);
    }
}

impl Mt7601uApp {
    /// Wrap a page in a centred vertical scroll area whose contents stay
    /// left-aligned, so labels do not drift to the middle of the column.
    fn scrolling_page(&mut self, ui: &mut egui::Ui, page: impl FnOnce(&mut Self, &mut egui::Ui)) {
        egui::ScrollArea::vertical()
            .id_salt("page")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let width = ui.available_width().min(CONTENT_MAX_WIDTH);
                let gutter = ((ui.available_width() - width) * 0.5).max(0.0);
                ui.horizontal(|ui| {
                    ui.add_space(gutter);
                    ui.allocate_ui_with_layout(
                        vec2(width, 0.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.set_width(width);
                            ui.spacing_mut().item_spacing.y = SPACE_3;
                            page(self, ui);
                        },
                    );
                });
            });
    }

    // ------------------------------------------------------------ title bar

    /// The self-drawn title bar: just the window title, small and left-aligned
    /// clear of the traffic lights.
    fn title_bar(&mut self, ui: &mut egui::Ui) {
        let full = ui.max_rect();
        let drag = ui.interact(full, ui.id().with("titlebar-drag"), Sense::click_and_drag());
        if drag.drag_started() {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
        if drag.double_clicked() {
            let maximized = ui
                .ctx()
                .input(|input| input.viewport().maximized.unwrap_or(false));
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
        }

        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), ui.available_height()),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.add_space(self.titlebar_inset);
                ui.label(
                    RichText::new("Wi-Fi Networks")
                        .size(TEXT_SMALL)
                        .color(color::MUTED),
                );
            },
        );
    }

    // ------------------------------------------------------------- tab strip

    fn tab_bar(&mut self, ui: &mut egui::Ui) {
        let width = ui.available_width();
        let active = self.tab;
        ui.allocate_ui_with_layout(
            vec2(width, TABBAR_HEIGHT),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                let each = width / Tab::ALL.len() as f32;
                for tab in Tab::ALL {
                    let (rect, response) =
                        ui.allocate_exact_size(vec2(each, TABBAR_HEIGHT), Sense::click());
                    tab_button(ui, rect, tab, tab == active, response.hovered());
                    if response.clicked() {
                        self.tab = tab;
                    }
                }
            },
        );
    }

    // ------------------------------------------------------------ action bar

    fn action_bar(&mut self, ui: &mut egui::Ui) {
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), ACTIONBAR_HEIGHT),
            Layout::left_to_right(Align::Center),
            |ui| {
                if self.state.is_scanning() {
                    ui.label(
                        RichText::new("PHY: MediaTek MT7601U")
                            .monospace()
                            .size(TEXT_SMALL)
                            .color(color::MUTED),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new("Scanning 2.4 GHz channels · Active")
                                .size(TEXT_SMALL)
                                .strong()
                                .color(color::WARN),
                        );
                    });
                    return;
                }

                dot(ui, with_alpha(color::MUTED, 200));
                ui.add_space(SPACE_1);
                let count = self.state.networks.len();
                ui.label(
                    RichText::new(format!("{count} network{} in range", plural(count)))
                        .size(TEXT_SMALL)
                        .color(color::MUTED),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(quiet_button("Join Other…"))
                        .on_hover_text("Type a network name that is not listed")
                        .clicked()
                    {
                        self.join_other_open = true;
                        self.join_other_ssid.clear();
                        self.join_other_note = None;
                    }
                    ui.add_space(SPACE_2);
                    let blocker = scan_blocker(&self.state);
                    let scan = ui.add_enabled(blocker.is_none(), quiet_button("Scan"));
                    let scan = match blocker {
                        Some(reason) => scan.on_disabled_hover_text(reason),
                        None => scan.on_hover_text("Look for networks again (⌘R)"),
                    };
                    if scan.clicked() {
                        self.backend.send(Command::Scan);
                    }
                });
            },
        );
    }
}

// ------------------------------------------------------------- networks page

impl Mt7601uApp {
    /// The status-and-picker page: the live link headline, then the power switch
    /// and the networks the radio can hear. The throughput graph appears under
    /// the switch, and only while traffic is actually relaying. Scanning
    /// replaces the list with a live progress card and skeleton rows.
    fn networks_page(&mut self, ui: &mut egui::Ui) {
        let time = ui.input(|input| input.time) as f32;
        self.power_card(ui);
        self.link_hero(ui);
        if self.state.tunnel.is_running() {
            self.throughput_card(ui, time);
        }

        if let Some((title, message, tone)) = self.operation_problem() {
            let retry = self
                .last_attempt
                .clone()
                .or_else(|| self.state.link.as_ref().map(|link| link.ssid.clone()));
            let saved = retry.as_ref().is_some_and(|ssid| self.state.is_saved(ssid));
            let (mut reconnect, mut new_password) = (false, false);
            callout(ui, tone, title, &message, |ui| {
                let Some(ssid) = &retry else { return };
                ui.add_space(SPACE_2);
                ui.horizontal_wrapped(|ui| {
                    reconnect = ui
                        .add(quiet_button("Try again"))
                        .on_hover_text(format!("Try joining {ssid} again"))
                        .clicked();
                    if saved {
                        new_password = ui
                            .add(quiet_button("Enter a different password"))
                            .on_hover_text("Forget the saved one and ask again")
                            .clicked();
                    }
                });
            });
            if reconnect {
                if let Some(ssid) = retry.clone() {
                    self.backend.send(Command::Connect {
                        ssid,
                        password: None,
                        remember: true,
                    });
                }
            }
            if new_password {
                if let Some(ssid) = retry.as_deref() {
                    self.ask_for_a_new_passphrase(ssid);
                }
            }
        }

        if self.state.is_scanning() {
            self.scanning_card(ui);
            self.discovered_section(ui);
            return;
        }

        // Nothing to list while the radio is off: the hero already says so, so
        // stop after the power switch rather than showing an empty picker.
        if self.radio_off() {
            return;
        }

        self.known_section(ui);
        self.available_section(ui);
        if self.state.link.is_some() {
            self.link_card(ui);
        }
    }

    /// Whether the radio is fully off: not open, not scanning, not associated.
    fn radio_off(&self) -> bool {
        !self.state.device.is_open()
            && !self.state.is_scanning()
            && !self.state.is_connecting()
            && self.state.connected_ssid().is_none()
    }

    /// The power switch: adapter identity and a native on/off toggle. The
    /// headline above carries the state, so this card stays a single control.
    fn power_card(&mut self, ui: &mut egui::Ui) {
        let scanning = self.state.is_scanning();
        let adapter = adapter_name(&self.state);
        let on = power_on(&self.state);
        let subtitle = if scanning {
            format!("{adapter} · Monitoring")
        } else {
            format!("{adapter} · 802.11n")
        };
        let title = if scanning {
            "Wi-Fi Interface"
        } else {
            "Wi-Fi Power"
        };

        let mut toggle = on;
        let mut toggled = false;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
                let tone = if on { Tone::Active } else { Tone::Idle };
                glyph_tile(ui.painter(), rect, tone, Glyph::Wifi);
                ui.add_space(SPACE_3);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(title)
                                .size(TEXT_TITLE)
                                .strong()
                                .color(color::TEXT),
                        );
                        ui.add_space(SPACE_1);
                        chip(ui, "USB");
                    });
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(&subtitle)
                            .size(TEXT_SMALL)
                            .color(color::MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if toggle_switch(ui, &mut toggle).changed() {
                        toggled = true;
                    }
                });
            });
        });

        if toggled {
            let command = if toggle {
                Command::OpenDevice
            } else {
                Command::CloseDevice
            };
            self.backend.send(command);
        }
    }

    /// Saved networks that are currently in range, with one-click Connect.
    fn known_section(&mut self, ui: &mut egui::Ui) {
        let saved = self.state.saved.clone();
        let mut known: Vec<Network> = self
            .state
            .networks
            .iter()
            .filter(|network| saved.iter().any(|ssid| ssid == &network.ssid))
            .cloned()
            .collect();
        if known.is_empty() {
            return;
        }
        sort_by_signal(&mut known);

        section_header_row(
            ui,
            "Known Networks",
            color::WARN,
            Some(&format!("{}", known.len())),
        );
        ui.add_space(SPACE_2);

        let connected = self.state.connected_ssid().map(str::to_string);
        let connecting = match &self.state.wifi {
            WifiState::Connecting { ssid } => Some(ssid.clone()),
            _ => None,
        };
        let time = ui.input(|input| input.time) as f32;
        let mut clicked = None;
        card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (index, network) in known.iter().enumerate() {
                if index > 0 {
                    row_divider(ui);
                }
                let response = network_row(
                    ui,
                    network,
                    RowStyle::Known,
                    connected.as_deref() == Some(network.ssid.as_str()),
                    true,
                    connecting.as_deref() == Some(network.ssid.as_str()),
                    false,
                    time,
                );
                if response.clicked() {
                    clicked = Some(network.ssid.clone());
                }
            }
        });

        if let Some(ssid) = clicked {
            self.join(&ssid);
        }
    }

    /// Everything else the radio can hear, with the inline join control for
    /// secured networks without a saved passphrase.
    fn available_section(&mut self, ui: &mut egui::Ui) {
        let saved = self.state.saved.clone();
        let mut available: Vec<Network> = self
            .state
            .networks
            .iter()
            .filter(|network| !saved.iter().any(|ssid| ssid == &network.ssid))
            .cloned()
            .collect();

        if available.is_empty() {
            // Only the genuinely empty picker gets the empty-state card; when
            // known networks are listed above, an absent "available" section is
            // simply nothing to add.
            if !self.state.networks.is_empty() {
                return;
            }
            let empty = empty_picker_state(&self.state);
            ui.add_space(SPACE_2);
            if let Some(action) = empty_state(ui, &empty) {
                match action {
                    PickerAction::Start => self.backend.send(Command::OpenDevice),
                    PickerAction::Scan if scan_blocker(&self.state).is_none() => {
                        self.backend.send(Command::Scan)
                    }
                    PickerAction::Scan => {}
                }
            }
            return;
        }
        sort_by_signal(&mut available);

        section_header_row(
            ui,
            "Available Networks",
            color::ACCENT,
            Some(&format!("{} found", available.len())),
        );
        ui.add_space(SPACE_2);

        let connected = self.state.connected_ssid().map(str::to_string);
        let connecting = match &self.state.wifi {
            WifiState::Connecting { ssid } => Some(ssid.clone()),
            _ => None,
        };
        let expanded = self.state.awaiting_password.clone();
        let saved = self.state.saved.clone();
        let time = ui.input(|input| input.time) as f32;
        let mut clicked = None;
        card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (index, network) in available.iter().enumerate() {
                if index > 0 {
                    row_divider(ui);
                }
                let open = expanded.as_deref() == Some(network.ssid.as_str());
                let response = network_row(
                    ui,
                    network,
                    RowStyle::Available,
                    connected.as_deref() == Some(network.ssid.as_str()),
                    saved.iter().any(|ssid| ssid == &network.ssid),
                    connecting.as_deref() == Some(network.ssid.as_str()),
                    open,
                    time,
                );
                if response.clicked() {
                    clicked = Some(network.ssid.clone());
                }
                if open {
                    row_divider(ui);
                    self.inline_join_control(ui, network);
                }
            }
        });

        if let Some(ssid) = clicked {
            self.toggle_inline_join(&ssid);
        }
    }

    /// The macOS-style inline password control, shown under a secured row.
    fn inline_join_control(&mut self, ui: &mut egui::Ui, network: &Network) {
        let ssid = network.ssid.clone();
        ui.add_space(SPACE_3);
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(15.0), Sense::hover());
            lock_icon(ui.painter(), rect.center(), color::MUTED);
            ui.add_space(SPACE_1);
            ui.label(
                RichText::new(format!("Enter the password for “{ssid}”"))
                    .size(TEXT_SMALL)
                    .strong()
                    .color(color::TEXT),
            );
        });
        ui.add_space(SPACE_2);

        let mut join = false;
        let mut cancel = false;
        ui.horizontal(|ui| {
            let field_width = (ui.available_width() - 34.0).max(80.0);
            let field = ui.add(
                egui::TextEdit::singleline(&mut self.state.password_input)
                    .password(!self.show_password)
                    .hint_text("Password")
                    .desired_width(field_width),
            );
            if self.focus_password {
                field.request_focus();
                self.focus_password = false;
            }
            let submitted = field.lost_focus() && ui.ctx().input(|i| i.key_pressed(Key::Enter));
            if submitted {
                join = true;
            }
            ui.add_space(SPACE_1);
            if eye_button(ui, self.show_password)
                .on_hover_text(if self.show_password {
                    "Hide the password"
                } else {
                    "Show the password"
                })
                .clicked()
            {
                self.show_password = !self.show_password;
            }
        });

        ui.add_space(SPACE_2);
        ui.checkbox(
            &mut self.remember,
            RichText::new("Remember this network").size(TEXT_SMALL),
        );

        ui.add_space(SPACE_2);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let ready = !self.state.password_input.is_empty();
            let confirm = ui
                .add_enabled(ready, primary_button("Join"))
                .on_disabled_hover_text("Enter the password first")
                .clicked();
            if confirm {
                join = true;
            }
            ui.add_space(SPACE_2);
            if ui.add(quiet_button("Cancel")).clicked() {
                cancel = true;
            }
        });
        ui.add_space(SPACE_3);

        if cancel || ui.ctx().input(|input| input.key_pressed(Key::Escape)) {
            self.state.awaiting_password = None;
            self.state.password_input.clear();
            return;
        }
        if join && !self.state.password_input.is_empty() {
            let passphrase = std::mem::take(&mut self.state.password_input);
            self.state.awaiting_password = None;
            self.backend.send(Command::Connect {
                ssid,
                password: Some(passphrase),
                remember: self.remember,
            });
        }
    }

    /// The scanning state: a live progress card followed by what has been
    /// heard so far.
    fn scanning_card(&mut self, ui: &mut egui::Ui) {
        let time = ui.input(|input| input.time) as f32;
        let mut stop = false;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
                spinner_arc(ui.painter(), rect.center(), 10.0, 2.2, color::ACCENT, time);
                ui.add_space(SPACE_3);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("Scanning for available networks…")
                            .size(TEXT_BODY)
                            .strong()
                            .color(color::TEXT),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("Probing 802.11 b/g/n beacons…")
                            .size(TEXT_SMALL)
                            .color(color::MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(quiet_button("Stop Scan"))
                        .on_hover_text("Stop the radio and release the adapter")
                        .clicked()
                    {
                        stop = true;
                    }
                });
            });
            ui.add_space(SPACE_3);
            progress_bar(ui, time);
        });
        ui.ctx().request_repaint_after(Duration::from_millis(33));
        if stop {
            self.backend.send(Command::CloseDevice);
        }
    }

    /// The networks found so far, sorted by RSSI, with skeleton rows while the
    /// scan is still running.
    fn discovered_section(&mut self, ui: &mut egui::Ui) {
        let mut found = self.state.networks.clone();
        sort_by_signal(&mut found);

        section_header_row(
            ui,
            "Discovered Networks",
            color::WARN,
            Some(&format!("{} found", found.len())),
        );
        ui.add_space(SPACE_2);

        let connected = self.state.connected_ssid().map(str::to_string);
        let connecting = match &self.state.wifi {
            WifiState::Connecting { ssid } => Some(ssid.clone()),
            _ => None,
        };
        let expanded = self.state.awaiting_password.clone();
        let saved = self.state.saved.clone();
        let time = ui.input(|input| input.time) as f32;
        let empty = found.is_empty();
        let mut clicked = None;
        card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (index, network) in found.iter().enumerate() {
                if index > 0 {
                    row_divider(ui);
                }
                let open = expanded.as_deref() == Some(network.ssid.as_str());
                let response = network_row(
                    ui,
                    network,
                    RowStyle::Discovered,
                    connected.as_deref() == Some(network.ssid.as_str()),
                    saved.iter().any(|ssid| ssid == &network.ssid),
                    connecting.as_deref() == Some(network.ssid.as_str()),
                    open,
                    time,
                );
                if response.clicked() {
                    clicked = Some(network.ssid.clone());
                }
                if open {
                    row_divider(ui);
                    self.inline_join_control(ui, network);
                }
            }
            if !empty {
                row_divider(ui);
            }
            for _ in 0..3 {
                skeleton_row(ui, time);
            }
        });

        if let Some(ssid) = clicked {
            self.toggle_inline_join(&ssid);
        }
    }
}

// --------------------------------------------------------------- link hero

impl Mt7601uApp {
    /// The headline on the Networks page: the relay state, the two live rates
    /// and the relay glyph. Uncarded, so the page opens on the live status and
    /// the network list follows.
    fn link_hero(&mut self, ui: &mut egui::Ui) {
        let off = self.radio_off();
        let traffic = self.state.traffic;
        let running = !off && self.state.tunnel.is_running();
        let (title, tone): (String, Tone) = if off {
            ("Wi-Fi Off".into(), Tone::Idle)
        } else {
            let (label, tone) = tunnel_summary(&self.state);
            (label.into(), tone)
        };
        let subtitle = if off {
            "Turn on Wi-Fi Power to scan for networks.".to_string()
        } else {
            tunnel_subtitle(&self.state)
        };

        ui.add_space(SPACE_1);
        ui.horizontal(|ui| {
            // let (rect, _) = ui.allocate_exact_size(Vec2::splat(HERO_GLYPH), Sense::hover());
            // glyph_tile(ui.painter(), rect, tone, Glyph::Wifi);
            ui.add_space(SPACE_3);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(title)
                        .size(TEXT_DISPLAY)
                        .strong()
                        .color(tone.color()),
                );
                ui.add_space(2.0);
                ui.label(RichText::new(subtitle).size(TEXT_SMALL).color(color::MUTED));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.vertical(|ui| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(if running {
                                format_rate(traffic.down_bytes_per_sec)
                            } else {
                                "—".into()
                            })
                            .size(TEXT_DISPLAY)
                            .monospace()
                            .strong()
                            .color(color::DOWN),
                        );
                        ui.add_space(SPACE_1);
                        ui.label(
                            RichText::new("↓")
                                .size(TEXT_HEAD)
                                .color(with_alpha(color::DOWN, 200)),
                        );
                    });
                    ui.add_space(2.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(if running {
                                format_rate(traffic.up_bytes_per_sec)
                            } else {
                                "—".into()
                            })
                            .size(TEXT_SMALL)
                            .monospace()
                            .color(color::UP),
                        );
                        ui.add_space(SPACE_1);
                        ui.label(
                            RichText::new("↑")
                                .size(TEXT_SMALL)
                                .color(with_alpha(color::UP, 200)),
                        );
                    });
                });
            });
        });
    }

    /// The live graph with the cumulative transfer counters beneath it. Only
    /// drawn while the tunnel is relaying, so there is no idle state to label.
    fn throughput_card(&mut self, ui: &mut egui::Ui, time: f32) {
        let down = self.state.down_history.iter().copied().collect::<Vec<_>>();
        let up = self.state.up_history.iter().copied().collect::<Vec<_>>();
        let traffic = self.state.traffic;

        card(ui, |ui| {
            ui.label(
                RichText::new("THROUGHPUT")
                    .size(TEXT_MICRO)
                    .strong()
                    .color(color::MUTED)
                    .extra_letter_spacing(0.8),
            );
            ui.add_space(SPACE_3);
            let (rect, _) =
                ui.allocate_exact_size(vec2(ui.available_width(), 96.0), Sense::hover());
            graph(ui.painter(), rect, &down, &up, time, true);
            ui.add_space(SPACE_3);
            ui.horizontal(|ui| {
                legend(ui, color::DOWN, "Download");
                ui.add_space(SPACE_3);
                legend(ui, color::UP, "Upload");
            });
            ui.add_space(SPACE_3);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = SPACE_4;
                telemetry_item(ui, "Received", &format_bytes(traffic.to_tun_bytes));
                telemetry_item(ui, "Sent", &format_bytes(traffic.to_link_bytes));
                telemetry_item(ui, "In packets", &format_count(traffic.to_tun_packets));
                telemetry_item(ui, "Out packets", &format_count(traffic.to_link_packets));
            });
        });
    }

    /// Everything the hero does not already show: the association, the local
    /// addressing and the tunnel, in one card.
    fn link_card(&self, ui: &mut egui::Ui) {
        let Some(link) = self.state.link.as_ref() else {
            return;
        };
        let (label, tone) = tunnel_summary(&self.state);
        let channel = link
            .channel
            .map(|channel| channel.to_string())
            .unwrap_or_else(|| "—".into());
        let bssid = link.bssid_string().unwrap_or_else(|| "—".into());
        let ip = link
            .ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "obtaining…".into());
        let interface = link.interface.clone().unwrap_or_else(|| "—".into());
        let router = link
            .router
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "—".into());
        let dns = if link.dns.is_empty() {
            "—".to_string()
        } else {
            link.dns
                .iter()
                .map(|server| server.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        card(ui, |ui| {
            ui.horizontal(|ui| {
                dot(ui, tone.color());
                ui.add_space(SPACE_2);
                ui.label(
                    RichText::new("Connection")
                        .size(TEXT_TITLE)
                        .strong()
                        .color(color::TEXT),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(label).size(TEXT_SMALL).color(tone.color()));
                });
            });
            ui.add_space(SPACE_3);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = SPACE_4;
                telemetry_item(ui, "Channel", &channel);
                telemetry_item(ui, "Security", link.security.label());
                telemetry_item(ui, "BSSID", &bssid);
                telemetry_item(ui, "Local IP", &ip);
            });
            ui.add_space(SPACE_3);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = SPACE_4;
                telemetry_item(ui, "Interface", &interface);
                telemetry_item(ui, "Router", &router);
                telemetry_item(ui, "DNS", &dns);
            });
        });
    }
}

// -------------------------------------------------------------- device page

impl Mt7601uApp {
    /// The USB device and the switches that shape how it runs — the things a
    /// user sets once rather than watches.
    fn device_page(&mut self, ui: &mut egui::Ui) {
        self.device_hero(ui);
        self.settings_card(ui);
    }

    /// The adapter identity, uncarded so it matches the Networks headline. The
    /// status line sits under the name rather than crowding in beside it.
    fn device_hero(&mut self, ui: &mut egui::Ui) {
        let (name, bus, identity) = device_summary(&self.state);
        let open = self.state.device.is_open();
        let status = self.state.device.label();
        let scanning = self.state.is_scanning();
        let mut toggle: Option<Command> = None;
        let mut identify = false;

        ui.add_space(SPACE_1);
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(HERO_GLYPH), Sense::hover());
            let tone = if open { Tone::Device } else { Tone::Idle };
            glyph_tile(ui.painter(), rect, tone, Glyph::Wifi);
            ui.add_space(SPACE_3);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(name)
                        .size(TEXT_DISPLAY)
                        .strong()
                        .color(color::TEXT),
                );
                ui.add_space(2.0);
                ui.label(RichText::new(status).size(TEXT_SMALL).color(color::MUTED));
            });
        });
        ui.add_space(SPACE_2);
        ui.label(RichText::new(bus).size(TEXT_SMALL).color(color::MUTED));
        ui.add_space(SPACE_1);
        ui.label(
            RichText::new(identity)
                .monospace()
                .size(TEXT_SMALL)
                .color(color::FAINT),
        );
        ui.add_space(SPACE_3);
        ui.horizontal(|ui| {
            let label = if open { "Close Device" } else { "Open Device" };
            if ui.add(quiet_button(label)).clicked() {
                toggle = Some(if open {
                    Command::CloseDevice
                } else {
                    Command::OpenDevice
                });
            }
            if ui
                .add_enabled(open, quiet_button("Identify"))
                .on_disabled_hover_text("Open the device first")
                .on_hover_text("Blink the dongle's LED")
                .clicked()
            {
                identify = true;
            }
            if scanning {
                ui.add_space(SPACE_1);
                ui.label(
                    RichText::new("scanning…")
                        .size(TEXT_SMALL)
                        .color(color::WARN),
                );
            }
        });

        if let Some(command) = toggle {
            self.backend.send(command);
        }
        if identify {
            self.backend.send(Command::Identify);
        }
    }

    /// The three switches that shape the run — the privileged helper, how the
    /// interface is addressed, and whether to reconnect on its own. Each is a
    /// title with its switch, then a line of prose explaining the switch.
    fn settings_card(&mut self, ui: &mut egui::Ui) {
        let root = crate::tunnel::is_root();
        let helper = self.helper_available;
        let busy = self.helper_job.is_some();
        let problem = self.state.manual_problem.clone();
        let parsed = self.state.manual_addressing().ok();

        let mut helper_on = root || helper;
        // The switch reflects the user's intent, not just the backend state: the
        // manual choice only reaches the backend on Save, so keep it locally.
        if !self.manual_editor && !self.manual_mode && !self.state.addressing.is_dhcp() {
            self.manual_mode = true;
        }
        let mut dhcp = !self.manual_mode;
        let mut auto = self.state.auto_connect;
        let (mut helper_toggle, mut addressing_toggle, mut auto_toggle, mut apply) =
            (false, false, false, false);

        card(ui, |ui| {
            // ── The privileged helper ──
            if switch_row(ui, helper_title(root, helper), &mut helper_on, !root) {
                helper_toggle = true;
            }
            ui.add_space(SPACE_1);
            ui.label(
                RichText::new(helper_info(root, helper, busy))
                    .size(TEXT_SMALL)
                    .color(color::MUTED),
            );

            row_divider(ui);

            // ── Addressing ──
            let addressing_title = if dhcp {
                "Automatic Addressing"
            } else {
                "Manual Addressing"
            };
            if switch_row(ui, addressing_title, &mut dhcp, true) {
                addressing_toggle = true;
            }
            ui.add_space(SPACE_1);
            ui.label(
                RichText::new(if dhcp {
                    "The router hands the interface its address, gateway and DNS (DHCP)."
                } else {
                    "Set the address, gateway and DNS the USB interface should use."
                })
                .size(TEXT_SMALL)
                .color(color::MUTED),
            );

            if self.manual_editor {
                ui.add_space(SPACE_2);
                Frame::new()
                    .fill(color::CANVAS)
                    .stroke(Stroke::new(1.0, color::HAIRLINE))
                    .corner_radius(CornerRadius::same(RADIUS_SM))
                    .inner_margin(Margin::same(SPACE_3 as i8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.spacing_mut().item_spacing.y = SPACE_2;
                        field(
                            ui,
                            "Address",
                            &mut self.state.manual_address,
                            "192.168.43.5",
                        );
                        field(
                            ui,
                            "Gateway",
                            &mut self.state.manual_gateway,
                            "192.168.43.1",
                        );
                        field(ui, "DNS", &mut self.state.manual_dns, "8.8.8.8, 1.1.1.1");
                        if let Some(problem) = &problem {
                            ui.add_space(SPACE_1);
                            ui.label(RichText::new(problem).size(TEXT_SMALL).color(color::ERROR));
                        }
                        ui.add_space(SPACE_1);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .add_enabled(parsed.is_some(), primary_button("Save"))
                                .on_disabled_hover_text("Fill every field with a valid address")
                                .clicked()
                            {
                                apply = true;
                            }
                        });
                    });
            }

            row_divider(ui);

            // ── Reconnect automatically ──
            if switch_row(ui, "Connect Automatically", &mut auto, true) {
                auto_toggle = true;
            }
            ui.add_space(SPACE_1);
            ui.label(
                RichText::new(
                    "Rejoin the last network on its own when the adapter hears it again.",
                )
                .size(TEXT_SMALL)
                .color(color::MUTED),
            );
        });

        if helper_toggle {
            let ctx = ui.ctx().clone();
            let job = if helper_on {
                HelperJob::Install
            } else {
                HelperJob::Uninstall
            };
            self.start_helper_job(job, &ctx);
        }
        if addressing_toggle {
            // The switch was flipped: remember the intent and open or close the
            // editor. Only the automatic choice is applied straight away.
            self.manual_mode = !dhcp;
            self.manual_editor = !dhcp;
            if dhcp {
                self.backend.send(Command::SetAddressing(Addressing::Dhcp));
            }
        }
        if apply {
            if let Ok(addressing) = self.state.manual_addressing() {
                self.backend.send(Command::SetAddressing(addressing));
            }
            // The values are in force; fold the editor away again.
            self.manual_editor = false;
        }
        if auto_toggle {
            self.backend.send(Command::SetAutoConnect(auto));
        }
    }
}

// ----------------------------------------------------------------- logs page
//
// The activity console is hidden from users. The code is kept, commented out,
// so it can be restored if an in-app log ever needs to be shown again.
//
// impl Mt7601uApp {
//     /// The activity console: a filter row, the scrolling lines and the export
//     /// controls.
//     fn logs_page(&mut self, ui: &mut egui::Ui) {
//         ui.set_max_width(ui.available_width().min(CONTENT_MAX_WIDTH + 120.0));
//         self.log_filter_row(ui);
//         ui.add_space(SPACE_2);
//         self.log_console(ui);
//         ui.add_space(SPACE_2);
//         self.log_actions(ui);
//     }
//
//     fn log_filter_row(&mut self, ui: &mut egui::Ui) {
//         let running = self.backend.is_running();
//         card(ui, |ui| {
//             ui.horizontal(|ui| {
//                 for filter in LogFilter::ALL {
//                     let active = self.log_filter == filter;
//                     if filter_pill(ui, filter.label(), active).clicked() {
//                         self.log_filter = filter;
//                     }
//                 }
//                 ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
//                     let total = self.state.logs.len();
//                     ui.label(
//                         RichText::new(format!("{} lines", format_count(total as u64)))
//                             .size(TEXT_SMALL)
//                             .color(color::MUTED),
//                     );
//                     ui.add_space(SPACE_2);
//                     dot(
//                         ui,
//                         if running { color::OK } else { color::WARN },
//                     );
//                 });
//             });
//         });
//     }
//
//     fn log_console(&mut self, ui: &mut egui::Ui) {
//         let filter = self.log_filter;
//         let lines: Vec<LogLine> = self
//             .state
//             .logs
//             .iter()
//             .filter(|line| filter.accepts(line.level))
//             .cloned()
//             .collect();
//         let auto_scroll = self.state.auto_scroll_logs;
//
//         let frame = Frame::new()
//             .fill(color::CANVAS)
//             .stroke(Stroke::new(1.0, color::HAIRLINE))
//             .corner_radius(CornerRadius::same(RADIUS_MD))
//             .inner_margin(Margin::same(SPACE_3 as i8));
//         frame.show(ui, |ui| {
//             ui.set_min_height(260.0);
//             let mut area = egui::ScrollArea::vertical()
//                 .id_salt("log-console")
//                 .auto_shrink(false);
//             if auto_scroll {
//                 area = area.stick_to_bottom(true);
//             }
//             area.show(ui, |ui| {
//                 ui.spacing_mut().item_spacing.y = SPACE_1;
//                 // Wrap long lines rather than letting them run off the edge; a
//                 // log line is prose once it is longer than the pane is wide.
//                 let wrap = ui.available_width();
//                 for line in &lines {
//                     let font = FontId::monospace(TEXT_MONO);
//                     let mut job = egui::text::LayoutJob::default();
//                     job.wrap.max_width = wrap;
//                     job.append(
//                         line.level.tag(),
//                         0.0,
//                         egui::TextFormat {
//                             font_id: font.clone(),
//                             color: level_colour(line.level),
//                             ..Default::default()
//                         },
//                     );
//                     job.append(
//                         " ",
//                         0.0,
//                         egui::TextFormat {
//                             font_id: font.clone(),
//                             color: color::TEXT,
//                             ..Default::default()
//                         },
//                     );
//                     job.append(
//                         &line.message,
//                         0.0,
//                         egui::TextFormat {
//                             font_id: font,
//                             color: color::TEXT,
//                             ..Default::default()
//                         },
//                     );
//                     ui.label(job);
//                 }
//             });
//         });
//     }
//
//     fn log_actions(&mut self, ui: &mut egui::Ui) {
//         let mut copy = false;
//         let mut export = false;
//         card(ui, |ui| {
//             ui.horizontal(|ui| {
//                 ui.checkbox(
//                     &mut self.state.auto_scroll_logs,
//                     RichText::new("Follow output").size(TEXT_SMALL),
//                 );
//                 ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
//                     if ui.add(quiet_button("Export…")).clicked() {
//                         export = true;
//                     }
//                     ui.add_space(SPACE_2);
//                     if ui.add(quiet_button("Copy")).clicked() {
//                         copy = true;
//                     }
//                     if let Some(status) = &self.export_status {
//                         ui.add_space(SPACE_2);
//                         ui.label(
//                             RichText::new(status)
//                                 .size(TEXT_SMALL)
//                                 .color(color::OK),
//                         );
//                     }
//                 });
//             });
//         });
//
//         if copy {
//             let text = self.state.logs.as_text();
//             ui.ctx().copy_text(text);
//             self.export_status = Some("Copied".into());
//         }
//         if export {
//             self.export_status = Some(export_logs(&self.state.logs));
//         }
//     }
// }

// ------------------------------------------------------------------- sheets

/// Which list a network row belongs to; it decides the trailing affordance and
/// the accent used for the signal mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowStyle {
    Known,
    Available,
    Discovered,
}

/// The action offered by the empty-state card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PickerAction {
    /// Open the radio and start the first scan.
    Start,
    /// Run another scan (the radio is already open).
    Scan,
}

/// What the picker shows when there is nothing to list.
#[derive(Debug, Clone)]
struct EmptyPicker {
    title: String,
    message: String,
    action: Option<PickerAction>,
    tone: Tone,
}

impl Mt7601uApp {
    /// The fault sheet: a native-looking alert for the problems that stop the
    /// user, with the recovery actions inline. Dismissing remembers the message
    /// so an unchanged fault does not nag every frame.
    fn fault_sheet(&mut self, ctx: &egui::Context) {
        let Some((title, message, tone)) = self.fault_message() else {
            return;
        };
        if self.alert_dismissed.as_deref() == Some(message.as_str()) {
            return;
        }

        let (mut replug, mut privacy, mut dismiss) = (false, false, false);
        let response = Modal::new(egui::Id::new("fault-sheet")).show(ctx, |ui| {
            ui.set_width(360.0);
            alert_sheet(ui, tone, title, &message);
            ui.add_space(SPACE_4);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(primary_button("Re-plug & Retry")).clicked() {
                    replug = true;
                }
                ui.add_space(SPACE_2);
                if ui.add(quiet_button("Privacy Settings…")).clicked() {
                    privacy = true;
                }
                ui.add_space(SPACE_2);
                if ui.add(quiet_button("Dismiss")).clicked() {
                    dismiss = true;
                }
            });
        });
        if response.should_close() {
            dismiss = true;
        }

        if replug {
            self.alert_dismissed = None;
            self.backend.send(Command::RefreshDevice);
            self.backend.send(Command::OpenDevice);
        }
        if privacy {
            open_privacy_settings();
        }
        if dismiss {
            self.alert_dismissed = Some(message);
        }
    }

    /// The standing fault, if one would block the user.
    fn fault_message(&self) -> Option<(&'static str, String, Tone)> {
        if let Some(reason) = &self.state.replug {
            return Some(("Re-plug the adapter", reason.clone(), Tone::Bad));
        }
        if let Some(reason) = &self.state.device_problem {
            return Some(("Cannot open the device", reason.clone(), Tone::Bad));
        }
        match &self.state.wifi {
            WifiState::Error(error) if !self.state.device.is_open() => {
                return Some(("Wi-Fi unavailable", error.clone(), Tone::Bad));
            }
            _ => {}
        }
        if let TunnelState::Error(error) = &self.state.tunnel {
            return Some(("Tunnel error", error.clone(), Tone::Bad));
        }
        None
    }

    /// The inline operation problem shown on the picker: a join or association
    /// failure the user can retry without a whole sheet.
    fn operation_problem(&self) -> Option<(&'static str, String, Tone)> {
        if let WifiState::Error(error) = &self.state.wifi {
            if self.state.device.is_open() && !self.state.is_scanning() {
                return Some(("Could not connect", error.clone(), Tone::Bad));
            }
        }
        None
    }

    /// The "Join Other…" sheet: type an SSID that may be hidden.
    fn join_other_sheet(&mut self, ctx: &egui::Context) {
        if !self.join_other_open {
            return;
        }
        let (mut join, mut close) = (false, false);
        let response = Modal::new(egui::Id::new("join-other")).show(ctx, |ui| {
            ui.set_width(340.0);
            ui.label(
                RichText::new("Join Other Network")
                    .size(TEXT_TITLE)
                    .strong()
                    .color(color::TEXT),
            );
            ui.add_space(SPACE_1);
            ui.label(
                RichText::new(
                    "Type the exact network name (SSID). If it is secured, you will be asked for its password.",
                )
                .size(TEXT_SMALL)
                .color(color::MUTED),
            );
            ui.add_space(SPACE_3);
            let field = ui.add(
                egui::TextEdit::singleline(&mut self.join_other_ssid)
                    .hint_text("Network name")
                    .desired_width(f32::INFINITY),
            );
            if let Some(note) = &self.join_other_note {
                ui.add_space(SPACE_2);
                ui.label(RichText::new(note).size(TEXT_SMALL).color(color::ERROR));
            }
            ui.add_space(SPACE_3);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(
                        !self.join_other_ssid.trim().is_empty(),
                        primary_button("Join"),
                    )
                    .clicked()
                {
                    join = true;
                }
                ui.add_space(SPACE_2);
                if ui.add(quiet_button("Cancel")).clicked() {
                    close = true;
                }
            });
            field
        });
        response.inner.request_focus();
        if response.should_close() {
            close = true;
        }

        if join {
            let ssid = self.join_other_ssid.trim().to_string();
            if self.state.network(&ssid).is_some() {
                self.join_other_open = false;
                self.join(&ssid);
            } else {
                self.join_other_note = Some(format!(
                    "“{ssid}” is not in range. Scan again or check the spelling."
                ));
            }
        }
        if close {
            self.join_other_open = false;
        }
    }
}

// ------------------------------------------------------------ state helpers

/// One settings row: a title on the left and its switch on the right. Returns
/// whether the switch was flipped. The switch is greyed and inert when
/// `enabled` is false (e.g. the helper is moot while running as root).
fn switch_row(ui: &mut egui::Ui, title: &str, on: &mut bool, enabled: bool) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(title)
                .size(TEXT_HEAD)
                .strong()
                .color(color::TEXT),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            changed = ui
                .add_enabled_ui(enabled, |ui| toggle_switch(ui, on).changed())
                .inner;
        });
    });
    changed
}

/// The helper switch's title, from the privilege the app actually holds.
fn helper_title(root: bool, helper: bool) -> &'static str {
    if root {
        "Running as Root"
    } else if helper {
        "Helper Installed"
    } else {
        "Helper Not Installed"
    }
}

/// The prose under the helper switch.
fn helper_info(root: bool, helper: bool, busy: bool) -> &'static str {
    if busy {
        "Waiting for the administrator prompt…"
    } else if root {
        "The app already runs with administrator rights, so no helper is needed."
    } else if helper {
        "The helper is installed, so the tunnel is created without a password. Turn this off to remove it."
    } else {
        "Install the helper once so the tunnel can be created without your password each time."
    }
}

/// The tunnel's headline label and tone.
fn tunnel_summary(state: &AppState) -> (&'static str, Tone) {
    match &state.tunnel {
        TunnelState::Running { .. } => ("Relaying", Tone::Good),
        TunnelState::Starting => ("Starting", Tone::Active),
        TunnelState::Error(_) => ("Tunnel error", Tone::Bad),
        TunnelState::Stopped => {
            if state.connected_ssid().is_some() {
                ("Standing by", Tone::Caution)
            } else {
                ("Idle", Tone::Idle)
            }
        }
    }
}

/// The line under the tunnel headline.
fn tunnel_subtitle(state: &AppState) -> String {
    match &state.tunnel {
        TunnelState::Running { .. } => {
            let ssid = state
                .link
                .as_ref()
                .map(|link| link.ssid.clone())
                .or_else(|| state.connected_ssid().map(str::to_string))
                .unwrap_or_else(|| "the network".into());
            format!("Relaying between {ssid} and macOS")
        }
        TunnelState::Starting => "Creating the utun interface…".into(),
        TunnelState::Error(error) => error.clone(),
        TunnelState::Stopped => {
            if state.connected_ssid().is_some() {
                "Waiting to relay traffic".into()
            } else {
                "Not relaying".into()
            }
        }
    }
}

/// Whether the radio is on, from the user's point of view.
fn power_on(state: &AppState) -> bool {
    state.device.is_open()
        || state.is_scanning()
        || state.is_connecting()
        || state.connected_ssid().is_some()
}

/// The adapter's marketing name, from the USB descriptors when we have them.
fn adapter_name(state: &AppState) -> String {
    match state.device.info() {
        Some(info) => info
            .product
            .clone()
            .or_else(|| info.manufacturer.clone())
            .unwrap_or_else(|| "MT7601U".into()),
        None => "MT7601U".into(),
    }
}

/// The device card's three lines: name, bus line and an identity string.
fn device_summary(state: &AppState) -> (String, String, String) {
    let name = adapter_name(state);
    match state.device.info() {
        Some(info) => {
            let bus = format!(
                "Bus {} · Address {} · {}",
                info.bus,
                info.address,
                info.speed.label()
            );
            let identity = format!(
                "VID {:04x}  PID {:04x}  driver {}",
                info.vid,
                info.pid,
                concat!("v", env!("CARGO_PKG_VERSION")),
            );
            (name, bus, identity)
        }
        None => (
            name,
            "Not detected".into(),
            "Plug the MT7601U into a USB port".into(),
        ),
    }
}

/// Why a scan cannot be started right now, if it cannot.
fn scan_blocker(state: &AppState) -> Option<&'static str> {
    if state.replug.is_some() {
        return Some("Re-plug the adapter first");
    }
    if state.device_problem.is_some() {
        return Some("The device is locked by another process");
    }
    if state.is_scanning() {
        return Some("A scan is already running");
    }
    if state.is_connecting() {
        return Some("Finish connecting first");
    }
    if !state.device.is_open() {
        return Some("Open the device first");
    }
    None
}

/// Whether the station can join this security mode.
fn security_supported(security: &Security) -> bool {
    !matches!(security, Security::Unknown)
}

/// The signal mark's tone, from the RSSI when we have one.
fn signal_tone(dbm: Option<i32>) -> Tone {
    match dbm {
        None => Tone::Idle,
        Some(dbm) if dbm >= -55 => Tone::Good,
        Some(dbm) if dbm >= -70 => Tone::Caution,
        Some(_) => Tone::Bad,
    }
}

/// How many of the four signal bars are lit, `0..=4`.
fn signal_level(dbm: Option<i32>) -> u8 {
    match dbm {
        None => 0,
        Some(dbm) if dbm >= -55 => 4,
        Some(dbm) if dbm >= -65 => 3,
        Some(dbm) if dbm >= -75 => 2,
        _ => 1,
    }
}

/// Strongest first, unknown RSSI last.
fn sort_by_signal(networks: &mut [Network]) {
    networks.sort_by(|a, b| {
        b.signal_dbm
            .unwrap_or(i32::MIN)
            .cmp(&a.signal_dbm.unwrap_or(i32::MIN))
    });
}

/// The plural suffix for a count.
fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

// /// The colour of a log tag.
// fn level_colour(level: LogLevel) -> Color32 {
//     match level {
//         LogLevel::Debug => color::FAINT,
//         LogLevel::Info => color::ACCENT,
//         LogLevel::Warn => color::WARN,
//         LogLevel::Error => color::ERROR,
//     }
// }

/// What the picker shows when there is nothing to list.
fn empty_picker_state(state: &AppState) -> EmptyPicker {
    if state.replug.is_some() {
        return EmptyPicker {
            title: "Adapter needs a re-plug".into(),
            message: state
                .replug
                .clone()
                .unwrap_or_else(|| "Unplug and plug the dongle back in.".into()),
            action: None,
            tone: Tone::Bad,
        };
    }
    if state.device_problem.is_some() {
        return EmptyPicker {
            title: "Cannot open the device".into(),
            message: state
                .device_problem
                .clone()
                .unwrap_or_else(|| "Close any other program using the dongle.".into()),
            action: None,
            tone: Tone::Bad,
        };
    }
    if !state.device.is_open() {
        return EmptyPicker {
            title: "No networks yet".into(),
            message: "Open the radio to scan for nearby Wi-Fi networks.".into(),
            action: Some(PickerAction::Start),
            tone: Tone::Idle,
        };
    }
    EmptyPicker {
        title: "Nothing in range".into(),
        message: "No access points answered the last scan. Try again.".into(),
        action: Some(PickerAction::Scan),
        tone: Tone::Idle,
    }
}

// /// Write the log buffer to a stamped file, returning a human-readable result.
// fn export_logs(logs: &LogBuffer) -> String {
//     let dir = crate::paths::data_dir();
//     if let Err(error) = std::fs::create_dir_all(&dir) {
//         return format!("export failed: {error}");
//     }
//     let stamp = std::time::SystemTime::now()
//         .duration_since(std::time::UNIX_EPOCH)
//         .map(|elapsed| elapsed.as_secs())
//         .unwrap_or(0);
//     let path = dir.join(format!("mt7601u-log-{stamp}.txt"));
//     match std::fs::write(&path, logs.as_text()) {
//         Ok(()) => format!("Saved to {}", path.display()),
//         Err(error) => format!("export failed: {error}"),
//     }
// }

/// Open the macOS Privacy & Security pane, where Full Disk / Input Monitoring
/// style permissions live.
fn open_privacy_settings() {
    let _ = std::process::Command::new("open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy")
        .spawn();
}

// ------------------------------------------------------------ small pieces

/// The glyph drawn inside a tinted tile.
#[derive(Debug, Clone, Copy)]
enum Glyph {
    Wifi,
}

/// A grouped content card: the macOS `2c2c2e` surface, one hairline and a
/// large corner radius.
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    Frame::new()
        .fill(color::SURFACE)
        .stroke(Stroke::new(1.0, color::HAIRLINE))
        .corner_radius(CornerRadius::same(RADIUS_LG))
        .inner_margin(Margin::same(SPACE_3 as i8))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = SPACE_2;
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A tinted inline notice with optional recovery actions.
fn callout(
    ui: &mut egui::Ui,
    tone: Tone,
    title: &str,
    message: &str,
    add_actions: impl FnOnce(&mut egui::Ui),
) {
    Frame::new()
        .fill(tone.tint())
        .stroke(Stroke::new(1.0, tone.edge()))
        .corner_radius(CornerRadius::same(RADIUS_MD))
        .inner_margin(Margin::same(SPACE_3 as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.add_space(SPACE_1);
                dot(ui, tone.color());
                ui.add_space(SPACE_2);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(title)
                            .size(TEXT_BODY)
                            .strong()
                            .color(color::TEXT),
                    );
                    ui.label(RichText::new(message).size(TEXT_SMALL).color(color::MUTED));
                });
            });
            add_actions(ui);
        });
}

/// The body of the fault alert: a centred glyph rubric and two lines.
fn alert_sheet(ui: &mut egui::Ui, tone: Tone, title: &str, message: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(SPACE_2);
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(HERO_GLYPH), Sense::hover());
        glyph_tile(ui.painter(), rect, tone, Glyph::Wifi);
        ui.add_space(SPACE_3);
        ui.label(
            RichText::new(title)
                .size(TEXT_TITLE)
                .strong()
                .color(color::TEXT),
        );
        ui.add_space(SPACE_1);
        ui.label(RichText::new(message).size(TEXT_SMALL).color(color::MUTED));
    });
}

/// A neutral, text-only button that takes the default SSH chrome.
fn quiet_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).size(TEXT_BODY)).min_size(vec2(0.0, CONTROL_HEIGHT))
}

/// The default action: the soft blue macOS uses for "the one button you mean".
fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text)
            .size(TEXT_BODY)
            .strong()
            .color(color::ACCENT_SOFT_INK),
    )
    .fill(color::ACCENT_SOFT)
    .stroke(Stroke::NONE)
    .min_size(vec2(0.0, CONTROL_HEIGHT))
}

/// A pill-shaped, non-interactive tag.
fn chip(ui: &mut egui::Ui, text: &str) {
    Frame::new()
        .fill(color::RAISED)
        .corner_radius(CornerRadius::same(RADIUS_PILL))
        .inner_margin(Margin::symmetric(SPACE_2 as i8, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text.to_uppercase())
                    .size(TEXT_MICRO)
                    .strong()
                    .color(color::MUTED)
                    .extra_letter_spacing(0.5),
            );
        });
}

/// A little status dot.
fn dot(ui: &mut egui::Ui, colour: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 3.5, colour);
}

/// A tab-strip item: glyph over label with an underline marker on the active
/// tab. Deliberately not a filled button — it should read as a tab.
fn tab_button(ui: &mut egui::Ui, rect: Rect, tab: Tab, active: bool, hovered: bool) {
    let painter = ui.painter();
    let colour = if active {
        color::ACCENT
    } else if hovered {
        color::TEXT
    } else {
        color::MUTED
    };
    tab_glyph(
        painter,
        pos2(rect.center().x, rect.top() + 20.0),
        tab,
        colour,
    );
    painter.text(
        pos2(rect.center().x, rect.bottom() - 13.0),
        Align2::CENTER_CENTER,
        tab.label(),
        FontId::proportional(TEXT_MICRO),
        colour,
    );
    if active {
        let y = rect.bottom() - 4.0;
        let bar = Rect::from_min_max(
            pos2(rect.center().x - 13.0, y),
            pos2(rect.center().x + 13.0, y + 2.0),
        );
        painter.rect_filled(bar, CornerRadius::same(1), color::ACCENT);
    }
}

/// The three tab glyphs, drawn to a 20×20 box centred on `center`.
fn tab_glyph(painter: &egui::Painter, center: egui::Pos2, tab: Tab, colour: Color32) {
    let stroke = Stroke::new(1.6, colour);
    match tab {
        Tab::Networks => wifi_arcs(painter, pos2(center.x, center.y + 7.0), 22.0, 1.6, colour),
        Tab::Device => {
            let body = Rect::from_center_size(center, vec2(14.0, 8.0));
            painter.rect_stroke(
                body,
                CornerRadius::same(RADIUS_SM),
                stroke,
                StrokeKind::Inside,
            );
            painter.line_segment(
                [
                    pos2(body.right(), center.y),
                    pos2(body.right() + 5.0, center.y),
                ],
                stroke,
            );
        }
    }
}

/// Three concentric arcs opening upward, from `base`.
fn wifi_arcs(
    painter: &egui::Painter,
    base: egui::Pos2,
    width: f32,
    stroke_w: f32,
    colour: Color32,
) {
    let stroke = Stroke::new(stroke_w, colour);
    for scale in [0.34_f32, 0.64, 0.94] {
        let radius = width * 0.5 * scale;
        let points: Vec<egui::Pos2> = (0..=16)
            .map(|step| {
                let angle = 34.0 + 112.0 * (step as f32 / 16.0);
                let radians = angle.to_radians();
                pos2(
                    base.x - radius * radians.cos(),
                    base.y - radius * radians.sin(),
                )
            })
            .collect();
        painter.add(egui::Shape::line(points, stroke));
    }
    painter.circle_filled(base, stroke_w, colour);
}

/// A 40-point tinted tile with a glyph in the middle.
fn glyph_tile(painter: &egui::Painter, rect: Rect, tone: Tone, glyph: Glyph) {
    painter.rect_filled(rect, CornerRadius::same(RADIUS_MD), tone.tint());
    painter.rect_stroke(
        rect,
        CornerRadius::same(RADIUS_MD),
        Stroke::new(1.0, tone.edge()),
        StrokeKind::Inside,
    );
    match glyph {
        Glyph::Wifi => {
            let size = rect.width();
            wifi_arcs(
                painter,
                pos2(rect.center().x, rect.center().y + size * 0.18),
                size * 0.62,
                1.6,
                tone.color(),
            );
        }
    }
}

/// A padlock mark.
fn lock_icon(painter: &egui::Painter, center: egui::Pos2, colour: Color32) {
    let body = Rect::from_center_size(pos2(center.x, center.y + 1.6), vec2(9.0, 7.0));
    painter.rect_filled(body, CornerRadius::same(2), colour);
    let radius = 3.0;
    let points: Vec<egui::Pos2> = (0..=12)
        .map(|step| {
            let angle = 180.0 + 180.0 * (step as f32 / 12.0);
            let radians = angle.to_radians();
            pos2(
                center.x + radius * radians.cos(),
                body.top() + radius * radians.sin() - 10.0 + 10.0,
            )
        })
        .collect();
    painter.add(egui::Shape::line(points, Stroke::new(1.2, colour)));
}

/// The show/hide-password eye toggle.
fn eye_button(ui: &mut egui::Ui, shown: bool) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(CONTROL_HEIGHT), Sense::click());
    let colour = if response.hovered() {
        color::TEXT
    } else {
        color::MUTED
    };
    let painter = ui.painter();
    let center = rect.center();
    let eye = Rect::from_center_size(center, vec2(16.0, 9.0));
    painter.add(egui::Shape::convex_polygon(
        vec![
            pos2(eye.left(), center.y),
            pos2(center.x, eye.top()),
            pos2(eye.right(), center.y),
            pos2(center.x, eye.bottom()),
        ],
        Color32::TRANSPARENT,
        Stroke::new(1.2, colour),
    ));
    painter.circle_filled(center, 2.2, colour);
    if !shown {
        painter.line_segment(
            [
                pos2(eye.left() - 1.0, eye.bottom() + 1.0),
                pos2(eye.right() + 1.0, eye.top() - 1.0),
            ],
            Stroke::new(1.2, colour),
        );
    }
    response
}

/// A native-looking switch. Returns a changed response when toggled.
fn toggle_switch(ui: &mut egui::Ui, on: &mut bool) -> Response {
    let enabled = ui.is_enabled();
    let (rect, mut response) = ui.allocate_exact_size(vec2(40.0, 24.0), Sense::click());
    if enabled && response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let painter = ui.painter();
    let track = Rect::from_center_size(rect.center(), vec2(38.0, 22.0));
    let radius = CornerRadius::same(RADIUS_PILL);
    let track_colour = if !enabled {
        color::RAISED
    } else if *on {
        color::OK
    } else {
        color::RAISED_HOVER
    };
    painter.rect_filled(track, radius, track_colour);
    let knob_x = if *on {
        track.right() - 12.0
    } else {
        track.left() + 12.0
    };
    let knob = if enabled {
        Color32::WHITE
    } else {
        with_alpha(Color32::WHITE, 110)
    };
    painter.circle_filled(pos2(knob_x, track.center().y), 9.0, knob);
    response
}

/// A labelled value in the telemetry rows.
fn telemetry_item(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.label(
            RichText::new(label)
                .size(TEXT_MICRO)
                .color(color::FAINT)
                .extra_letter_spacing(0.4),
        );
        ui.add_space(1.0);
        ui.label(
            RichText::new(value)
                .size(TEXT_SMALL)
                .monospace()
                .color(color::TEXT),
        );
    });
}

/// A colour key under the graph.
fn legend(ui: &mut egui::Ui, colour: Color32, text: &str) {
    ui.horizontal(|ui| {
        dot(ui, colour);
        ui.add_space(SPACE_1);
        ui.label(RichText::new(text).size(TEXT_SMALL).color(color::MUTED));
    });
}

/// A section header: an accent mark, an uppercase title and an optional count.
fn section_header_row(ui: &mut egui::Ui, title: &str, colour: Color32, count: Option<&str>) {
    ui.horizontal(|ui| {
        dot(ui, colour);
        ui.add_space(SPACE_1);
        ui.label(
            RichText::new(title.to_uppercase())
                .size(TEXT_MICRO)
                .strong()
                .color(color::MUTED)
                .extra_letter_spacing(0.9),
        );
        if let Some(count) = count {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(count).size(TEXT_MICRO).color(color::FAINT));
            });
        }
    });
}

/// The inset hairline between rows of a list.
fn row_divider(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    let inset = rect.shrink2(vec2(46.0, 0.0));
    ui.painter()
        .rect_filled(inset, CornerRadius::ZERO, with_alpha(color::HAIRLINE, 160));
}

/// A labelled text field for the manual-addressing form.
fn field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            vec2(72.0, CONTROL_HEIGHT),
            Label::new(RichText::new(label).size(TEXT_SMALL).color(color::MUTED)),
        );
        let width = ui.available_width();
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(width),
        );
    });
}

// /// A selectable log-level pill.
// fn filter_pill(ui: &mut egui::Ui, label: &str, active: bool) -> Response {
//     let text = RichText::new(label)
//         .size(TEXT_SMALL)
//         .strong()
//         .color(if active {
//             color::ACCENT_SOFT_INK
//         } else {
//             color::MUTED
//         });
//     let button = egui::Button::new(text).min_size(vec2(58.0, CONTROL_HEIGHT - 6.0));
//     let button = if active {
//         button.fill(color::ACCENT_SOFT).stroke(Stroke::NONE)
//     } else {
//         button
//             .fill(Color32::TRANSPARENT)
//             .stroke(Stroke::new(1.0, color::HAIRLINE))
//     };
//     ui.add(button)
// }

/// The four signal bars, lit by RSSI.
fn signal_bars(painter: &egui::Painter, rect: Rect, dbm: Option<i32>, tone: Tone) {
    let lit = signal_level(dbm);
    let bar_width = 3.0;
    let gap = 2.0;
    for index in 0..4u8 {
        let height = 5.0 + f32::from(index) * 3.2;
        let x = rect.left() + f32::from(index) * (bar_width + gap);
        let bar = Rect::from_min_max(
            pos2(x, rect.bottom() - height),
            pos2(x + bar_width, rect.bottom()),
        );
        let colour = if index < lit {
            tone.color()
        } else {
            with_alpha(color::FAINT, 120)
        };
        painter.rect_filled(bar, CornerRadius::same(1), colour);
    }
}

/// One network row: bars, name, metadata and the trailing affordance. The whole
/// row is one click target.
#[allow(clippy::too_many_arguments)]
fn network_row(
    ui: &mut egui::Ui,
    network: &Network,
    style: RowStyle,
    connected: bool,
    saved: bool,
    connecting: bool,
    open: bool,
    time: f32,
) -> Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(vec2(width, ROW_HEIGHT), Sense::click());
    let painter = ui.painter();

    if response.hovered() {
        painter.rect_filled(
            rect,
            CornerRadius::same(RADIUS_MD),
            with_alpha(color::RAISED, 70),
        );
    }

    let tone = signal_tone(network.signal_dbm);
    let bars = Rect::from_center_size(pos2(rect.left() + 22.0, rect.center().y), vec2(18.0, 16.0));
    signal_bars(painter, bars, network.signal_dbm, tone);

    let text_left = rect.left() + 46.0;
    painter.text(
        pos2(text_left, rect.center().y - 9.0),
        Align2::LEFT_CENTER,
        &network.ssid,
        FontId::proportional(TEXT_BODY + 1.0),
        color::TEXT,
    );

    let mut meta = network.security.label().to_string();
    if let Some(channel) = network.channel {
        meta.push_str(&format!("  ·  ch {channel}"));
    }
    if let Some(dbm) = network.signal_dbm {
        meta.push_str(&format!("  ·  {dbm} dBm"));
    }
    if saved && style != RowStyle::Known {
        meta.push_str("  ·  saved");
    }
    painter.text(
        pos2(text_left, rect.center().y + 10.0),
        Align2::LEFT_CENTER,
        meta,
        FontId::proportional(TEXT_SMALL),
        color::MUTED,
    );

    let right = rect.right() - 12.0;
    if connecting {
        spinner_arc(
            painter,
            pos2(right - 66.0, rect.center().y),
            8.0,
            2.0,
            color::ACCENT,
            time,
        );
        painter.text(
            pos2(right, rect.center().y),
            Align2::RIGHT_CENTER,
            "Connecting…",
            FontId::proportional(TEXT_SMALL),
            color::ACCENT,
        );
    } else if connected {
        painter.text(
            pos2(right, rect.center().y),
            Align2::RIGHT_CENTER,
            "Connected",
            FontId::proportional(TEXT_SMALL),
            color::OK,
        );
    } else if open {
        painter.text(
            pos2(right, rect.center().y),
            Align2::RIGHT_CENTER,
            "Cancel",
            FontId::proportional(TEXT_SMALL),
            color::ACCENT,
        );
    } else {
        let secured = matches!(
            network.security,
            Security::Wpa | Security::Wpa2 | Security::Wpa3
        );
        let label = match style {
            RowStyle::Known => "Connect",
            RowStyle::Available | RowStyle::Discovered => "Join",
        };
        if secured {
            lock_icon(painter, pos2(right - 50.0, rect.center().y), color::MUTED);
        }
        painter.text(
            pos2(right, rect.center().y),
            Align2::RIGHT_CENTER,
            label,
            FontId::proportional(TEXT_SMALL),
            color::ACCENT,
        );
    }

    response
}

/// A shimmering placeholder row shown while a scan is still running.
fn skeleton_row(ui: &mut egui::Ui, time: f32) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(width, ROW_HEIGHT), Sense::hover());
    let pulse = 0.5 + 0.5 * (time * 2.0).sin();
    let alpha = (50.0 + 70.0 * pulse) as u8;
    let painter = ui.painter();
    painter.rect_filled(
        Rect::from_center_size(
            pos2(rect.left() + 120.0, rect.center().y - 6.0),
            vec2(150.0, 12.0),
        ),
        CornerRadius::same(RADIUS_SM),
        with_alpha(color::RAISED_HOVER, alpha),
    );
    painter.rect_filled(
        Rect::from_center_size(
            pos2(rect.left() + 70.0, rect.center().y + 12.0),
            vec2(90.0, 8.0),
        ),
        CornerRadius::same(RADIUS_SM),
        with_alpha(color::RAISED, alpha / 2 + 40),
    );
}

/// An indeterminate progress bar.
fn progress_bar(ui: &mut egui::Ui, time: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 4.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(
        rect,
        CornerRadius::same(RADIUS_PILL),
        with_alpha(color::RAISED, 200),
    );
    let segment = rect.width() * 0.28;
    let phase = (time * 0.6).fract();
    let x = rect.left() + phase * (rect.width() + segment) - segment;
    let seg = Rect::from_min_max(
        pos2(x.max(rect.left()), rect.top()),
        pos2((x + segment).min(rect.right()), rect.bottom()),
    );
    painter.rect_filled(seg, CornerRadius::same(RADIUS_PILL), color::ACCENT);
}

/// A rotating arc used as a spinner.
fn spinner_arc(
    painter: &egui::Painter,
    center: egui::Pos2,
    radius: f32,
    stroke_w: f32,
    colour: Color32,
    time: f32,
) {
    let start = (time * 2.4).fract() * std::f32::consts::TAU;
    let sweep = 1.9_f32;
    let steps = 16;
    let points: Vec<egui::Pos2> = (0..=steps)
        .map(|step| {
            let angle = start + sweep * (step as f32 / steps as f32);
            pos2(
                center.x + radius * angle.cos(),
                center.y + radius * angle.sin(),
            )
        })
        .collect();
    painter.add(egui::Shape::line(points, Stroke::new(stroke_w, colour)));
}

/// The live throughput graph: download as bars, upload as a line.
fn graph(painter: &egui::Painter, rect: Rect, down: &[f32], up: &[f32], time: f32, running: bool) {
    painter.rect_filled(rect, CornerRadius::same(RADIUS_MD), color::CANVAS);
    painter.rect_stroke(
        rect,
        CornerRadius::same(RADIUS_MD),
        Stroke::new(1.0, color::HAIRLINE),
        StrokeKind::Inside,
    );

    for step in 1..4 {
        let y = rect.top() + rect.height() * (step as f32 / 4.0);
        painter.line_segment(
            [pos2(rect.left(), y), pos2(rect.right(), y)],
            Stroke::new(1.0, with_alpha(color::HAIRLINE, 90)),
        );
    }

    let samples = down.len().max(up.len());
    if !running || samples == 0 {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "no traffic yet",
            FontId::proportional(TEXT_SMALL),
            color::FAINT,
        );
        return;
    }

    let peak = down
        .iter()
        .chain(up.iter())
        .copied()
        .fold(0.0_f32, f32::max)
        .max(1.0);
    let step = rect.width() / samples as f32;
    let usable = rect.height() - 6.0;

    for (index, value) in down.iter().enumerate() {
        let height = (value / peak) * usable;
        if height <= 0.0 {
            continue;
        }
        let x = rect.left() + index as f32 * step;
        let bar = Rect::from_min_max(
            pos2(x, rect.bottom() - height),
            pos2(x + (step * 0.55).max(1.0), rect.bottom()),
        );
        painter.rect_filled(bar, CornerRadius::same(1), with_alpha(color::DOWN, 210));
    }

    if up.len() > 1 {
        let points: Vec<egui::Pos2> = up
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let height = (value / peak) * usable;
                pos2(
                    rect.left() + index as f32 * step + step * 0.27,
                    rect.bottom() - height,
                )
            })
            .collect();
        painter.add(egui::Shape::line(points, Stroke::new(1.5, color::UP)));
    }

    // A soft marker of "now" on the right edge while relaying.
    let now = (time * 0.5).fract();
    let _ = now;
}

/// The empty-state card and its single action.
fn empty_state(ui: &mut egui::Ui, empty: &EmptyPicker) -> Option<PickerAction> {
    let mut chosen = None;
    card(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(SPACE_2);
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
            glyph_tile(ui.painter(), rect, empty.tone, Glyph::Wifi);
            ui.add_space(SPACE_3);
            ui.label(
                RichText::new(&empty.title)
                    .size(TEXT_BODY)
                    .strong()
                    .color(color::TEXT),
            );
            ui.add_space(SPACE_1);
            ui.label(
                RichText::new(&empty.message)
                    .size(TEXT_SMALL)
                    .color(color::MUTED),
            );
            if let Some(action) = empty.action {
                ui.add_space(SPACE_3);
                let label = match action {
                    PickerAction::Start => "Open & Scan",
                    PickerAction::Scan => "Scan Again",
                };
                if ui.add(primary_button(label)).clicked() {
                    chosen = Some(action);
                }
            }
            ui.add_space(SPACE_2);
        });
    });
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(ssid: &str, dbm: Option<i32>) -> Network {
        Network {
            ssid: ssid.into(),
            bssid: None,
            signal_dbm: dbm,
            channel: Some(6),
            security: Security::Wpa2,
        }
    }

    #[test]
    fn tabs_cover_the_two_surfaces() {
        assert_eq!(Tab::default(), Tab::Networks);
        let labels: Vec<_> = Tab::ALL.iter().map(|tab| tab.label()).collect();
        assert_eq!(labels, ["Networks", "Device"]);
    }

    // #[test]
    // fn log_filter_matches_its_level() {
    //     assert!(LogFilter::All.accepts(LogLevel::Debug));
    //     assert!(LogFilter::Info.accepts(LogLevel::Info));
    //     assert!(!LogFilter::Info.accepts(LogLevel::Warn));
    //     assert!(LogFilter::Warn.accepts(LogLevel::Warn));
    //     assert!(!LogFilter::Warn.accepts(LogLevel::Error));
    //     assert!(LogFilter::Error.accepts(LogLevel::Error));
    // }

    #[test]
    fn unknown_security_cannot_be_joined() {
        assert!(!security_supported(&Security::Unknown));
        assert!(security_supported(&Security::Open));
        assert!(security_supported(&Security::Wpa2));
    }

    #[test]
    fn a_replug_is_a_hard_fault() {
        let state = AppState {
            replug: Some("unplug it".into()),
            ..AppState::default()
        };
        assert_eq!(tunnel_summary(&state), ("Idle", Tone::Idle));
        assert!(scan_blocker(&state).is_some());
    }

    #[test]
    fn a_relaying_link_reads_as_connected() {
        let state = AppState {
            wifi: WifiState::Connected {
                ssid: "home".into(),
            },
            tunnel: TunnelState::Running {
                to_link_packets: 0,
                to_tun_packets: 0,
            },
            ..AppState::default()
        };
        assert_eq!(tunnel_summary(&state), ("Relaying", Tone::Good));
        assert_eq!(tunnel_subtitle(&state), "Relaying between home and macOS");
    }

    #[test]
    fn a_scan_needs_an_open_device() {
        let state = AppState::default();
        assert_eq!(scan_blocker(&state), Some("Open the device first"));

        let scanning = AppState {
            wifi: WifiState::Scanning,
            ..AppState::default()
        };
        assert_eq!(scan_blocker(&scanning), Some("A scan is already running"));
    }

    #[test]
    fn signal_bars_track_the_rssi() {
        assert_eq!(signal_level(None), 0);
        assert_eq!(signal_level(Some(-40)), 4);
        assert_eq!(signal_level(Some(-68)), 2);
        assert_eq!(signal_level(Some(-80)), 1);
        assert_eq!(signal_tone(Some(-40)), Tone::Good);
        assert_eq!(signal_tone(None), Tone::Idle);
    }

    #[test]
    fn sorting_puts_the_strongest_signal_first_and_unknown_last() {
        let mut nets = vec![
            network("weak", Some(-85)),
            network("strong", Some(-40)),
            network("unknown", None),
            network("mid", Some(-65)),
        ];
        sort_by_signal(&mut nets);
        let order: Vec<_> = nets.iter().map(|net| net.ssid.as_str()).collect();
        assert_eq!(order, ["strong", "mid", "weak", "unknown"]);
    }

    #[test]
    fn the_plural_suffix_follows_the_count() {
        assert_eq!(plural(0), "s");
        assert_eq!(plural(1), "");
        assert_eq!(plural(2), "s");
    }
}
