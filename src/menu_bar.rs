//! The macOS menu bar item: a Wi-Fi glyph with the live up/down throughput.
//!
//! The status item is created once, on the main thread, and refreshed by an
//! `NSTimer` on the main run loop — so the readout keeps moving while the
//! window is closed and the app is tucked away in the background. The backend
//! thread publishes rate samples into a plain mutex; AppKit itself is only
//! touched from the main thread.

#[cfg(target_os = "macos")]
pub use platform::{hide_app, install, set_rates, take_actions};
#[cfg(not(target_os = "macos"))]
pub use stubs::{hide_app, install, set_rates, take_actions};

/// An action the user picked from the status-item menu.
///
/// The AppKit menu runs on the main thread and cannot touch the app directly,
/// so each item queues one of these; the GUI drains them on its next frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    OpenDevice,
    CloseDevice,
    Rescan,
    Identify,
    ToggleDetails,
    ToggleLogs,
}

#[cfg(target_os = "macos")]
mod platform {
    use std::cell::RefCell;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, NSObjectProtocol, Sel};
    use objc2::{define_class, msg_send, sel, AnyThread, MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{
        NSApplication, NSCellImagePosition, NSFont, NSFontWeightRegular, NSImage, NSMenu,
        NSMenuItem, NSStatusBar, NSStatusBarButton, NSStatusItem, NSVariableStatusItemLength,
        NSView, NSWindow,
    };
    use objc2_foundation::{NSObject, NSString, NSTimer};

    use super::MenuAction;
    use crate::format::format_status_rates;

    /// A published reading is shown for this long without a fresh one.
    const RATES_FRESH: Duration = Duration::from_secs(2);
    /// How often the readout is refreshed, in seconds.
    const TICK_SECONDS: f64 = 0.5;
    /// The readout's font size: small enough for the menu bar's density, kept
    /// monospaced so changing digits do not jiggle the title.
    const TITLE_FONT_SIZE: f64 = 12.0;

    /// The latest relay rates, in bytes per second, tagged with their age.
    #[derive(Clone, Copy)]
    struct Rates {
        up: f64,
        down: f64,
        at: Instant,
    }

    static RATES: Mutex<Option<Rates>> = Mutex::new(None);

    /// Menu picks waiting for the GUI to drain. Bounded: the menu lives for the
    /// app's lifetime, so a stuck GUI would otherwise grow this without limit.
    static ACTIONS: Mutex<Vec<MenuAction>> = Mutex::new(Vec::new());

    /// Queue a menu pick and nudge the GUI so it renders a frame to drain it.
    fn push(action: MenuAction) {
        if let Ok(mut queue) = ACTIONS.lock() {
            if queue.len() < 32 {
                queue.push(action);
            }
        }
        notify();
    }

    /// Ask egui for a frame, waking a hidden/occluded window to handle a pick.
    fn notify() {
        UI.with(|ui| {
            if let Some(ui) = ui.borrow().as_ref() {
                ui.ctx.request_repaint();
            }
        });
    }

    /// Hand the queued menu picks to the GUI. Called once per frame.
    pub fn take_actions() -> Vec<MenuAction> {
        ACTIONS
            .lock()
            .map(|mut queue| std::mem::take(&mut *queue))
            .unwrap_or_default()
    }

    /// Main-thread-only AppKit objects, kept alive for the app's lifetime.
    struct Ui {
        _item: Retained<NSStatusItem>,
        button: Retained<NSStatusBarButton>,
        _target: Retained<StatusTarget>,
        _timer: Retained<NSTimer>,
        window: Option<Retained<NSWindow>>,
        ctx: egui::Context,
        last_title: String,
    }

    thread_local! {
        static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
    }

    define_class!(
        /// Menu actions and the rate tick of the status item.
        #[unsafe(super(NSObject))]
        struct StatusTarget;

        impl StatusTarget {
            /// "Show Wi-Fi Window": order the window back in and activate.
            #[unsafe(method(showWindow:))]
            fn show_window(&self, _sender: Option<&AnyObject>) {
                reveal_window();
            }

            /// "Hide Wi-Fi Window": tuck the app away, relay keeps running.
            #[unsafe(method(hideWindow:))]
            fn hide_window(&self, _sender: Option<&AnyObject>) {
                let Some(mtm) = MainThreadMarker::new() else {
                    return;
                };
                NSApplication::sharedApplication(mtm).hide(None);
            }

            /// "Open Device": claim the dongle and start scanning.
            #[unsafe(method(openDevice:))]
            fn open_device(&self, _sender: Option<&AnyObject>) {
                push(MenuAction::OpenDevice);
            }

            /// "Close Device": release the dongle and stop relaying.
            #[unsafe(method(closeDevice:))]
            fn close_device(&self, _sender: Option<&AnyObject>) {
                push(MenuAction::CloseDevice);
            }

            /// "Rescan Networks": trigger a fresh scan.
            #[unsafe(method(rescanNetworks:))]
            fn rescan_networks(&self, _sender: Option<&AnyObject>) {
                push(MenuAction::Rescan);
            }

            /// "Identify Device": blink the dongle's LED so you can pick it out.
            #[unsafe(method(identifyDevice:))]
            fn identify_device(&self, _sender: Option<&AnyObject>) {
                push(MenuAction::Identify);
            }

            /// "Connection Details": reveal the window with the drawer toggled.
            #[unsafe(method(showDetails:))]
            fn show_details(&self, _sender: Option<&AnyObject>) {
                reveal_window();
                push(MenuAction::ToggleDetails);
            }

            // The log console is hidden from users, so its menu item is gone.
            // /// "Activity Log": reveal the window with the log console toggled.
            // #[unsafe(method(showLogs:))]
            // fn show_logs(&self, _sender: Option<&AnyObject>) {
            //     reveal_window();
            //     push(MenuAction::ToggleLogs);
            // }

            /// "Quit": the same termination path as ⌘Q.
            #[unsafe(method(quitApp:))]
            fn quit_app(&self, _sender: Option<&AnyObject>) {
                let Some(mtm) = MainThreadMarker::new() else {
                    return;
                };
                NSApplication::sharedApplication(mtm).terminate(None);
            }

            /// The timer tick: keep the icon's rate readout current.
            #[unsafe(method(pollRates:))]
            fn poll_rates(&self, _timer: &NSTimer) {
                refresh_title();
            }
        }

        unsafe impl NSObjectProtocol for StatusTarget {}
    );

    impl StatusTarget {
        fn new() -> Retained<Self> {
            let this = Self::alloc().set_ivars(());
            unsafe { msg_send![super(this), init] }
        }
    }

    /// Create the status item. Call on the main thread; idempotent, and
    /// `false` simply means a later frame may retry.
    pub fn install(
        ctx: &egui::Context,
        handle: Option<raw_window_handle::RawWindowHandle>,
    ) -> bool {
        let Some(mtm) = MainThreadMarker::new() else {
            return false;
        };
        if UI.with(|ui| ui.borrow().is_some()) {
            return true;
        }

        let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
        let Some(button) = item.button(mtm) else {
            return false;
        };

        let symbol = NSString::from_str("wifi");
        let description = NSString::from_str("MT7601U Wi-Fi");
        if let Some(image) =
            NSImage::imageWithSystemSymbolName_accessibilityDescription(&symbol, Some(&description))
        {
            image.setTemplate(true);
            button.setImage(Some(&image));
            button.setImagePosition(NSCellImagePosition::ImageLeft);
        }
        let font = NSFont::monospacedDigitSystemFontOfSize_weight(
            TITLE_FONT_SIZE,
            // SAFETY: a plain constant.
            unsafe { NSFontWeightRegular },
        );
        button.setFont(Some(&font));
        button.setToolTip(Some(&NSString::from_str(
            "MT7601U Wi-Fi — throughput and window",
        )));

        let target = StatusTarget::new();
        let menu = NSMenu::new(mtm);
        menu.addItem(&menu_item(
            mtm,
            "Show Wi-Fi Window",
            sel!(showWindow:),
            "",
            &target,
        ));
        menu.addItem(&menu_item(
            mtm,
            "Hide Wi-Fi Window",
            sel!(hideWindow:),
            "",
            &target,
        ));
        menu.addItem(&NSMenuItem::separatorItem(mtm));
        menu.addItem(&menu_item(
            mtm,
            "Open Device",
            sel!(openDevice:),
            "",
            &target,
        ));
        menu.addItem(&menu_item(
            mtm,
            "Close Device",
            sel!(closeDevice:),
            "",
            &target,
        ));
        menu.addItem(&menu_item(
            mtm,
            "Rescan Networks",
            sel!(rescanNetworks:),
            "r",
            &target,
        ));
        menu.addItem(&menu_item(
            mtm,
            "Identify Device",
            sel!(identifyDevice:),
            "",
            &target,
        ));
        menu.addItem(&NSMenuItem::separatorItem(mtm));
        menu.addItem(&menu_item(
            mtm,
            "Device Details",
            sel!(showDetails:),
            "d",
            &target,
        ));
        // menu.addItem(&menu_item(
        //     mtm,
        //     "Activity Log",
        //     sel!(showLogs:),
        //     "l",
        //     &target,
        // ));
        menu.addItem(&NSMenuItem::separatorItem(mtm));
        menu.addItem(&menu_item(
            mtm,
            "Quit MT7601U Wi-Fi",
            sel!(quitApp:),
            "q",
            &target,
        ));
        item.setMenu(Some(&menu));

        // The readout is driven from the main run loop, so it keeps updating
        // while the window is closed and the app sits in the background.
        let timer = unsafe {
            NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
                TICK_SECONDS,
                &target,
                sel!(pollRates:),
                None,
                true,
            )
        };

        UI.with(|ui| {
            *ui.borrow_mut() = Some(Ui {
                _item: item,
                button,
                _target: target,
                _timer: timer,
                window: ns_window(handle),
                ctx: ctx.clone(),
                last_title: String::new(),
            });
        });
        refresh_title();

        tracing::info!("menu bar item installed");
        true
    }

    /// Publish the latest relay rates — `(up, down)`, in bytes per second.
    ///
    /// Callable from any thread; `None` clears the readout.
    pub fn set_rates(rates: Option<(f64, f64)>) {
        let mut slot = RATES.lock().unwrap_or_else(|error| error.into_inner());
        *slot = rates.map(|(up, down)| Rates {
            up,
            down,
            at: Instant::now(),
        });
    }

    /// Tuck the whole app away; the menu bar item keeps running.
    pub fn hide_app() {
        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        NSApplication::sharedApplication(mtm).hide(None);
    }

    /// Bring the window back: unhide the app, activate it, and order the window
    /// front. Used by "Show" and by the items that need the window visible.
    fn reveal_window() {
        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        let app = NSApplication::sharedApplication(mtm);
        app.unhide(None);
        // `activate` is macOS 14+; the older call covers every macOS.
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);
        UI.with(|ui| {
            if let Some(ui) = ui.borrow().as_ref() {
                if let Some(window) = &ui.window {
                    window.makeKeyAndOrderFront(None);
                }
                ui.ctx.request_repaint();
            }
        });
    }

    /// One item of the status menu, wired to `target`. A non-empty `key` shows
    /// as the item's ⌘ shortcut (AppKit's default modifier for menu items).
    fn menu_item(
        mtm: MainThreadMarker,
        title: &str,
        action: Sel,
        key: &str,
        target: &StatusTarget,
    ) -> Retained<NSMenuItem> {
        let item = unsafe {
            NSMenuItem::initWithTitle_action_keyEquivalent(
                NSMenuItem::alloc(mtm),
                &NSString::from_str(title),
                Some(action),
                &NSString::from_str(key),
            )
        };
        let object: &AnyObject = target;
        unsafe { item.setTarget(Some(object)) };
        item
    }

    /// The NSWindow behind eframe's AppKit view, if the handle names one.
    fn ns_window(handle: Option<raw_window_handle::RawWindowHandle>) -> Option<Retained<NSWindow>> {
        let raw_window_handle::RawWindowHandle::AppKit(handle) = handle? else {
            return None;
        };
        // SAFETY: the view is eframe's surface view and lives for as long as
        // the app; the main thread owns both AppKit and this call.
        let view = unsafe { &*handle.ns_view.as_ptr().cast::<NSView>() };
        view.window()
    }

    /// Push the current readout to the status item when it changed.
    fn refresh_title() {
        let rates = *RATES.lock().unwrap_or_else(|error| error.into_inner());
        let title = match rates {
            Some(rates) if rates.at.elapsed() < RATES_FRESH => {
                format_status_rates(Some((rates.up, rates.down)))
            }
            _ => String::new(),
        };
        UI.with(|ui| {
            let mut ui = ui.borrow_mut();
            let Some(ui) = ui.as_mut() else {
                return;
            };
            if ui.last_title != title {
                ui.button.setTitle(&NSString::from_str(&title));
                ui.last_title = title;
            }
        });
    }
}

#[cfg(not(target_os = "macos"))]
mod stubs {
    /// Off macOS there is no menu bar item to create.
    pub fn install(
        _ctx: &egui::Context,
        _handle: Option<raw_window_handle::RawWindowHandle>,
    ) -> bool {
        false
    }

    /// Off macOS there is nothing to hide.
    pub fn hide_app() {}

    /// Off macOS there is nothing to publish.
    pub fn set_rates(_rates: Option<(f64, f64)>) {}

    /// Off macOS there is no menu, so no picks are ever queued.
    pub fn take_actions() -> Vec<super::MenuAction> {
        Vec::new()
    }
}
