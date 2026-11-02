//! Visual design system for the GUI.
//!
//! One authored dark theme in the spirit of a native macOS utility: San
//! Francisco for text (loaded from the system, so the app looks like it
//! belongs on the desktop), a cool near-black canvas, and a single warm
//! "signal" accent so the colour meaning *act* or *locked* is unmistakable
//! against the chrome. Every widget in `app.rs` takes its colour, size and
//! radius from here rather than choosing inline values.
//!
//! Status colour is the vocabulary of this console — the user's first question
//! is always "is it up yet?" — so the accent is reserved for action and
//! in-flight work, green marks locked/complete, and amber/red only ever appear
//! as small marks rather than fills.

use std::sync::Arc;

use egui::style::Widgets;
use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Shadow, Stroke,
    TextStyle, Visuals,
};

/// Layout rhythm: 4 for micro-breaths, 8 for component gaps, 12 for padding,
/// 20 and 28 for section breaks.
pub const SPACE_1: f32 = 4.0;
pub const SPACE_2: f32 = 8.0;
pub const SPACE_3: f32 = 12.0;
pub const SPACE_4: f32 = 20.0;
pub const SPACE_5: f32 = 28.0;

pub const RADIUS_SM: u8 = 5;
pub const RADIUS_MD: u8 = 8;
pub const RADIUS_LG: u8 = 12;
pub const RADIUS_XL: u8 = 16;
pub const RADIUS_PILL: u8 = 99;

/// Hero numbers ("what speed is it going?").
pub const TEXT_DISPLAY: f32 = 26.0;
pub const TEXT_TITLE: f32 = 17.0;
pub const TEXT_HEAD: f32 = 14.0;
pub const TEXT_BODY: f32 = 13.0;
pub const TEXT_SMALL: f32 = 12.0;
pub const TEXT_MICRO: f32 = 11.0;
pub const TEXT_MONO: f32 = 12.0;

/// Named colours, drawn from the macOS dark system palette: a near-black
/// window, slightly raised grouped surfaces, the system-blue accent and the
/// standard signal colours. Keeping to the platform palette is what makes the
/// app read as a native utility rather than a themed dashboard.
pub mod color {
    use egui::Color32;

    pub const CANVAS: Color32 = Color32::from_rgb(0x1c, 0x1c, 0x1e);
    pub const PANEL: Color32 = Color32::from_rgb(0x1c, 0x1c, 0x1e);
    /// Grouped content surface (cards, list groups).
    pub const SURFACE: Color32 = Color32::from_rgb(0x2c, 0x2c, 0x2e);
    /// Slightly raised surface used inside a card.
    pub const RAISED: Color32 = Color32::from_rgb(0x3a, 0x3a, 0x3c);
    pub const RAISED_HOVER: Color32 = Color32::from_rgb(0x48, 0x48, 0x4a);
    pub const HAIRLINE: Color32 = Color32::from_rgb(0x38, 0x38, 0x3a);
    pub const HAIRLINE_STRONG: Color32 = Color32::from_rgb(0x48, 0x48, 0x4a);

    pub const TEXT: Color32 = Color32::from_rgb(0xf2, 0xf2, 0xf7);
    pub const MUTED: Color32 = Color32::from_rgb(0x8e, 0x8e, 0x93);
    /// Reserved for decorative text and disabled states; too low contrast to
    /// carry anything the user has to read.
    pub const FAINT: Color32 = Color32::from_rgb(0x63, 0x63, 0x66);

    /// Action, focus and in-flight work: the system accent colour.
    pub const ACCENT: Color32 = Color32::from_rgb(0x0a, 0x84, 0xff);
    /// Text drawn on top of a saturated accent surface.
    pub const ACCENT_INK: Color32 = Color32::from_rgb(0xff, 0xff, 0xff);
    /// A prominent (accented) button: the soft blue macOS uses for the default
    /// action in dark mode, with dark ink for contrast.
    pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0xa9, 0xc7, 0xfa);
    pub const ACCENT_SOFT_INK: Color32 = Color32::from_rgb(0x0a, 0x1b, 0x36);

    /// Locked, associated, relaying.
    pub const OK: Color32 = Color32::from_rgb(0x30, 0xd1, 0x58);
    /// Needs attention, not broken.
    pub const WARN: Color32 = Color32::from_rgb(0xff, 0x9f, 0x0a);
    pub const ERROR: Color32 = Color32::from_rgb(0xff, 0x45, 0x3a);
    /// The USB device plane.
    pub const DEVICE: Color32 = Color32::from_rgb(0x64, 0xd2, 0xff);

    /// Download throughput (network → this Mac).
    pub const DOWN: Color32 = Color32::from_rgb(0x0a, 0x84, 0xff);
    /// Upload throughput (this Mac → network).
    pub const UP: Color32 = Color32::from_rgb(0xbf, 0x5a, 0xf2);
}

/// Semantic colour role for a status mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Nothing to report yet.
    Idle,
    /// Work in flight.
    Active,
    /// Up, locked or complete.
    Good,
    /// Needs attention, not broken.
    Caution,
    /// Failed.
    Bad,
    /// USB device plane.
    Device,
}

impl Tone {
    pub fn color(self) -> Color32 {
        match self {
            Self::Idle => color::FAINT,
            Self::Active => color::ACCENT,
            Self::Good => color::OK,
            Self::Caution => color::WARN,
            Self::Bad => color::ERROR,
            Self::Device => color::DEVICE,
        }
    }

    /// Fill for a badge carrying this tone.
    pub fn tint(self) -> Color32 {
        with_alpha(self.color(), if self == Self::Idle { 30 } else { 26 })
    }

    /// Border for a badge carrying this tone.
    pub fn edge(self) -> Color32 {
        with_alpha(self.color(), 80)
    }
}

/// `color` at `alpha` (0-255), for tints, marks and hairlines.
pub fn with_alpha(color: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha)
}

/// Linear blend between two colours, `t` in `0..=1`.
pub fn lerp_color(from: Color32, to: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * t).round() as u8;
    Color32::from_rgba_unmultiplied(
        mix(from.r(), to.r()),
        mix(from.g(), to.g()),
        mix(from.b(), to.b()),
        mix(from.a(), to.a()),
    )
}

/// Install the theme and the system typefaces on a context.
///
/// Idempotent, so it is safe to call again (and cheap: the fonts are only read
/// from disk the first time).
pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.all_styles_mut(|style| {
        style.visuals = visuals();
        style.animation_time = 0.12;
        style.url_in_tooltip = false;
        style.interaction.tooltip_delay = 0.3;
        style.interaction.tooltip_grace_time = 0.2;

        let spacing = &mut style.spacing;
        spacing.item_spacing = egui::vec2(SPACE_2, SPACE_1 + 2.0);
        spacing.window_margin = egui::Margin::same(SPACE_3 as i8);
        spacing.button_padding = egui::vec2(10.0, 5.0);
        spacing.menu_margin = egui::Margin::same(SPACE_1 as i8);
        spacing.indent = SPACE_3;
        // Comfortable control height for a desktop tool (macOS controls sit
        // around 28pt); the width minimum keeps icon-only buttons sane.
        spacing.interact_size = egui::vec2(40.0, 28.0);
        spacing.combo_height = 220.0;
        spacing.slider_width = 120.0;
        spacing.scroll.bar_width = 8.0;
        spacing.scroll.floating = true;
        spacing.scroll.handle_min_length = 32.0;
        spacing.scroll.bar_inner_margin = SPACE_1;
        spacing.scroll.bar_outer_margin = 0.0;

        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(TEXT_TITLE)),
            (TextStyle::Body, FontId::proportional(TEXT_BODY)),
            (TextStyle::Button, FontId::proportional(TEXT_BODY)),
            (TextStyle::Small, FontId::proportional(TEXT_SMALL)),
            (TextStyle::Monospace, FontId::monospace(TEXT_MONO)),
        ]
        .into();
    });
}

/// Load San Francisco (and friends) from the system so the app reads as a
/// native macOS application. Any failure falls back to egui's bundled fonts,
/// so a missing file degrades the look, never the app.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    // Preferred first, fallbacks after: the family list is a chain.
    const PROPORTIONAL: &[(&str, &str)] = &[
        ("sf-pro", "/System/Library/Fonts/SFNS.ttf"),
        ("helvetica-neue", "/System/Library/Fonts/HelveticaNeue.ttc"),
    ];
    const MONOSPACE: &[(&str, &str)] = &[
        ("sf-mono", "/System/Library/Fonts/SFNSMono.ttf"),
        ("menlo", "/System/Library/Fonts/Menlo.ttc"),
    ];

    let mut proportional = Vec::new();
    for (name, path) in PROPORTIONAL {
        if let Some(data) = read_font(path) {
            fonts.font_data.insert((*name).to_owned(), Arc::new(data));
            proportional.push((*name).to_owned());
        }
    }
    let mut monospace = Vec::new();
    for (name, path) in MONOSPACE {
        if let Some(data) = read_font(path) {
            fonts.font_data.insert((*name).to_owned(), Arc::new(data));
            monospace.push((*name).to_owned());
        }
    }

    for (family, names) in [
        (FontFamily::Proportional, proportional),
        (FontFamily::Monospace, monospace),
    ] {
        if names.is_empty() {
            continue;
        }
        let chain = fonts.families.entry(family).or_default();
        for (position, name) in names.into_iter().enumerate() {
            chain.insert(position, name);
        }
    }

    ctx.set_fonts(fonts);
}

/// Read a font file, returning `None` when it is missing or unreadable.
fn read_font(path: &str) -> Option<FontData> {
    let bytes = std::fs::read(path).ok()?;
    Some(FontData::from_owned(bytes))
}

fn visuals() -> Visuals {
    let mut visuals = Visuals::dark();
    visuals.dark_mode = true;
    visuals.panel_fill = color::PANEL;
    visuals.window_fill = color::SURFACE;
    visuals.extreme_bg_color = color::CANVAS;
    visuals.faint_bg_color = color::SURFACE;
    visuals.text_edit_bg_color = Some(color::RAISED);
    visuals.code_bg_color = color::CANVAS;
    visuals.window_stroke = Stroke::new(1.0, color::HAIRLINE);
    visuals.window_corner_radius = CornerRadius::same(RADIUS_LG);
    visuals.menu_corner_radius = CornerRadius::same(RADIUS_MD);
    visuals.hyperlink_color = color::ACCENT;
    visuals.warn_fg_color = color::WARN;
    visuals.error_fg_color = color::ERROR;
    visuals.weak_text_alpha = 0.8;
    visuals.disabled_alpha = 0.34;
    visuals.slider_trailing_fill = true;
    visuals.window_shadow = Shadow {
        offset: [0, 10],
        blur: 28,
        spread: 0,
        color: Color32::from_black_alpha(170),
    };
    visuals.popup_shadow = Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(150),
    };

    // Selection is the accent, so "chosen" and "actionable" read the same way.
    visuals.selection.bg_fill = with_alpha(color::ACCENT, 42);
    visuals.selection.stroke = Stroke::new(1.5, color::ACCENT);

    let hairline = Stroke::new(1.0, color::HAIRLINE);

    let mut noninteractive = visuals.widgets.noninteractive;
    noninteractive.bg_fill = color::SURFACE;
    noninteractive.weak_bg_fill = color::SURFACE;
    noninteractive.bg_stroke = hairline;
    noninteractive.fg_stroke = Stroke::new(1.0, color::MUTED);
    noninteractive.corner_radius = CornerRadius::same(RADIUS_MD);
    noninteractive.expansion = 0.0;

    let mut inactive = visuals.widgets.inactive;
    inactive.bg_fill = color::RAISED;
    inactive.weak_bg_fill = color::RAISED;
    inactive.bg_stroke = hairline;
    inactive.fg_stroke = Stroke::new(1.0, color::TEXT);
    inactive.corner_radius = CornerRadius::same(RADIUS_MD);
    inactive.expansion = 0.0;

    let mut hovered = inactive;
    hovered.bg_fill = color::RAISED_HOVER;
    hovered.weak_bg_fill = color::RAISED_HOVER;
    hovered.bg_stroke = Stroke::new(1.0, color::HAIRLINE_STRONG);
    hovered.fg_stroke = Stroke::new(1.0, color::TEXT);

    // `active` doubles as the keyboard focus ring: egui paints it for focused
    // widgets, so the accent stroke is what a keyboard user follows.
    let mut active = inactive;
    active.bg_fill = color::HAIRLINE_STRONG;
    active.weak_bg_fill = color::HAIRLINE_STRONG;
    active.bg_stroke = Stroke::new(1.5, color::ACCENT);
    active.fg_stroke = Stroke::new(1.0, color::TEXT);

    let mut open = hovered;
    open.bg_fill = color::RAISED_HOVER;
    open.bg_stroke = Stroke::new(1.0, color::ACCENT);

    visuals.widgets = Widgets {
        noninteractive,
        inactive,
        hovered,
        active,
        open,
    };

    visuals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tones_are_visually_distinct() {
        let tones = [
            Tone::Idle,
            Tone::Active,
            Tone::Good,
            Tone::Caution,
            Tone::Bad,
            Tone::Device,
        ];
        for (i, a) in tones.iter().enumerate() {
            for b in &tones[i + 1..] {
                assert_ne!(a.color(), b.color(), "{a:?} and {b:?} share a colour");
            }
        }
    }

    #[test]
    fn active_tone_uses_the_action_accent() {
        assert_eq!(Tone::Active.color(), color::ACCENT);
    }

    #[test]
    fn with_alpha_scales_the_colour_towards_transparent() {
        assert_eq!(with_alpha(color::ACCENT, 255), color::ACCENT);

        let faint = with_alpha(color::ACCENT, 20);
        let strong = with_alpha(color::ACCENT, 120);
        assert_eq!((faint.a(), strong.a()), (20, 120));
        // Color32 is premultiplied, so a higher alpha keeps more of the source
        // colour: tints must stay ordered by strength.
        assert!(
            faint.r() < strong.r(),
            "a stronger tint must carry more of the accent"
        );
    }

    #[test]
    fn badge_tints_are_more_transparent_than_their_edges() {
        for tone in [Tone::Good, Tone::Caution, Tone::Bad, Tone::Active] {
            assert!(tone.tint().a() < tone.edge().a());
        }
    }

    #[test]
    fn lerp_color_moves_between_the_endpoints() {
        let a = Color32::from_rgb(0, 0, 0);
        let b = Color32::from_rgb(100, 200, 50);
        assert_eq!(lerp_color(a, b, 0.0), a);
        assert_eq!(lerp_color(a, b, 1.0), b);
        let mid = lerp_color(a, b, 0.5);
        assert_eq!((mid.r(), mid.g(), mid.b()), (50, 100, 25));
        // Out-of-range t clamps rather than extrapolating.
        assert_eq!(lerp_color(a, b, 2.0), b);
    }
}
