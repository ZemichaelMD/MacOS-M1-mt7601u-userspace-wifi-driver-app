# Icon & Asset Specifications

Contract for every image asset the app can consume: **what** to make, **which
format / resolution / transparency**, and **where to drop the files** so the
build and the UI pick them up.

Nothing here is required for the app to run — the UI icons are currently drawn
as vectors in code (`src/app.rs`), and the menu-bar item uses the SF Symbol
`wifi`. Assets are how you replace that with your own art.

---

## 1. TL;DR

| Asset | Format | Resolution | Transparency | Route |
| --- | --- | --- | --- | --- |
| App icon (Dock / Finder / app drawer) | `.icns` (built from PNG) | 16 → 1024 px set | Yes (RGBA) | `assets/AppIcon.icns` |
| App icon masters | PNG | 16,32,64,128,256,512,1024 | Yes (RGBA) | `assets/app-icon/AppIcon.iconset/` |
| Menu-bar (status item) logo | PNG (template) | 18 pt + @2x (36 px) | Yes (RGBA) | `assets/menubar/` |
| In-app UI icons | PNG | logical px + @2x | Yes (RGBA) | `assets/ui/` |
| DMG installer background (optional) | PNG | 540×380 + @2x | Yes or opaque | `assets/dmg/dmg-background.png` |

Deliver **PNG-24 with an alpha channel (RGBA)**, sRGB, at **@1x and @2x**.
SVG masters are welcome as a source you keep, but the app consumes rasterized
PNG (egui has no SVG loader), so export PNG for delivery.

---

## 2. Rules that apply to every asset

- **Format:** PNG, 24-bit color + 8-bit alpha. Do not deliver JPEG or flat
  (no-alpha) PNGs for anything that sits on the app background.
- **Color space:** sRGB. Embed no color profile (or sRGB IEC61966-2.1).
- **Transparency:** Required for the app icon (outside the rounded shape),
  the menu-bar icon, and all in-app UI icons. Keep the corners/background fully
  transparent, not a fake canvas color.
- **Resolutions:** Provide **@1x and @2x** of each file (`name.png`,
  `name@2x.png`). @2x is the important one on Retina; @3x is unnecessary here.
- **Monochrome vs color:**
  - Icons the app recolors (tints to match state) must be delivered as a
    **pure-black silhouette (`#000000`) with alpha only**. The app supplies the
    color. Never bake in a tint for these.
  - Icons that are inherently colored (e.g. warning, signal-strength bars) may
    be delivered full-color. Say which is which when you hand them over.
- **Optical weight:** Design at the stated logical size so a 1.5 px stroke stays
  ≥ ~1.5 px after scaling. Avoid hairlines; they alias.
- **Naming:** lowercase, hyphenated, no spaces (`plug-usb@2x.png`).
- **Do not** put assets under `src/` or `target/`; they live under `assets/`
  (repo root). `assets/` is not git-ignored.

Reference palette (from `src/theme.rs`) so art can match the app:

| Token | Hex | Use |
| --- | --- | --- |
| `ACCENT` | `#F0B429` | brand / Wi-Fi mark, active controls |
| `OK` | `#4ED8A0` | good / relaying |
| `WARN` | `#F08C3C` | warning triangle |
| `ERROR` | `#FF6B66` | failure |
| `DEVICE` | `#7FB2E5` | USB device |
| `DOWN` | `#5AA9FF` | download |
| `UP` | `#B48CFF` | upload |
| `TEXT` | `#E8EEF5` | primary text |
| `MUTED` | `#96A3B3` | secondary |
| `FAINT` | `#6B7A8C` | least emphasis |
| `CANVAS` | `#0C1016` | window background |
| `PANEL` | `#12171F` | panel |
| `SURFACE` | `#171E27` | surface |
| `RAISED` | `#1F2833` | raised surface |

---

## 3. App icon (Dock, Finder, "app drawer")

macOS does not mask app icons for you — **you bake the rounded-rectangle shape
into the artwork** and leave everything outside it transparent.

- **Canvas:** 1024×1024 px, transparent.
- **Body:** a centered rounded rectangle **824×824 px** (100 px margin on all
  sides), corner radius **~185 px**, matching Apple's Big Sur icon grid.
- **Artwork:** keep essential details inside a ~10% inner safe area; the motif
  should read at 16 px. Rounded-rect sprocket corners must be clean.
- **Shadow:** optional subtle drop shadow inside the transparent margin; skip if
  unsure (the system adds none for macOS).

### Deliverables

1. **Final icon** at `assets/AppIcon.icns`. The bundle script already looks for
   exactly this path and adds `CFBundleIconFile` automatically
   (`scripts/bundle-macos-app.sh`), so once the file exists every
   `dist/*.app` gets the icon with no code change.
2. **Masters** in an iconset so the `.icns` can be regenerated:

   ```
   assets/app-icon/AppIcon.iconset/
     icon_16x16.png        (16×16)
     icon_16x16@2x.png     (32×32)
     icon_32x32.png        (32×32)
     icon_32x32@2x.png     (64×64)
     icon_128x128.png      (128×128)
     icon_128x128@2x.png   (256×256)
     icon_256x256.png      (256×256)
     icon_256x256@2x.png   (512×512)
     icon_512x512.png      (512×512)
     icon_512x512@2x.png   (1024×1024)
   ```

   Build the `.icns` with:

   ```
   iconutil -c icns assets/app-icon/AppIcon.iconset -o assets/AppIcon.icns
   ```

   (A 1024×1024 master PNG is enough to generate the whole set; `sips` can
   downscale it.)

### Concept

The in-app mark is the Wi-Fi arc motif in the accent color. The app icon should
be the "hero" version of that: the arcs (or the USB dongle + arcs) on a
`CANVAS`→`RAISED` background with the accent, high contrast, no text.

---

## 4. Menu-bar (status item) logo

Shown in the macOS menu bar next to the live up/down throughput.

- **Type:** template image — **black (`#000000`) artwork, alpha only**, no color;
  macOS tints it for light/dark menu bars. (`src/menu_bar.rs` calls
  `setTemplate(true)`; keep the art a pure silhouette.)
- **Canvas:** 18×18 pt; draw the glyph ~15–16 pt tall, optically centered.
- **Deliver:** `status.png` (18×18) and `status@2x.png` (36×36). @3x (54×54)
  optional.
- **Stroke:** ≥ 1.5 pt at 18 pt; no detail that disappears at 18 pt.

### Route

```
assets/menubar/
  status.png
  status@2x.png
```

> Wiring note: the status item currently renders an SF Symbol. Using this PNG is
> a small code change (load the image instead of
> `imageWithSystemSymbolName_…`); the file just needs to exist at the path above.

---

## 5. In-app UI icons

All are **transparent RGBA PNG at the logical size + @2x** (e.g. a 16 px icon
ships as `16×16` and `32×32`). Unless noted "full-color", deliver a
**black silhouette with alpha** so the app tints it (`color::TEXT/MUTED/ACCENT/…`).

| File (`assets/ui/`) | Used for | Logical size | Color |
| --- | --- | --- | --- |
| `power` | Hero "Stopped" state; toolbar Start/Stop button | 40 (hero) / 16 (button) | Monochrome |
| `plug-usb` | Hero "absent"; empty state "Stopped" / "No dongle detected" | 34–46 | Monochrome |
| `radar` | Hero "scanning"; empty state "Scanning…" / "No networks found" | 40–46 | Monochrome (+ optional accent sweep layer) |
| `spinner` | Hero "working"; empty state "Starting…" / "Waiting for the radio" | 28–40 | Monochrome |
| `warning` | Hero "attention"; empty state "Scan failed" | 34–46 | Full-color `WARN` `#F08C3C` |
| `wifi` | Hero "joined"/"relaying"; also the header product mark | 30–42 | Monochrome (tinted `ACCENT`) |
| `check` | Row marker for the connected network; relaying badge | 14 | Monochrome |
| `lock` | Secured network row | 14 | Monochrome |
| `sliders` | Toolbar Settings button | 16 | Monochrome |
| `terminal` | Toolbar Logs button | 16 | Monochrome |
| `signal-0` … `signal-4` | Network-row signal meter, one file per level | 20×16 | Full-color (see below) |

### Animated glyphs (`radar`, `spinner`)

The app animates these itself (it draws a rotating sweep / an arc that spins),
so a **static** PNG is fine — supply the base rings/shape only. If you prefer to
ship motion, provide an 8–12 frame horizontal sprite sheet named
`radar-sheet.png` / `spinner-sheet.png` (frames of equal width) and note the
frame count.

### Signal bars (`signal-0` … `signal-4`)

- `signal-0` = no signal (outline/dim), `signal-4` = full.
- Full-color variant: filled bars use `OK` `#4ED8A0`, empty bars `FAINT`
  `#6B7A8C`. If you would rather ship monochrome, the app will tint by level;
  say so and we keep a single mask.

### Route

```
assets/ui/
  power.png            power@2x.png
  plug-usb.png         plug-usb@2x.png
  radar.png            radar@2x.png
  spinner.png          spinner@2x.png
  warning.png          warning@2x.png
  wifi.png             wifi@2x.png
  check.png            check@2x.png
  lock.png             lock@2x.png
  sliders.png          sliders@2x.png
  terminal.png         terminal@2x.png
  signal-0.png … signal-4.png   (+ @2x for each)
```

> These are optional. The current hand-drawn vectors work; supplying PNGs means
> replacing the draw calls with textured images (a code change). Hand off a set
> and we wire it in one pass.

---

## 6. Optional extras

| File | Purpose | Spec |
| --- | --- | --- |
| `assets/ui/mark@2x.png` | Standalone header logo tile (currently drawn in code) | 30 px, tinted `ACCENT`, transparent |
| `assets/dmg/dmg-background.png` | DMG window background | 540×380 + @2x (1080×760), can be opaque |
| `assets/branding/wordmark.png` | "MT7601U Bridge" lockup for About/docs | transparent, height ~64 px, @2x |
| `assets/AppIcon-master.png` | Editable 1024 png master | 1024×1024, transparent |

---

## 7. What is automatic vs. what needs code

- **Automatic:** `assets/AppIcon.icns` → bundled and referenced by
  `scripts/bundle-macos-app.sh` (no code change).
- **Needs a code change:** the menu-bar template icon and every `assets/ui/*`
  icon (load once at startup into `egui::TextureHandle`s and draw instead of the
  vector routines). Keep the vector fallback if you want the app to run without
  assets present.

---

## 8. Checklist before handing assets over

- [ ] App icon: 1024 master + `.iconset` PNGs, `assets/AppIcon.icns` built and
      opening correctly in Finder/Dock (rounded shape, transparent corners).
- [ ] Menu-bar: black-on-transparent template PNG @1x/@2x, legible at 18 pt.
- [ ] UI icons: transparent, @1x + @2x, named exactly as in the tables above.
- [ ] Tintable icons are pure black + alpha (no baked color).
- [ ] Colored icons (warning, signal bars) are final color.
- [ ] sRGB, no JPEGs, no spaces in filenames.
