//! The application icon, decoded from the bundled `assets/AppIcon.icns`.
//!
//! The `.icns` is embedded in the binary, so the icon travels with the
//! executable and does not depend on the working directory or an installed
//! bundle. `eframe` wants raw RGBA for the window icon and macOS wants an
//! `NSImage` for the Dock; both are produced from the same embedded bytes.
//!
//! An `.icns` is a container of typed chunks. Modern icons store each
//! resolution as a PNG, so we pick the largest PNG frame and hand it to the
//! `png` decoder — no ImageIO round-trip and no per-platform image code.

/// The bundled icon.
const ICNS: &[u8] = include_bytes!("../assets/AppIcon.icns");

/// Decode the largest PNG frame in the `.icns` into an [`egui::IconData`].
///
/// Returns `None` when the icon cannot be parsed; the caller simply runs
/// without a window icon.
pub fn window_icon() -> Option<egui::IconData> {
    decode_png(largest_png(ICNS)?)
}

/// The largest PNG chunk carried by an `.icns` container.
fn largest_png(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 8 || &bytes[..4] != b"icns" {
        return None;
    }
    let declared = u32::from_be_bytes(bytes[4..8].try_into().ok()?) as usize;
    let end = declared.min(bytes.len());

    let mut best: Option<&[u8]> = None;
    let mut offset = 8;
    while offset + 8 <= end {
        let length =
            u32::from_be_bytes(bytes[offset + 4..offset + 8].try_into().ok()?) as usize;
        if length < 8 || offset + length > bytes.len() {
            break;
        }
        let chunk = &bytes[offset + 8..offset + length];
        if chunk.starts_with(b"\x89PNG\r\n\x1a\n") && best.is_none_or(|best| best.len() < chunk.len())
        {
            best = Some(chunk);
        }
        offset += length;
    }
    best
}

/// Decode a PNG into straight RGBA8.
fn decode_png(data: &[u8]) -> Option<egui::IconData> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(data));
    // Widen palette/grayscale and drop 16-bit samples so every input lands in
    // 8-bit RGBA or a simple 8-bit form we can expand.
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().ok()?;

    let mut buffer = vec![0u8; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buffer).ok()?;
    let frame = &buffer[..info.buffer_size()];

    let rgba = match info.color_type {
        png::ColorType::Rgba => frame.to_vec(),
        png::ColorType::Rgb => frame
            .as_chunks::<3>()
            .0
            .iter()
            .flat_map(|pixel| [pixel[0], pixel[1], pixel[2], 0xff])
            .collect(),
        png::ColorType::Grayscale => frame
            .iter()
            .flat_map(|&grey| [grey, grey, grey, 0xff])
            .collect(),
        png::ColorType::GrayscaleAlpha => frame
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|pixel| [pixel[0], pixel[0], pixel[0], pixel[1]])
            .collect(),
        // `normalize_to_color8` expands the palette, so this cannot occur.
        png::ColorType::Indexed => return None,
    };

    Some(egui::IconData {
        rgba,
        width: info.width,
        height: info.height,
    })
}

/// Set the macOS Dock icon from the embedded `.icns`.
///
/// No-op anywhere else. Best-effort: a failure leaves the default icon.
#[cfg(target_os = "macos")]
pub fn set_dock_icon() {
    use objc2::AllocAnyThread;
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;

    let Some(marker) = MainThreadMarker::new() else {
        return;
    };
    let data = NSData::with_bytes(ICNS);
    let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) else {
        return;
    };
    let app = NSApplication::sharedApplication(marker);
    // SAFETY: on the main thread (checked above), with a valid `NSImage`.
    unsafe { app.setApplicationIconImage(Some(&image)) };
}

/// Off macOS there is no Dock icon to set.
#[cfg(not(target_os = "macos"))]
pub fn set_dock_icon() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_icon_decodes_to_a_square_rgba_image() {
        let icon = window_icon().expect("assets/AppIcon.icns should decode");
        assert_eq!(icon.width, icon.height);
        assert!(icon.width >= 128, "want a reasonably sized frame");
        assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
    }
}
