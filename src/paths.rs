//! Locating runtime assets (the firmware blob).
//!
//! The blob is deliberately not vendored; it is found at runtime from a few
//! well-known places so both `cargo run` and a bundled `.app` work.

use std::path::PathBuf;

/// Candidate locations for `mt7601u.bin`, in priority order.
pub fn firmware_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // 1. Explicit override.
    if let Some(explicit) = std::env::var_os("MT7601U_FIRMWARE") {
        paths.push(PathBuf::from(explicit));
    }

    // 2. Inside a macOS bundle: Contents/MacOS/<exe> -> Contents/Resources/.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("../Resources/mt7601u.bin"));
        }
    }

    // 3. Relative to the working directory (handy with `cargo run`).
    paths.push(PathBuf::from("mt7601u.bin"));
    paths.push(PathBuf::from("mediatek/mt7601u.bin"));
    paths.push(PathBuf::from(
        "mt7601u-refs/linux-firmware/mediatek/mt7601u.bin",
    ));

    // 4. Per-user locations.
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        paths.push(home.join(".mt7601u/mt7601u.bin"));
        paths.push(home.join("Downloads/mt7601u.bin"));
    }

    paths
}

/// The first existing firmware candidate, if any.
pub fn find_firmware() -> Option<PathBuf> {
    firmware_candidates()
        .into_iter()
        .find(|path| path.is_file())
}

/// Per-user directory for saved networks and preferences.
pub fn data_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join("Library/Application Support/mt7601u-macos"),
        None => std::env::temp_dir().join("mt7601u-macos"),
    }
}

/// Where saved passphrases and preferences live. Created `0600`.
pub fn credentials_file() -> PathBuf {
    data_dir().join("credentials")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_non_empty_and_ordered() {
        let paths = firmware_candidates();
        assert!(!paths.is_empty());
        // The bare relative path is always included.
        assert!(paths.contains(&PathBuf::from("mt7601u.bin")));
    }
}
