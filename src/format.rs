//! Human-readable formatting for byte counts and throughput, shared by the
//! backend's periodic log line and the GUI.

/// Format a byte-per-second rate as a bit rate, the way "internet speed" is
/// normally quoted.
pub fn format_rate(bytes_per_sec: f64) -> String {
    let bits = bytes_per_sec.max(0.0) * 8.0;
    if bits >= 1e9 {
        format!("{:.2} Gbps", bits / 1e9)
    } else if bits >= 1e6 {
        format!("{:.1} Mbps", bits / 1e6)
    } else if bits >= 1e3 {
        format!("{:.0} Kbps", bits / 1e3)
    } else {
        format!("{bits:.0} bps")
    }
}

/// Format a byte total with a binary-ish SI unit.
pub fn format_bytes(bytes: u64) -> String {
    let value = bytes as f64;
    if value >= 1e9 {
        format!("{:.2} GB", value / 1e9)
    } else if value >= 1e6 {
        format!("{:.1} MB", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1} KB", value / 1e3)
    } else {
        format!("{bytes} B")
    }
}

/// Format a frame count compactly.
pub fn format_count(count: u64) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1e6)
    } else if count >= 1_000 {
        format!("{:.1}k", count as f64 / 1e3)
    } else {
        count.to_string()
    }
}

/// The menu bar readout: `↑ up  ↓ down`, or empty when the relay is idle.
pub fn format_status_rates(rates: Option<(f64, f64)>) -> String {
    match rates {
        Some((up, down)) => format!("↑ {}  ↓ {}", format_rate(up), format_rate(down)),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_render_in_network_units() {
        assert_eq!(format_rate(0.0), "0 bps");
        assert_eq!(format_rate(125_000.0), "1.0 Mbps");
        assert_eq!(format_rate(1_000_000.0), "8.0 Mbps");
        assert_eq!(format_rate(12_500_000.0), "100.0 Mbps");
    }

    #[test]
    fn byte_totals_render_in_si_units() {
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_500), "1.5 KB");
        assert_eq!(format_bytes(2_000_000), "2.0 MB");
    }

    #[test]
    fn status_rates_render_up_then_down() {
        assert_eq!(
            format_status_rates(Some((1_000.0, 1_000_000.0))),
            "↑ 8 Kbps  ↓ 8.0 Mbps"
        );
        assert_eq!(format_status_rates(None), "");
    }

    #[test]
    fn counts_are_compact() {
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_500), "1.5k");
        assert_eq!(format_count(2_400_000), "2.4M");
    }
}
