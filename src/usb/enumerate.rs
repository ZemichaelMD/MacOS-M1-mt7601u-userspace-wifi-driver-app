//! Enumerate USB devices and describe their descriptors.
//!
//! Nothing is hardcoded from an unverified description: every field comes from
//! the actual descriptors returned by the device.

use std::time::Duration;

use rusb::{Context, Device, UsbContext};

use crate::mt7601u;

/// Timeout for the (best-effort) string-descriptor reads.
const STRING_TIMEOUT: Duration = Duration::from_millis(300);

/// Errors produced by the USB layer.
#[derive(Debug, thiserror::Error)]
pub enum UsbError {
    /// An error bubbled up from `libusb`/`rusb`.
    #[error("libusb error: {0}")]
    Libusb(#[from] rusb::Error),
    /// The requested device is no longer attached.
    #[error("device not found")]
    NotFound,
    /// Firmware image handling failed.
    #[error("firmware: {0}")]
    Firmware(String),
    /// Any other USB-related failure.
    #[error("{0}")]
    Other(String),
}

/// Transfer type of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbTransferType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
    Unknown,
}

impl UsbTransferType {
    fn from_rusb(value: rusb::TransferType) -> Self {
        match value {
            rusb::TransferType::Control => Self::Control,
            rusb::TransferType::Isochronous => Self::Isochronous,
            rusb::TransferType::Bulk => Self::Bulk,
            rusb::TransferType::Interrupt => Self::Interrupt,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Control => "Control",
            Self::Isochronous => "Isochronous",
            Self::Bulk => "Bulk",
            Self::Interrupt => "Interrupt",
            Self::Unknown => "Unknown",
        }
    }
}

/// Negotiated USB link speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    Low,
    Full,
    High,
    Super,
    SuperPlus,
    Unknown,
}

impl UsbSpeed {
    fn from_rusb(value: rusb::Speed) -> Self {
        match value {
            rusb::Speed::Low => Self::Low,
            rusb::Speed::Full => Self::Full,
            rusb::Speed::High => Self::High,
            rusb::Speed::Super => Self::Super,
            rusb::Speed::SuperPlus => Self::SuperPlus,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "Low (1.5 Mbit/s)",
            Self::Full => "Full (12 Mbit/s)",
            Self::High => "High (480 Mbit/s)",
            Self::Super => "Super (5 Gbit/s)",
            Self::SuperPlus => "SuperPlus (10 Gbit/s)",
            Self::Unknown => "Unknown",
        }
    }
}

/// A single endpoint descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInfo {
    pub address: u8,
    pub is_in: bool,
    pub transfer_type: UsbTransferType,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl EndpointInfo {
    pub fn direction_label(&self) -> &'static str {
        if self.is_in {
            "IN"
        } else {
            "OUT"
        }
    }

    pub fn describe(&self) -> String {
        format!(
            "Endpoint 0x{:02x} ({} {}), max packet {}, interval {}",
            self.address,
            self.direction_label(),
            self.transfer_type.label(),
            self.max_packet_size,
            self.interval
        )
    }
}

/// An interface descriptor (one alternate setting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub number: u8,
    pub alt_setting: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<EndpointInfo>,
}

impl InterfaceInfo {
    pub fn describe(&self) -> String {
        format!(
            "Interface {} alt {}: class 0x{:02x}/0x{:02x}/0x{:02x}, {} endpoint(s)",
            self.number,
            self.alt_setting,
            self.class,
            self.subclass,
            self.protocol,
            self.endpoints.len()
        )
    }
}

/// A configuration descriptor and its interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationInfo {
    pub number: u8,
    pub self_powered: bool,
    pub remote_wakeup: bool,
    pub max_power_ma: u16,
    pub interfaces: Vec<InterfaceInfo>,
}

impl ConfigurationInfo {
    pub fn describe(&self) -> String {
        format!(
            "Configuration {}: self-powered={}, remote-wakeup={}, max power {} mA, {} interface(s)",
            self.number,
            self.self_powered,
            self.remote_wakeup,
            self.max_power_ma,
            self.interfaces.len()
        )
    }
}

/// Snapshot of a USB device's identity and descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub vid: u16,
    pub pid: u16,
    pub bus: u8,
    pub address: u8,
    pub speed: UsbSpeed,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub configurations: Vec<ConfigurationInfo>,
}

impl DeviceInfo {
    /// True when this device is an MT7601U.
    pub fn is_mt7601u(&self) -> bool {
        mt7601u::is_mt7601u(self.vid, self.pid)
    }

    /// Multi-line descriptor dump suitable for the GUI or a terminal.
    ///
    /// The serial number is intentionally reported only as present/absent so
    /// that it never leaks into shared logs.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{:04x}:{:04x} bus {} address {} ({})\n",
            self.vid,
            self.pid,
            self.bus,
            self.address,
            self.speed.label()
        ));
        out.push_str(&format!(
            "  Manufacturer: {}\n",
            self.manufacturer.as_deref().unwrap_or("<none>")
        ));
        out.push_str(&format!(
            "  Product:      {}\n",
            self.product.as_deref().unwrap_or("<none>")
        ));
        out.push_str(&format!(
            "  Serial:       {}\n",
            if self.serial.is_some() {
                "<present, redacted>"
            } else {
                "<none>"
            }
        ));
        for config in &self.configurations {
            out.push_str(&format!("  {}\n", config.describe()));
            for iface in &config.interfaces {
                out.push_str(&format!("    {}\n", iface.describe()));
                for ep in &iface.endpoints {
                    out.push_str(&format!("      {}\n", ep.describe()));
                }
            }
        }
        out
    }
}

/// Detection state of the MT7601U as reported by the backend.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DeviceStatus {
    #[default]
    Unknown,
    Absent,
    Present(DeviceInfo),
    Open(DeviceInfo),
    Error(String),
}

impl DeviceStatus {
    pub fn label(&self) -> String {
        match self {
            DeviceStatus::Unknown => "Unknown".to_string(),
            DeviceStatus::Absent => "Not detected".to_string(),
            DeviceStatus::Present(_) => "Detected (closed)".to_string(),
            DeviceStatus::Open(_) => "Open (interface claimed)".to_string(),
            DeviceStatus::Error(e) => format!("Error: {e}"),
        }
    }

    pub fn info(&self) -> Option<&DeviceInfo> {
        match self {
            DeviceStatus::Present(info) | DeviceStatus::Open(info) => Some(info),
            _ => None,
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, DeviceStatus::Open(_))
    }
}

/// Read the string descriptor at `index`, if a handle and a language are
/// available. Failures are swallowed because string descriptors are optional.
fn read_string<T: UsbContext>(
    handle: &rusb::DeviceHandle<T>,
    lang: rusb::Language,
    index: u8,
) -> Option<String> {
    if index == 0 {
        return None;
    }
    handle
        .read_string_descriptor(lang, index, STRING_TIMEOUT)
        .ok()
}

/// Build a [`DeviceInfo`] from a `libusb` device, reading descriptors only.
fn describe_device<T: UsbContext>(device: &Device<T>) -> Result<DeviceInfo, UsbError> {
    let desc = device.device_descriptor()?;

    let handle = device.open().ok();
    let lang = handle
        .as_ref()
        .and_then(|h| h.read_languages(STRING_TIMEOUT).ok())
        .and_then(|langs| langs.first().cloned());

    let read = |index: Option<u8>| match (handle.as_ref(), lang.as_ref()) {
        (Some(h), Some(lang)) => index.and_then(|i| read_string(h, *lang, i)),
        _ => None,
    };

    let mut configurations = Vec::new();
    for index in 0..desc.num_configurations() {
        let config = match device.config_descriptor(index) {
            Ok(config) => config,
            Err(_) => continue,
        };

        let mut interfaces = Vec::new();
        for iface in config.interfaces() {
            for iface_desc in iface.descriptors() {
                let endpoints = iface_desc
                    .endpoint_descriptors()
                    .map(|ep| EndpointInfo {
                        address: ep.address(),
                        is_in: matches!(ep.direction(), rusb::Direction::In),
                        transfer_type: UsbTransferType::from_rusb(ep.transfer_type()),
                        max_packet_size: ep.max_packet_size(),
                        interval: ep.interval(),
                    })
                    .collect();

                interfaces.push(InterfaceInfo {
                    number: iface_desc.interface_number(),
                    alt_setting: iface_desc.setting_number(),
                    class: iface_desc.class_code(),
                    subclass: iface_desc.sub_class_code(),
                    protocol: iface_desc.protocol_code(),
                    endpoints,
                });
            }
        }

        configurations.push(ConfigurationInfo {
            number: config.number(),
            self_powered: config.self_powered(),
            remote_wakeup: config.remote_wakeup(),
            max_power_ma: config.max_power() * 2,
            interfaces,
        });
    }

    Ok(DeviceInfo {
        vid: desc.vendor_id(),
        pid: desc.product_id(),
        bus: device.bus_number(),
        address: device.address(),
        speed: UsbSpeed::from_rusb(device.speed()),
        manufacturer: read(desc.manufacturer_string_index()),
        product: read(desc.product_string_index()),
        serial: read(desc.serial_number_string_index()),
        configurations,
    })
}

/// Enumerate every USB device this process can read. Devices that fail to
/// describe are skipped rather than aborting the whole listing.
pub fn list_devices() -> Result<Vec<DeviceInfo>, UsbError> {
    let context = Context::new()?;
    let mut devices = Vec::new();
    for device in context.devices()?.iter() {
        if let Ok(info) = describe_device(&device) {
            devices.push(info);
        }
    }
    Ok(devices)
}

/// Find the first attached MT7601U, if any.
pub fn find_mt7601u() -> Result<Option<DeviceInfo>, UsbError> {
    Ok(list_devices()?.into_iter().find(DeviceInfo::is_mt7601u))
}

/// Whether an MT7601U is attached, without opening a handle on it.
///
/// [`find_mt7601u`] opens the device to read its string descriptors, which must
/// not happen while the driver holds the interface: a second handle's control
/// transfers race with the MCU command channel. This only reads the cached
/// device descriptors, so it is safe to poll while the radio is in use.
pub fn mt7601u_attached() -> Result<bool, UsbError> {
    let context = Context::new()?;
    for device in context.devices()?.iter() {
        let Ok(descriptor) = device.device_descriptor() else {
            continue;
        };
        if mt7601u::is_mt7601u(descriptor.vendor_id(), descriptor.product_id()) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device() -> DeviceInfo {
        DeviceInfo {
            vid: mt7601u::VENDOR_ID,
            pid: mt7601u::PRODUCT_ID,
            bus: 1,
            address: 4,
            speed: UsbSpeed::High,
            manufacturer: Some("MediaTek".into()),
            product: Some("802.11 n WLAN".into()),
            serial: Some("1.0".into()),
            configurations: vec![ConfigurationInfo {
                number: 1,
                self_powered: false,
                remote_wakeup: false,
                max_power_ma: 160,
                interfaces: vec![InterfaceInfo {
                    number: 0,
                    alt_setting: 0,
                    class: 0xff,
                    subclass: 0x00,
                    protocol: 0x00,
                    endpoints: vec![
                        EndpointInfo {
                            address: 0x81,
                            is_in: true,
                            transfer_type: UsbTransferType::Bulk,
                            max_packet_size: 512,
                            interval: 0,
                        },
                        EndpointInfo {
                            address: 0x01,
                            is_in: false,
                            transfer_type: UsbTransferType::Bulk,
                            max_packet_size: 512,
                            interval: 0,
                        },
                    ],
                }],
            }],
        }
    }

    #[test]
    fn describe_redacts_serial() {
        let text = sample_device().describe();
        assert!(text.contains("Serial:       <present, redacted>"));
        assert!(!text.contains("1.0\n"));
    }

    #[test]
    fn describe_includes_endpoints() {
        let text = sample_device().describe();
        assert!(text.contains("Endpoint 0x81 (IN Bulk)"));
        assert!(text.contains("Endpoint 0x01 (OUT Bulk)"));
        assert!(text.contains("148f:7601"));
    }

    #[test]
    fn endpoint_direction_labels() {
        let ep = EndpointInfo {
            address: 0x81,
            is_in: true,
            transfer_type: UsbTransferType::Bulk,
            max_packet_size: 512,
            interval: 0,
        };
        assert_eq!(ep.direction_label(), "IN");
    }

    #[test]
    fn device_status_helpers() {
        assert_eq!(DeviceStatus::Absent.label(), "Not detected");
        assert!(DeviceStatus::Absent.info().is_none());
        let open = DeviceStatus::Open(sample_device());
        assert!(open.is_open());
        assert!(open.info().is_some());
    }
}
