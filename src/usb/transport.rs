//! Transport abstraction so protocol logic is not tied to one USB crate.
//!
//! Implements the transfers the MT7601U vendor protocol needs: interface
//! claim/release plus control and bulk transfers.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use rusb::{Context, DeviceHandle, UsbContext};

use super::enumerate::{DeviceInfo, UsbError};

/// Minimal device transport.
pub trait Transport: Sized {
    /// Open the device described by `info`.
    fn open(info: &DeviceInfo) -> Result<Self, UsbError>;

    /// Claim an interface so it can be used for transfers.
    fn claim_interface(&mut self, interface: u8) -> Result<(), UsbError>;

    /// Release a previously claimed interface.
    fn release_interface(&mut self, interface: u8) -> Result<(), UsbError>;

    /// Whether a usable device handle is currently held.
    fn is_open(&self) -> bool;

    /// Release all claimed interfaces and drop the handle.
    fn close(&mut self);

    /// Control transfer, OUT direction. Returns the number of bytes transferred.
    fn control_out(
        &self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
        timeout: Duration,
    ) -> Result<usize, UsbError>;

    /// Control transfer, IN direction. Returns the number of bytes received.
    fn control_in(
        &self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, UsbError>;

    /// Bulk transfer, OUT direction. Returns the number of bytes transferred.
    fn bulk_out(&self, endpoint: u8, data: &[u8], timeout: Duration) -> Result<usize, UsbError>;

    /// Bulk transfer, IN direction. Returns the number of bytes received.
    fn bulk_in(&self, endpoint: u8, buf: &mut [u8], timeout: Duration) -> Result<usize, UsbError>;
}

/// `rusb` (libusb) backed transport.
///
/// The libusb handle is shared behind an [`Arc`] so a second copy of this
/// transport can drive concurrent transfers from another thread (the receive
/// reader, [`super::rx_pump::RxPump`]). libusb handles are thread-safe; the
/// interface claims stay with the original owner.
pub struct RusbTransport {
    handle: Arc<DeviceHandle<Context>>,
    claimed: BTreeSet<u8>,
}

impl RusbTransport {
    /// Interfaces currently claimed by this transport.
    pub fn claimed_interfaces(&self) -> &BTreeSet<u8> {
        &self.claimed
    }
}

impl Clone for RusbTransport {
    /// A second handle to the same device, for concurrent transfers.
    ///
    /// The claim bookkeeping deliberately stays behind: the clone only runs
    /// transfers, and dropping it must not release interfaces the original
    /// still owns. libusb closes the device when the last copy goes away.
    fn clone(&self) -> Self {
        Self {
            handle: Arc::clone(&self.handle),
            claimed: BTreeSet::new(),
        }
    }
}

impl Transport for RusbTransport {
    fn open(info: &DeviceInfo) -> Result<Self, UsbError> {
        let context = Context::new()?;
        for device in context.devices()?.iter() {
            let descriptor = match device.device_descriptor() {
                Ok(descriptor) => descriptor,
                Err(_) => continue,
            };
            if descriptor.vendor_id() != info.vid
                || descriptor.product_id() != info.pid
                || device.bus_number() != info.bus
                || device.address() != info.address
            {
                continue;
            }

            let handle = device.open()?;
            // Best effort: on Linux this detaches a kernel driver; on macOS it
            // is a no-op. Failure is not fatal here.
            let _ = handle.set_auto_detach_kernel_driver(true);
            return Ok(Self {
                handle: Arc::new(handle),
                claimed: BTreeSet::new(),
            });
        }
        Err(UsbError::NotFound)
    }

    fn claim_interface(&mut self, interface: u8) -> Result<(), UsbError> {
        self.handle.claim_interface(interface)?;
        self.claimed.insert(interface);
        Ok(())
    }

    fn release_interface(&mut self, interface: u8) -> Result<(), UsbError> {
        self.handle.release_interface(interface)?;
        self.claimed.remove(&interface);
        Ok(())
    }

    fn is_open(&self) -> bool {
        true
    }

    fn close(&mut self) {
        let claimed: Vec<u8> = self.claimed.iter().copied().collect();
        for interface in claimed {
            let _ = self.handle.release_interface(interface);
            self.claimed.remove(&interface);
        }
    }

    fn control_out(
        &self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
        timeout: Duration,
    ) -> Result<usize, UsbError> {
        Ok(self
            .handle
            .write_control(request_type, request, value, index, data, timeout)?)
    }

    fn control_in(
        &self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, UsbError> {
        Ok(self
            .handle
            .read_control(request_type, request, value, index, buf, timeout)?)
    }

    fn bulk_out(&self, endpoint: u8, data: &[u8], timeout: Duration) -> Result<usize, UsbError> {
        Ok(self.handle.write_bulk(endpoint, data, timeout)?)
    }

    fn bulk_in(&self, endpoint: u8, buf: &mut [u8], timeout: Duration) -> Result<usize, UsbError> {
        Ok(self.handle.read_bulk(endpoint, buf, timeout)?)
    }
}
