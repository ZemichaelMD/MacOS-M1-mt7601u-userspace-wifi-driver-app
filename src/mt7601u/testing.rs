//! Shared test doubles for the MT7601U driver layer.
//!
//! Only compiled under `cfg(test)`.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use crate::mt7601u::{dma, regs};
use crate::usb::{
    ConfigurationInfo, DeviceInfo, EndpointInfo, InterfaceInfo, Transport, UsbError, UsbSpeed,
    UsbTransferType,
};

/// The RX bulk IN endpoint in [`device_info`] (first bulk IN, descriptor order).
pub const RX_ENDPOINT: u8 = 0x84;

/// A recorded control transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Out {
        request: u8,
        value: u16,
        index: u16,
        data: Vec<u8>,
    },
    In {
        request: u8,
        value: u16,
        index: u16,
    },
}

/// An in-memory [`Transport`] that serves canned register reads, records
/// transfers, and can return a canned bulk-IN response.
#[derive(Default)]
pub struct MockTransport {
    registers: RefCell<HashMap<u16, u32>>,
    /// Canned responses for repeated reads of one register (a FIFO): each read
    /// pops the next value, then the static `registers` map serves the rest.
    reg_reads: RefCell<HashMap<u16, VecDeque<u32>>>,
    calls: RefCell<Vec<Call>>,
    pub bulk_writes: RefCell<Vec<(u8, Vec<u8>)>>,
    bulk_in_data: RefCell<Option<Vec<u8>>>,
    /// Frames handed to the RX endpoint, one per read (FIFO).
    rx_frames: RefCell<VecDeque<Vec<u8>>>,
    /// Whether reads with nothing queued time out (a live but idle endpoint)
    /// instead of reporting the canned-data error.
    bulk_in_timeout: Cell<bool>,
    /// Clear `MT_USB_DMA_CFG.RX_BUSY` once the RX endpoint is read, the way the
    /// RX DMA engine reports itself idle only after the pending transfer has
    /// been read out (and stays busy otherwise, wedging a later bring-up).
    rx_busy_clears_after_bulk_in: Cell<bool>,
    auto_cmd_ack: Cell<bool>,
    /// Last value written to each control `wIndex`. The BBP/RF command registers
    /// echo the address they were given, and `bbp_rr` / `rf_rr` reject a read
    /// whose address does not come back, so the mock needs to remember it.
    last_writes: RefCell<HashMap<u16, u32>>,
}

impl MockTransport {
    /// Create a mock whose register `index` reads return the given values.
    pub fn with_registers(entries: &[(u32, u32)]) -> Self {
        let mock = Self::default();
        {
            let mut regs = mock.registers.borrow_mut();
            for (offset, value) in entries {
                regs.insert(*offset as u16, *value);
            }
        }
        mock
    }

    /// Queue the next register value a read of `offset` returns; each queued
    /// value is served once, in order (models a read-to-pop FIFO register).
    pub fn push_reg_read(&self, offset: u32, value: u32) {
        self.reg_reads
            .borrow_mut()
            .entry(offset as u16)
            .or_default()
            .push_back(value);
    }

    /// Set the payload returned by the next bulk-IN transfers.
    pub fn set_bulk_in(&self, data: Vec<u8>) {
        *self.bulk_in_data.borrow_mut() = Some(data);
    }

    /// Queue one DMA-framed buffer for the RX endpoint; each read pops one.
    pub fn push_rx_frame(&self, data: Vec<u8>) {
        self.rx_frames.borrow_mut().push_back(data);
    }

    /// Make reads with nothing queued time out, the way a live but idle
    /// endpoint behaves, instead of reporting the canned-data error.
    ///
    /// For the receive reader (`usb::rx_pump`) an idle read must look like a
    /// timeout: it re-arms the transfer, where any other error is fatal.
    pub fn time_out_empty_bulk_in(&self) {
        self.bulk_in_timeout.set(true);
    }

    /// Apply the RX DMA quirk: `MT_USB_DMA_CFG.RX_BUSY` stays set until a bulk
    /// IN reads the pending receive data out, and clears afterwards. Models the
    /// engine that hangs a later bring-up when nothing arms the endpoint.
    pub fn clear_rx_busy_after_bulk_in(&self) {
        self.rx_busy_clears_after_bulk_in.set(true);
    }

    /// Automatically acknowledge MCU commands: a bulk-IN read returns a
    /// `CMD_DONE` response whose sequence matches the last command written.
    pub fn ack_mcu_commands(&self) {
        self.auto_cmd_ack.set(true);
    }

    /// Recorded control transfers.
    pub fn calls(&self) -> std::cell::Ref<'_, Vec<Call>> {
        self.calls.borrow()
    }
}

/// A device with one bulk IN (`0x84`), one MCU-response bulk IN (`0x85`), and
/// one bulk OUT (`0x08`) endpoint, matching the captured descriptors.
pub fn device_info() -> DeviceInfo {
    DeviceInfo {
        vid: 0x148f,
        pid: 0x7601,
        bus: 1,
        address: 4,
        speed: UsbSpeed::High,
        manufacturer: None,
        product: None,
        serial: None,
        configurations: vec![ConfigurationInfo {
            number: 1,
            self_powered: false,
            remote_wakeup: false,
            max_power_ma: 320,
            interfaces: vec![InterfaceInfo {
                number: 0,
                alt_setting: 0,
                class: 0xff,
                subclass: 0xff,
                protocol: 0xff,
                endpoints: vec![
                    endpoint(0x84, true),
                    endpoint(0x85, true),
                    endpoint(0x08, false),
                    endpoint(0x04, false),
                    endpoint(0x05, false),
                    endpoint(0x06, false),
                    endpoint(0x07, false),
                    endpoint(0x09, false),
                ],
            }],
        }],
    }
}

fn endpoint(address: u8, is_in: bool) -> EndpointInfo {
    EndpointInfo {
        address,
        is_in,
        transfer_type: UsbTransferType::Bulk,
        max_packet_size: 512,
        interval: 0,
    }
}

impl Transport for MockTransport {
    fn open(_info: &DeviceInfo) -> Result<Self, UsbError> {
        Ok(Self::default())
    }
    fn claim_interface(&mut self, _interface: u8) -> Result<(), UsbError> {
        Ok(())
    }
    fn release_interface(&mut self, _interface: u8) -> Result<(), UsbError> {
        Ok(())
    }
    fn is_open(&self) -> bool {
        true
    }
    fn close(&mut self) {}
    fn control_out(
        &self,
        _request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
        _timeout: Duration,
    ) -> Result<usize, UsbError> {
        self.calls.borrow_mut().push(Call::Out {
            request,
            value,
            index,
            data: data.to_vec(),
        });
        self.last_writes
            .borrow_mut()
            .insert(index, u32::from(value));
        Ok(data.len())
    }
    fn control_in(
        &self,
        _request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
        _timeout: Duration,
    ) -> Result<usize, UsbError> {
        self.calls.borrow_mut().push(Call::In {
            request,
            value,
            index,
        });
        let mut register = self
            .reg_reads
            .borrow_mut()
            .get_mut(&index)
            .and_then(VecDeque::pop_front)
            .or_else(|| self.registers.borrow().get(&index).copied())
            .unwrap_or(0);

        // A BBP/RF read echoes the address (and bank) it was given, with the data
        // in a low byte field. Serve the canned data with the last written
        // address so that `bbp_rr` / `rf_rr` accept the read.
        for (command, data_mask) in [
            (regs::MT_BBP_CSR_CFG as u16, regs::MT_BBP_CSR_CFG_VAL),
            (regs::MT_RF_CSR_CFG as u16, regs::MT_RF_CSR_CFG_DATA),
        ] {
            if index == command {
                let address = self.last_writes.borrow().get(&index).copied().unwrap_or(0);
                register = (address & !data_mask) | (register & data_mask);
            }
        }

        let bytes = register.to_le_bytes();
        buf[..4].copy_from_slice(&bytes);
        Ok(buf.len())
    }
    fn bulk_out(&self, endpoint: u8, data: &[u8], _timeout: Duration) -> Result<usize, UsbError> {
        self.bulk_writes
            .borrow_mut()
            .push((endpoint, data.to_vec()));
        Ok(data.len())
    }
    fn bulk_in(&self, endpoint: u8, buf: &mut [u8], _timeout: Duration) -> Result<usize, UsbError> {
        // RX frames are only served to the RX endpoint, so queued management
        // frames are not mistaken for MCU responses on the other bulk IN pipe.
        if endpoint == RX_ENDPOINT {
            if self.rx_busy_clears_after_bulk_in.get() {
                let mut registers = self.registers.borrow_mut();
                let entry = registers.entry(regs::MT_USB_DMA_CFG as u16).or_insert(0);
                *entry &= !regs::MT_USB_DMA_CFG_RX_BUSY;
            }
            if let Some(data) = self.rx_frames.borrow_mut().pop_front() {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                return Ok(n);
            }
        } else if self.auto_cmd_ack.get() {
            if let Some((_, last)) = self.bulk_writes.borrow().last() {
                if last.len() >= dma::MT_DMA_HDR_LEN {
                    let info = u32::from_le_bytes([last[0], last[1], last[2], last[3]]);
                    let seq = dma::command_seq(info);
                    let mut response = [0u8; 16];
                    // CMD_DONE is 0, so only the sequence needs setting.
                    response[..4].copy_from_slice(&(u32::from(seq) << 16).to_le_bytes());
                    let n = response.len().min(buf.len());
                    buf[..n].copy_from_slice(&response[..n]);
                    return Ok(n);
                }
            }
        }

        match self.bulk_in_data.borrow().as_ref() {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
            None if self.bulk_in_timeout.get() => Err(UsbError::Libusb(rusb::Error::Timeout)),
            None => Err(UsbError::Other("no canned bulk-in data".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_report_two_bulk_in_and_six_bulk_out() {
        let info = device_info();
        let endpoints = &info.configurations[0].interfaces[0].endpoints;
        assert_eq!(endpoints.iter().filter(|e| e.is_in).count(), 2);
        assert_eq!(endpoints.iter().filter(|e| !e.is_in).count(), 6);
    }
}
