//! MT7601U device layer: vendor requests, register access, identification and
//! firmware upload.
//!
//! Transcribed from the Linux driver:
//! * vendor requests / register access — `usb.c`
//! * ASIC readiness polling — `core.c`
//! * firmware upload sequence — `mcu.c`
//!
//! Every operation is bounded: transfers have timeouts and polling loops have
//! deadlines.

use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

use crate::usb::{DeviceInfo, EndpointInfo, Transport, UsbError, UsbTransferType};

use super::{dma, firmware, regs};

/// `USB_DIR_IN`.
pub const USB_DIR_IN: u8 = 0x80;
/// `USB_DIR_OUT`.
pub const USB_DIR_OUT: u8 = 0x00;
/// `USB_TYPE_VENDOR` (`0x02 << 5`).
pub const USB_TYPE_VENDOR: u8 = 0x40;
/// `USB_RECIP_DEVICE`.
pub const USB_RECIP_DEVICE: u8 = 0x00;

/// `MT_VEND_DEV_MODE`.
pub const REQ_DEV_MODE: u8 = 1;
/// `MT_VEND_WRITE`.
pub const REQ_WRITE: u8 = 2;
/// `MT_VEND_MULTI_READ`.
pub const REQ_MULTI_READ: u8 = 7;
/// `MT_VEND_WRITE_FCE`.
pub const REQ_WRITE_FCE: u8 = 0x42;

/// `MT_VEND_DEV_MODE_RESET`.
pub const DEV_MODE_RESET: u16 = 1;
/// `MT_VEND_REQ_MAX_RETRY`.
pub const VEND_REQ_MAX_RETRY: u32 = 10;
/// `MT_VEND_REQ_TOUT_MS`.
pub const VEND_REQ_TIMEOUT: Duration = Duration::from_millis(300);
/// Inter-retry delay (`msleep(5)` in `usb.c`).
pub const VEND_REQ_RETRY_DELAY: Duration = Duration::from_millis(5);
/// Register transfer size (`MT_VEND_BUF`).
pub const VEND_BUF_LEN: usize = 4;
/// Vendor request value that hands the IVB to the boot ROM.
pub const DEV_MODE_IVB: u16 = 0x12;

/// Result of reading the device identity registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ident {
    /// `MT_ASIC_VERSION` (0x0000).
    pub asic_version: u32,
    /// `MT_MAC_CSR0` (0x1000).
    pub mac_csr0: u32,
    /// `MT_EFUSE_CTRL` (0x0024).
    pub efuse_ctrl: u32,
}

impl Ident {
    /// True when the ASIC version's top 16 bits identify an MT7601 (`0x7601`).
    pub fn is_mt7601(&self) -> bool {
        (self.asic_version >> 16) == 0x7601
    }

    /// Low 16 bits of the ASIC version register.
    pub fn asic_revision(&self) -> u16 {
        (self.asic_version & 0xffff) as u16
    }

    /// Whether an eFuse is present (`MT_EFUSE_CTRL_SEL`).
    pub fn efuse_present(&self) -> bool {
        self.efuse_ctrl & regs::MT_EFUSE_CTRL_SEL != 0
    }
}

/// Summary of a successful firmware upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareLoad {
    pub version: String,
    pub build: u16,
    pub build_time: String,
    pub ilm_bytes: usize,
    pub dlm_bytes: usize,
}

/// MT7601U device driver over a [`Transport`].
pub struct Mt7601u<T: Transport> {
    transport: T,
    info: DeviceInfo,
    /// MCU command sequence number (`dev->mcu.msg_seq` in `mcu.c`).
    msg_seq: Cell<u8>,
    /// Received data frames recorded while a DHCP exchange is waiting.
    frame_trace: RefCell<Vec<super::data::FrameTrace>>,
    /// Whether [`Self::frame_trace`] is being recorded into.
    trace_enabled: Cell<bool>,
}

impl<T: Transport> Mt7601u<T> {
    /// Wrap an open transport plus the descriptors captured at enumeration time.
    pub fn new(transport: T, info: DeviceInfo) -> Self {
        Self {
            transport,
            info,
            msg_seq: Cell::new(0),
            frame_trace: RefCell::new(Vec::new()),
            trace_enabled: Cell::new(false),
        }
    }

    /// Start recording every received data frame seen by the receive loop.
    ///
    /// Called around a DHCP exchange so a reply that arrives but is rejected is
    /// captured before the client's own receive loop discards it.
    pub fn start_frame_trace(&self) {
        self.frame_trace.borrow_mut().clear();
        self.trace_enabled.set(true);
    }

    /// Stop recording.
    pub fn stop_frame_trace(&self) {
        self.trace_enabled.set(false);
    }

    /// The frames recorded since [`Self::start_frame_trace`].
    pub fn frame_trace(&self) -> Vec<super::data::FrameTrace> {
        self.frame_trace.borrow().clone()
    }

    /// Whether frames are currently being recorded. The receive path checks
    /// this before doing any of the tracing work.
    pub fn is_frame_trace_enabled(&self) -> bool {
        self.trace_enabled.get()
    }

    /// Record one frame if tracing is enabled (bounded).
    pub(crate) fn record_frame_trace(&self, entry: super::data::FrameTrace) {
        if !self.trace_enabled.get() {
            return;
        }
        let mut trace = self.frame_trace.borrow_mut();
        if trace.len() < super::data::MAX_TRACED_FRAMES {
            trace.push(entry);
        }
    }

    /// Allocate the next non-zero 4-bit MCU command sequence number,
    /// mirroring `while (!seq) seq = ++dev->mcu.msg_seq & 0xf;`.
    pub fn next_seq(&self) -> u8 {
        loop {
            let next = (self.msg_seq.get() + 1) & 0xf;
            self.msg_seq.set(next);
            if next != 0 {
                return next;
            }
        }
    }

    /// The underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Descriptor information used to resolve endpoints.
    pub fn device_info(&self) -> &DeviceInfo {
        &self.info
    }

    fn request_type(direction: u8) -> u8 {
        direction | USB_TYPE_VENDOR | USB_RECIP_DEVICE
    }

    /// Vendor control transfer, OUT, with the driver's retry policy.
    pub fn vendor_out(
        &self,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<usize, UsbError> {
        let request_type = Self::request_type(USB_DIR_OUT);
        let mut last_error = None;
        for attempt in 0..VEND_REQ_MAX_RETRY {
            match self.transport.control_out(
                request_type,
                request,
                value,
                index,
                data,
                VEND_REQ_TIMEOUT,
            ) {
                Ok(count) => return Ok(count),
                Err(error) => {
                    last_error = Some(error);
                    if attempt + 1 < VEND_REQ_MAX_RETRY {
                        std::thread::sleep(VEND_REQ_RETRY_DELAY);
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| UsbError::Other("vendor OUT request failed".to_string())))
    }

    /// Vendor control transfer, IN, with the driver's retry policy.
    pub fn vendor_in(
        &self,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
    ) -> Result<usize, UsbError> {
        let request_type = Self::request_type(USB_DIR_IN);
        let mut last_error = None;
        for attempt in 0..VEND_REQ_MAX_RETRY {
            match self.transport.control_in(
                request_type,
                request,
                value,
                index,
                buf,
                VEND_REQ_TIMEOUT,
            ) {
                Ok(count) => return Ok(count),
                Err(error) => {
                    last_error = Some(error);
                    if attempt + 1 < VEND_REQ_MAX_RETRY {
                        std::thread::sleep(VEND_REQ_RETRY_DELAY);
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| UsbError::Other("vendor IN request failed".to_string())))
    }

    /// `mt7601u_rr`: read one 32-bit register via `MT_VEND_MULTI_READ`.
    pub fn read_reg(&self, offset: u32) -> Result<u32, UsbError> {
        let index = offset_index(offset)?;
        let mut buf = [0u8; VEND_BUF_LEN];
        let read = self.vendor_in(REQ_MULTI_READ, 0, index, &mut buf)?;
        if read != VEND_BUF_LEN {
            return Err(UsbError::Other(format!(
                "short register read at 0x{offset:08x}: {read} bytes"
            )));
        }
        Ok(u32::from_le_bytes(buf))
    }

    /// `mt7601u_vendor_single_wr`: two OUT transfers, low then high 16 bits.
    pub fn single_wr(&self, request: u8, offset: u32, value: u32) -> Result<(), UsbError> {
        let low_index = offset_index(offset)?;
        self.vendor_out(request, (value & 0xffff) as u16, low_index, &[])?;
        let high_index = offset_index(offset + 2)?;
        self.vendor_out(request, (value >> 16) as u16, high_index, &[])?;
        Ok(())
    }

    /// `mt7601u_wr`: write one 32-bit register via `MT_VEND_WRITE`.
    pub fn write_reg(&self, offset: u32, value: u32) -> Result<(), UsbError> {
        self.single_wr(REQ_WRITE, offset, value)
    }

    /// `mt7601u_rmw`: read, clear `mask`, OR in `value`, write back.
    pub fn rmw(&self, offset: u32, mask: u32, value: u32) -> Result<u32, UsbError> {
        let merged = (self.read_reg(offset)? & !mask) | value;
        self.write_reg(offset, merged)?;
        Ok(merged)
    }

    /// Set bits without clearing any (`mt76_set`).
    pub fn set_bits(&self, offset: u32, bits: u32) -> Result<u32, UsbError> {
        self.rmw(offset, 0, bits)
    }

    /// `mt7601u_vendor_reset`: device-mode reset vendor request.
    pub fn vendor_reset(&self) -> Result<(), UsbError> {
        self.vendor_out(REQ_DEV_MODE, DEV_MODE_RESET, 0, &[])?;
        Ok(())
    }

    /// `mt7601u_wait_asic_ready` from `core.c`: poll `MT_MAC_CSR0` until it is
    /// neither 0 nor all-ones.
    pub fn wait_asic_ready(&self, attempts: u32, delay: Duration) -> Result<(), UsbError> {
        for _ in 0..attempts {
            let value = self.read_reg(regs::MT_MAC_CSR0)?;
            if value != 0 && value != u32::MAX {
                return Ok(());
            }
            std::thread::sleep(delay);
        }
        Err(UsbError::Other("ASIC is not ready".to_string()))
    }

    /// Read the identity registers used by the Linux probe.
    pub fn identify(&self) -> Result<Ident, UsbError> {
        Ok(Ident {
            asic_version: self.read_reg(regs::MT_ASIC_VERSION)?,
            mac_csr0: self.read_reg(regs::MT_MAC_CSR0)?,
            efuse_ctrl: self.read_reg(regs::MT_EFUSE_CTRL)?,
        })
    }

    /// `firmware_running()` from `mcu.c`: `MT_MCU_COM_REG0 == 1`.
    pub fn firmware_running(&self) -> Result<bool, UsbError> {
        Ok(self.read_reg(regs::MT_MCU_COM_REG0)? == 1)
    }

    /// `mt7601u_reset_csr_bbp` from `init.c`.
    pub fn reset_csr_bbp(&self) -> Result<(), UsbError> {
        self.write_reg(
            regs::MT_MAC_SYS_CTRL,
            regs::MT_MAC_SYS_CTRL_RESET_CSR | regs::MT_MAC_SYS_CTRL_RESET_BBP,
        )?;
        self.write_reg(regs::MT_USB_DMA_CFG, 0)?;
        std::thread::sleep(Duration::from_millis(1));
        self.write_reg(regs::MT_MAC_SYS_CTRL, 0)?;
        Ok(())
    }

    /// `mt7601u_init_usb_dma` from `init.c`.
    pub fn init_usb_dma(&self) -> Result<(), UsbError> {
        let mut value = (regs::MT_USB_AGGR_TIMEOUT & regs::MT_USB_DMA_CFG_RX_BULK_AGG_TOUT_MASK)
            | ((regs::MT_USB_AGGR_SIZE_LIMIT & regs::MT_USB_DMA_CFG_RX_BULK_AGG_TOUT_MASK)
                << regs::MT_USB_DMA_CFG_RX_BULK_AGG_LMT_SHIFT)
            | regs::MT_USB_DMA_CFG_RX_BULK_EN
            | regs::MT_USB_DMA_CFG_TX_BULK_EN;
        if self.in_max_packet() == Some(512) {
            value |= regs::MT_USB_DMA_CFG_RX_BULK_AGG_EN;
        }
        self.write_reg(regs::MT_USB_DMA_CFG, value)?;

        self.write_reg(
            regs::MT_USB_DMA_CFG,
            value | regs::MT_USB_DMA_CFG_UDMA_RX_WL_DROP,
        )?;
        self.write_reg(
            regs::MT_USB_DMA_CFG,
            value & !regs::MT_USB_DMA_CFG_UDMA_RX_WL_DROP,
        )?;
        Ok(())
    }

    /// The `MT_USB_DMA_CFG` write at the top of `mcu.c::mt7601u_load_firmware`.
    ///
    /// The driver performs it on *every* init, before it checks whether the
    /// firmware is already running, because the in-band MCU command channel is
    /// carried by these bulk DMA directions. It is what a device needs after its
    /// USB handle has been closed and reopened.
    pub fn enable_usb_dma(&self) -> Result<(), UsbError> {
        self.write_reg(
            regs::MT_USB_DMA_CFG,
            regs::MT_USB_DMA_CFG_RX_BULK_EN | regs::MT_USB_DMA_CFG_TX_BULK_EN,
        )
    }

    /// Wait until the WPDMA TX/RX engines report idle (`init.c`).
    pub fn wait_dma_idle(&self, timeout: Duration) -> Result<(), UsbError> {
        self.poll_reg(
            regs::MT_WPDMA_GLO_CFG,
            regs::MT_WPDMA_GLO_CFG_TX_DMA_BUSY | regs::MT_WPDMA_GLO_CFG_RX_DMA_BUSY,
            0,
            timeout,
        )
    }

    /// Post-firmware initialization up to (but not including) MCU commands,
    /// mirroring the middle of `mt7601u_init_hardware`.
    pub fn init_after_firmware(&self) -> Result<(), UsbError> {
        self.wait_dma_idle(Duration::from_millis(100))?;
        self.wait_asic_ready(100, Duration::from_millis(1))?;
        self.reset_csr_bbp()?;
        self.init_usb_dma()?;
        Ok(())
    }

    /// `mt7601u_set_wlan_state` from `init.c`: enable/disable the WLAN clock and,
    /// when enabling, wait for XTAL and PLL to lock.
    fn set_wlan_state(&self, mut value: u32, enable: bool) -> Result<(), UsbError> {
        if enable {
            value |= regs::MT_WLAN_FUN_CTRL_WLAN_EN | regs::MT_WLAN_FUN_CTRL_WLAN_CLK_EN;
        } else {
            value &= !regs::MT_WLAN_FUN_CTRL_WLAN_EN;
        }
        self.write_reg(regs::MT_WLAN_FUN_CTRL, value)?;
        std::thread::sleep(Duration::from_micros(20));

        if !enable {
            return Ok(());
        }

        // The driver logs (but does not fail) if the PLL/XTAL never locks.
        for _ in 0..200 {
            let value = self.read_reg(regs::MT_CMB_CTRL)?;
            if value & regs::MT_CMB_CTRL_XTAL_RDY != 0 && value & regs::MT_CMB_CTRL_PLL_LD != 0 {
                return Ok(());
            }
            std::thread::sleep(Duration::from_micros(20));
        }
        tracing::warn!("PLL and XTAL check failed after enabling WLAN");
        Ok(())
    }

    /// `mt7601u_chip_onoff` from `init.c`.
    pub fn chip_onoff(&self, enable: bool, reset: bool) -> Result<(), UsbError> {
        let mut value = self.read_reg(regs::MT_WLAN_FUN_CTRL)?;

        if reset {
            value |= regs::MT_WLAN_FUN_CTRL_GPIO_OUT_EN;
            value &= !regs::MT_WLAN_FUN_CTRL_FRC_WL_ANT_SEL;

            if value & regs::MT_WLAN_FUN_CTRL_WLAN_EN != 0 {
                value |= regs::MT_WLAN_FUN_CTRL_WLAN_RESET | regs::MT_WLAN_FUN_CTRL_WLAN_RESET_RF;
                self.write_reg(regs::MT_WLAN_FUN_CTRL, value)?;
                std::thread::sleep(Duration::from_micros(20));
                value &=
                    !(regs::MT_WLAN_FUN_CTRL_WLAN_RESET | regs::MT_WLAN_FUN_CTRL_WLAN_RESET_RF);
            }
        }

        self.write_reg(regs::MT_WLAN_FUN_CTRL, value)?;
        std::thread::sleep(Duration::from_micros(20));
        self.set_wlan_state(value, enable)
    }

    pub(crate) fn endpoints(&self) -> Vec<&EndpointInfo> {
        self.info
            .configurations
            .iter()
            .flat_map(|config| config.interfaces.iter())
            .flat_map(|interface| interface.endpoints.iter())
            .collect()
    }

    /// The bulk OUT endpoint the Linux driver uses as `MT_EP_OUT_INBAND_CMD`
    /// (index 0 of the OUT endpoints in descriptor order). Resolved at runtime;
    /// never hardcoded.
    pub fn inband_cmd_endpoint(&self) -> Result<u8, UsbError> {
        self.endpoints()
            .into_iter()
            .find(|endpoint| !endpoint.is_in && endpoint.transfer_type == UsbTransferType::Bulk)
            .map(|endpoint| endpoint.address)
            .ok_or_else(|| UsbError::Other("no bulk OUT endpoint found".to_string()))
    }

    /// Max packet size of the first bulk IN endpoint (`dev->in_max_packet`).
    pub fn in_max_packet(&self) -> Option<u16> {
        self.endpoints()
            .into_iter()
            .find(|endpoint| endpoint.is_in && endpoint.transfer_type == UsbTransferType::Bulk)
            .map(|endpoint| endpoint.max_packet_size)
    }

    /// Bulk IN endpoint carrying received frames (`MT_EP_IN_PKT_RX`, index 0).
    pub fn rx_endpoint(&self) -> Result<u8, UsbError> {
        self.endpoints()
            .into_iter()
            .find(|endpoint| endpoint.is_in && endpoint.transfer_type == UsbTransferType::Bulk)
            .map(|endpoint| endpoint.address)
            .ok_or_else(|| UsbError::Other("no bulk IN endpoint found".to_string()))
    }

    /// Upload an MT7601U firmware image, adapted from `mt7601u_load_firmware`
    /// and `mt7601u_upload_firmware` in `mcu.c`.
    pub fn load_firmware(&self, data: &[u8]) -> Result<FirmwareLoad, UsbError> {
        let image = firmware::parse(data).map_err(|error| UsbError::Firmware(error.to_string()))?;
        let endpoint = self.inband_cmd_endpoint()?;

        self.prepare_firmware_load()?;
        self.upload_section(image.ilm, regs::MT_MCU_IVB_SIZE as u32, endpoint)?;
        self.upload_section(image.dlm, regs::MT_MCU_DLM_OFFSET, endpoint)?;

        // Hand the IVB to the boot ROM, then wait for the MCU to start.
        self.vendor_out(REQ_DEV_MODE, DEV_MODE_IVB, 0, image.ivb)?;
        self.wait_firmware_running()?;

        Ok(FirmwareLoad {
            version: image.header.version_string(),
            build: image.header.build_ver,
            build_time: image.build_time_string(),
            ilm_bytes: image.ilm.len(),
            dlm_bytes: image.dlm.len(),
        })
    }

    /// Register sequence that precedes the firmware transfer (`mcu.c`).
    fn prepare_firmware_load(&self) -> Result<(), UsbError> {
        let bulk = regs::MT_USB_DMA_CFG_RX_BULK_EN | regs::MT_USB_DMA_CFG_TX_BULK_EN;

        self.write_reg(regs::MT_USB_DMA_CFG, bulk)?;
        self.write_reg(regs::MT_LOAD_FW_REG_094C, 0)?;
        self.write_reg(regs::MT_FCE_PSE_CTRL, 0)?;
        self.vendor_reset()?;
        std::thread::sleep(Duration::from_millis(5));
        self.write_reg(regs::MT_LOAD_FW_REG_0A44, 0)?;
        self.write_reg(regs::MT_FCE_DMA_ADDR, regs::MT_LOAD_FW_FCE_BASE)?;
        self.write_reg(regs::MT_PBF_SYS_CTRL, regs::MT_LOAD_FW_PBF_SYS_CTRL_VALUE)?;
        self.write_reg(regs::MT_FCE_PSE_CTRL, 1)?;
        self.set_bits(regs::MT_PBF_CFG, regs::MT_PBF_CFG_TXQ_EN)?;
        self.write_reg(regs::MT_FCE_PSE_CTRL, 1)?;
        self.write_reg(regs::MT_USB_DMA_CFG, bulk)?;
        let value = self.set_bits(regs::MT_USB_DMA_CFG, regs::MT_USB_DMA_CFG_TX_CLR)?
            & !regs::MT_USB_DMA_CFG_TX_CLR;
        self.write_reg(regs::MT_USB_DMA_CFG, value)?;
        self.write_reg(
            regs::MT_TX_CPU_FROM_FCE_BASE_PTR,
            regs::MT_LOAD_FW_TX_FCE_BASE,
        )?;
        self.write_reg(regs::MT_TX_CPU_FROM_FCE_MAX_COUNT, 1)?;
        self.write_reg(
            regs::MT_FCE_PDMA_GLOBAL_CONF,
            regs::MT_LOAD_FW_PDMA_GLOBAL_CONF,
        )?;
        self.write_reg(regs::MT_FCE_SKIP_FS, regs::MT_LOAD_FW_SKIP_FS)?;
        Ok(())
    }

    fn upload_section(&self, data: &[u8], destination: u32, endpoint: u8) -> Result<(), UsbError> {
        let mut offset = 0usize;
        while offset < data.len() {
            let len = usize::min(firmware::MCU_FW_URB_MAX_PAYLOAD, data.len() - offset);
            self.upload_chunk(
                &data[offset..offset + len],
                destination + offset as u32,
                endpoint,
            )?;
            self.poll_reg(
                regs::MT_MCU_COM_REG1,
                regs::MT_MCU_COM_REG1_FW_READY,
                regs::MT_MCU_COM_REG1_FW_READY,
                Duration::from_millis(500),
            )?;
            offset += len;
        }
        Ok(())
    }

    fn upload_chunk(&self, payload: &[u8], destination: u32, endpoint: u8) -> Result<(), UsbError> {
        let buffer = dma::packet_buffer(payload);
        self.single_wr(REQ_WRITE_FCE, regs::MT_FCE_DMA_ADDR, destination)?;
        let padded = payload.len().next_multiple_of(4) as u32;
        self.single_wr(REQ_WRITE_FCE, regs::MT_FCE_DMA_LEN, padded << 16)?;

        let written = self
            .transport
            .bulk_out(endpoint, &buffer, Duration::from_millis(1000))?;
        if written != buffer.len() {
            return Err(UsbError::Other(format!(
                "firmware chunk short write: {written}/{}",
                buffer.len()
            )));
        }

        let index = self.read_reg(regs::MT_TX_CPU_FROM_FCE_CPU_DESC_IDX)?;
        self.write_reg(regs::MT_TX_CPU_FROM_FCE_CPU_DESC_IDX, index.wrapping_add(1))?;
        Ok(())
    }

    fn wait_firmware_running(&self) -> Result<(), UsbError> {
        for _ in 0..100 {
            if self.read_reg(regs::MT_MCU_COM_REG0)? == 1 {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(UsbError::Other(
            "firmware did not start (MT_MCU_COM_REG0 != 1)".to_string(),
        ))
    }

    pub(crate) fn poll_reg(
        &self,
        offset: u32,
        mask: u32,
        value: u32,
        timeout: Duration,
    ) -> Result<(), UsbError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.read_reg(offset)? & mask == value {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(UsbError::Other(format!(
                    "timeout polling register 0x{offset:08x}"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl<T: Transport> Drop for Mt7601u<T> {
    fn drop(&mut self) {
        self.transport.close();
    }
}

/// Convert a register offset into the 16-bit control `wIndex`.
fn offset_index(offset: u32) -> Result<u16, UsbError> {
    u16::try_from(offset).map_err(|_| {
        UsbError::Other(format!(
            "register offset 0x{offset:08x} exceeds the 16-bit control index"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{device_info, Call, MockTransport};

    fn image_with_sections(ilm_len: u32, dlm_len: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&ilm_len.to_le_bytes());
        data.extend_from_slice(&dlm_len.to_le_bytes());
        data.extend_from_slice(&7u16.to_le_bytes());
        data.extend_from_slice(&0x1234u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]);
        data.extend_from_slice(&[0u8; 16]);
        data.resize(
            firmware::FW_HEADER_LEN + ilm_len as usize + dlm_len as usize,
            0x5a,
        );
        data
    }

    #[test]
    fn read_reg_uses_multi_read_and_parses_le() {
        let mock = MockTransport::with_registers(&[(regs::MT_ASIC_VERSION, 0x7601_0000)]);
        let chip = Mt7601u::new(mock, device_info());
        assert_eq!(chip.read_reg(regs::MT_ASIC_VERSION).unwrap(), 0x7601_0000);
        assert_eq!(
            chip.transport().calls().as_slice(),
            &[Call::In {
                request: REQ_MULTI_READ,
                value: 0,
                index: 0,
            }]
        );
    }

    #[test]
    fn write_reg_splits_into_two_out_transfers() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        chip.write_reg(0x0230, 0xdead_beef).unwrap();
        assert_eq!(
            chip.transport().calls().as_slice(),
            &[
                Call::Out {
                    request: REQ_WRITE,
                    value: 0xbeef,
                    index: 0x0230,
                    data: vec![],
                },
                Call::Out {
                    request: REQ_WRITE,
                    value: 0xdead,
                    index: 0x0232,
                    data: vec![],
                },
            ]
        );
    }

    #[test]
    fn identify_reads_three_registers() {
        let mock = MockTransport::with_registers(&[
            (regs::MT_ASIC_VERSION, 0x7601_1234),
            (regs::MT_MAC_CSR0, 0x0000_0001),
            (regs::MT_EFUSE_CTRL, regs::MT_EFUSE_CTRL_SEL),
        ]);
        let chip = Mt7601u::new(mock, device_info());
        let ident = chip.identify().unwrap();
        assert!(ident.is_mt7601());
        assert_eq!(ident.asic_revision(), 0x1234);
        assert!(ident.efuse_present());
    }

    #[test]
    fn inband_endpoint_is_first_bulk_out() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        assert_eq!(chip.inband_cmd_endpoint().unwrap(), 0x08);
    }

    #[test]
    fn in_max_packet_reads_bulk_in_endpoint() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        assert_eq!(chip.in_max_packet(), Some(512));
    }

    #[test]
    fn firmware_running_reads_com_reg0() {
        let mock = MockTransport::with_registers(&[(regs::MT_MCU_COM_REG0, 1)]);
        let chip = Mt7601u::new(mock, device_info());
        assert!(chip.firmware_running().unwrap());
    }

    #[test]
    fn init_after_firmware_writes_usb_dma_cfg() {
        let mock = MockTransport::with_registers(&[
            (regs::MT_WPDMA_GLO_CFG, 0),
            (regs::MT_MAC_CSR0, 0x0000_0001),
        ]);
        let chip = Mt7601u::new(mock, device_info());
        chip.init_after_firmware().unwrap();

        // `init_usb_dma` must enable both bulk directions and, for a 512-byte
        // endpoint, RX bulk aggregation. `write_reg` splits the value across
        // `offset` (low 16) and `offset + 2` (high 16).
        let expected = regs::MT_USB_AGGR_TIMEOUT
            | (regs::MT_USB_AGGR_SIZE_LIMIT << 8)
            | regs::MT_USB_DMA_CFG_RX_BULK_EN
            | regs::MT_USB_DMA_CFG_TX_BULK_EN
            | regs::MT_USB_DMA_CFG_RX_BULK_AGG_EN;

        let calls = chip.transport().calls();
        let low = calls.iter().any(|call| {
            matches!(call, Call::Out { value, index, .. }
                if *index == regs::MT_USB_DMA_CFG as u16 && *value == expected as u16)
        });
        let high = calls.iter().any(|call| {
            matches!(call, Call::Out { value, index, .. }
                if *index == regs::MT_USB_DMA_CFG as u16 + 2
                    && *value == (expected >> 16) as u16)
        });
        assert!(low, "expected a low-half MT_USB_DMA_CFG write");
        assert!(high, "expected a high-half MT_USB_DMA_CFG write");
    }

    #[test]
    fn load_firmware_uploads_and_starts_mcu() {
        // Registers the firmware path polls while running.
        let mock = MockTransport::with_registers(&[
            (regs::MT_MCU_COM_REG1, regs::MT_MCU_COM_REG1_FW_READY),
            (regs::MT_MCU_COM_REG0, 1),
        ]);
        let chip = Mt7601u::new(mock, device_info());
        let report = chip
            .load_firmware(&image_with_sections(0x100, 0x40))
            .unwrap();

        assert_eq!(report.ilm_bytes, 0x100 - regs::MT_MCU_IVB_SIZE);
        assert_eq!(report.dlm_bytes, 0x40);
        // Two bulk transfers: ILM section then DLM section.
        assert_eq!(chip.transport().bulk_writes.borrow().len(), 2);
        assert_eq!(chip.transport().bulk_writes.borrow()[0].0, 0x08);
    }

    #[test]
    fn load_firmware_chunks_large_sections() {
        let mock = MockTransport::with_registers(&[
            (regs::MT_MCU_COM_REG1, regs::MT_MCU_COM_REG1_FW_READY),
            (regs::MT_MCU_COM_REG0, 1),
        ]);
        let chip = Mt7601u::new(mock, device_info());
        // ILM payload = 0x8000 bytes (> one 0x3800 chunk) + IVB.
        let ilm_field = 0x8000u32 + regs::MT_MCU_IVB_SIZE as u32;
        chip.load_firmware(&image_with_sections(ilm_field, 0))
            .unwrap();
        let chunks = chip.transport().bulk_writes.borrow().len();
        assert_eq!(ilm_field as usize - regs::MT_MCU_IVB_SIZE, 0x8000);
        assert_eq!(chunks, 3); // ceil(0x8000 / 0x3800) = 3
    }

    #[test]
    fn wait_asic_ready_fails_on_dead_bus() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        assert!(chip.wait_asic_ready(2, Duration::from_millis(1)).is_err());
    }

    #[test]
    fn asic_ready_succeeds_with_real_value() {
        let mock = MockTransport::with_registers(&[(regs::MT_MAC_CSR0, 0x0000_0001)]);
        let chip = Mt7601u::new(mock, device_info());
        assert!(chip.wait_asic_ready(2, Duration::from_millis(1)).is_ok());
    }
}
