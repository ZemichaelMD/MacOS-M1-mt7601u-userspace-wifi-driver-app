//! MCU command channel, transcribed from `mcu.c`.
//!
//! Commands are sent as bulk OUT to `MT_EP_OUT_INBAND_CMD` using the TX DMA
//! command framing; responses arrive on the second bulk IN endpoint. Each
//! waiting command gets a non-zero 4-bit sequence number.

use std::time::Duration;

use crate::usb::{Transport, UsbError, UsbTransferType};

use super::device::Mt7601u;
use super::dma;

/// `INBAND_PACKET_MAX_LEN` (`mcu.h`).
pub const INBAND_PACKET_MAX_LEN: usize = 192;
/// `MCU_RESP_URB_SIZE` (`mcu.c`).
pub const MCU_RESP_URB_SIZE: usize = 1024;
/// `MT_MCU_MEMMAP_WLAN` (`mcu.h`).
pub const MT_MCU_MEMMAP_WLAN: u32 = 0x0041_0000;
/// `MT_MCU_MEMMAP_BBP` (`mcu.h`).
pub const MT_MCU_MEMMAP_BBP: u32 = 0x4000_0000;
/// `MT_MCU_MEMMAP_RF` (`mcu.h`).
pub const MT_MCU_MEMMAP_RF: u32 = 0x8000_0000;

/// `enum mcu_cmd` (`mcu.h`).
pub const CMD_FUN_SET_OP: u8 = 1;
/// `CMD_BURST_WRITE`.
pub const CMD_BURST_WRITE: u8 = 8;
/// `CMD_RANDOM_WRITE`.
pub const CMD_RANDOM_WRITE: u8 = 12;
/// `CMD_CALIBRATION_OP`.
pub const CMD_CALIBRATION_OP: u8 = 31;

/// `enum mcu_function`: select the normal operating mode.
pub const FUNC_Q_SELECT: u32 = 1;
/// `enum mcu_function`: atomic TSSI setting.
pub const FUNC_ATOMIC_TSSI_SETTING: u32 = 5;

/// `enum mcu_calibrate` (`mcu.h`).
pub const CAL_R: u32 = 1;
/// `MCU_CAL_DCOC`.
pub const CAL_DCOC: u32 = 2;
/// `MCU_CAL_LC`.
pub const CAL_LC: u32 = 3;
/// `MCU_CAL_LOFT`.
pub const CAL_LOFT: u32 = 4;
/// `MCU_CAL_TXIQ`.
pub const CAL_TXIQ: u32 = 5;
/// `MCU_CAL_BW`.
pub const CAL_BW: u32 = 6;
/// `MCU_CAL_DPD`.
pub const CAL_DPD: u32 = 7;
/// `MCU_CAL_RXIQ`.
pub const CAL_RXIQ: u32 = 8;
/// `MCU_CAL_TXDCOC`.
pub const CAL_TXDCOC: u32 = 9;

/// Command OUT timeout.
const CMD_TIMEOUT: Duration = Duration::from_millis(500);
/// Response IN timeout per attempt.
const RESP_TIMEOUT: Duration = Duration::from_millis(300);
/// Response read attempts (`i = 5` in `mt7601u_mcu_wait_resp`).
const RESP_ATTEMPTS: u32 = 5;

impl<T: Transport> Mt7601u<T> {
    /// Bulk IN endpoint used for MCU responses (index 1 of the IN endpoints,
    /// `MT_EP_IN_CMD_RESP`).
    pub fn cmd_resp_endpoint(&self) -> Result<u8, UsbError> {
        self.endpoints()
            .into_iter()
            .filter(|endpoint| endpoint.is_in && endpoint.transfer_type == UsbTransferType::Bulk)
            .nth(1)
            .map(|endpoint| endpoint.address)
            .ok_or_else(|| UsbError::Other("no MCU response bulk IN endpoint".to_string()))
    }

    /// Send one MCU command (`mt7601u_mcu_msg_send`).
    ///
    /// When `wait_response` is set, a sequence number is allocated and the
    /// matching `CMD_DONE` response is awaited.
    pub fn mcu_send(
        &self,
        command: u8,
        payload: &[u8],
        wait_response: bool,
    ) -> Result<(), UsbError> {
        let endpoint = self.inband_cmd_endpoint()?;
        let seq = if wait_response { self.next_seq() } else { 0 };
        let buffer = dma::command_buffer(payload, seq, command);

        let written = self.transport().bulk_out(endpoint, &buffer, CMD_TIMEOUT)?;
        if written != buffer.len() {
            return Err(UsbError::Other(format!(
                "MCU command short write: {written}/{}",
                buffer.len()
            )));
        }

        if wait_response {
            self.mcu_wait_resp(seq)?;
        }
        Ok(())
    }

    /// `mt7601u_mcu_wait_resp`: read the response endpoint until a `CMD_DONE`
    /// event for `seq` arrives.
    fn mcu_wait_resp(&self, seq: u8) -> Result<(), UsbError> {
        let endpoint = self.cmd_resp_endpoint()?;
        let mut buf = vec![0u8; MCU_RESP_URB_SIZE];
        let mut last = None;

        for _ in 0..RESP_ATTEMPTS {
            match self.transport().bulk_in(endpoint, &mut buf, RESP_TIMEOUT) {
                Ok(len) if len >= dma::MT_DMA_HDR_LEN => {
                    let rxfce = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let resp_seq = dma::response_seq(rxfce);
                    let resp_evt = dma::response_evt(rxfce);
                    if resp_seq == seq && resp_evt == dma::EVT_CMD_DONE {
                        return Ok(());
                    }
                    last = Some(format!("seq {resp_seq} evt {resp_evt}"));
                }
                Ok(len) => last = Some(format!("short response ({len} bytes)")),
                Err(error) => last = Some(error.to_string()),
            }
        }

        Err(UsbError::Other(format!(
            "MCU response for seq {seq} not received ({})",
            last.unwrap_or_else(|| "no data".to_string())
        )))
    }

    /// `mt7601u_mcu_function_select`: `{ id, value }` with `CMD_FUN_SET_OP`.
    pub fn mcu_function_select(&self, function: u32, value: u32) -> Result<(), UsbError> {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&function.to_le_bytes());
        payload.extend_from_slice(&value.to_le_bytes());
        self.mcu_send(
            CMD_FUN_SET_OP,
            &payload,
            function == FUNC_ATOMIC_TSSI_SETTING,
        )
    }

    /// `mt7601u_mcu_cmd_init`: select the normal operating mode (`Q_SELECT`).
    pub fn mcu_cmd_init(&self) -> Result<(), UsbError> {
        self.mcu_function_select(FUNC_Q_SELECT, 1)
    }

    /// `mt7601u_mcu_calibrate`: `{ id, value }` with `CMD_CALIBRATION_OP`.
    pub fn mcu_calibrate(&self, calibration: u32, value: u32) -> Result<(), UsbError> {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&calibration.to_le_bytes());
        payload.extend_from_slice(&value.to_le_bytes());
        self.mcu_send(CMD_CALIBRATION_OP, &payload, true)
    }

    /// `mt7601u_write_reg_pairs`: write `(register, value)` pairs relative to
    /// `base`, at most `INBAND_PACKET_MAX_LEN / 8` per command.
    pub fn mcu_write_reg_pairs(&self, base: u32, pairs: &[(u32, u32)]) -> Result<(), UsbError> {
        let max_per_command = INBAND_PACKET_MAX_LEN / 8;
        let mut rest = pairs;

        while !rest.is_empty() {
            let count = rest.len().min(max_per_command);
            let mut payload = Vec::with_capacity(count * 8);
            for (register, value) in &rest[..count] {
                payload.extend_from_slice(&(base + register).to_le_bytes());
                payload.extend_from_slice(&value.to_le_bytes());
            }
            self.mcu_send(CMD_RANDOM_WRITE, &payload, count == rest.len())?;
            rest = &rest[count..];
        }
        Ok(())
    }

    /// `mt7601u_burst_write_regs`: write consecutive registers into the WLAN
    /// memory map, at most `INBAND_PACKET_MAX_LEN / 4 - 1` per command.
    pub fn mcu_burst_write_regs(&self, offset: u32, values: &[u32]) -> Result<(), UsbError> {
        let max_per_command = INBAND_PACKET_MAX_LEN / 4 - 1;
        let mut index = 0usize;

        while index < values.len() {
            let count = (values.len() - index).min(max_per_command);
            let mut payload = Vec::with_capacity((count + 1) * 4);
            payload
                .extend_from_slice(&(MT_MCU_MEMMAP_WLAN + offset + index as u32 * 4).to_le_bytes());
            for value in &values[index..index + count] {
                payload.extend_from_slice(&value.to_le_bytes());
            }
            self.mcu_send(CMD_BURST_WRITE, &payload, index + count == values.len())?;
            index += count;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::testing::{device_info, MockTransport};

    /// The `(seq, command)` fields of a written command buffer.
    fn command_fields(buffer: &[u8]) -> (u8, u8) {
        let info = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        (dma::command_seq(info), dma::command_id(info))
    }

    /// A response buffer whose first word reports `seq` + `CMD_DONE`.
    fn response_for(seq: u8) -> Vec<u8> {
        let mut buffer = vec![0u8; 16];
        let rxfce = u32::from(seq) << 16; // CMD_DONE is 0.
        buffer[..4].copy_from_slice(&rxfce.to_le_bytes());
        buffer
    }

    #[test]
    fn function_select_without_response_writes_command() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        chip.mcu_function_select(FUNC_Q_SELECT, 1).unwrap();

        let writes = chip.transport().bulk_writes.borrow();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, 0x08);
        assert_eq!(command_fields(&writes[0].1), (0, CMD_FUN_SET_OP));
        // No response was awaited, so nothing was read.
        assert_eq!(writes[0].1.len(), 4 + 8 + 4);
    }

    #[test]
    fn calibrate_awaits_and_accepts_matching_response() {
        let mock = MockTransport::default();
        mock.set_bulk_in(response_for(1));
        let chip = Mt7601u::new(mock, device_info());

        chip.mcu_calibrate(CAL_R, 0).unwrap();
        let writes = chip.transport().bulk_writes.borrow();
        assert_eq!(command_fields(&writes[0].1), (1, CMD_CALIBRATION_OP));
    }

    #[test]
    fn response_mismatch_times_out() {
        let mock = MockTransport::default();
        mock.set_bulk_in(response_for(7)); // wrong sequence number
        let chip = Mt7601u::new(mock, device_info());
        assert!(chip.mcu_calibrate(CAL_R, 0).is_err());
    }

    #[test]
    fn missing_response_times_out() {
        // No canned bulk-in data -> every read errors.
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        assert!(chip
            .mcu_function_select(FUNC_ATOMIC_TSSI_SETTING, 1)
            .is_err());
    }

    #[test]
    fn cmd_resp_endpoint_is_second_bulk_in() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        assert_eq!(chip.cmd_resp_endpoint().unwrap(), 0x85);
    }

    #[test]
    fn write_reg_pairs_chunks_and_only_last_waits() {
        let mock = MockTransport::default();
        mock.set_bulk_in(response_for(1)); // only the final chunk waits -> seq 1
        let chip = Mt7601u::new(mock, device_info());

        let pairs: Vec<(u32, u32)> = (0..50).map(|i| (i * 4, 0x1000 + i)).collect();
        chip.mcu_write_reg_pairs(MT_MCU_MEMMAP_WLAN, &pairs)
            .unwrap();

        let writes = chip.transport().bulk_writes.borrow();
        // 50 pairs at 24 per command -> 3 commands.
        assert_eq!(writes.len(), 3);
        assert_eq!(command_fields(&writes[0].1), (0, CMD_RANDOM_WRITE));
        assert_eq!(command_fields(&writes[1].1), (0, CMD_RANDOM_WRITE));
        assert_eq!(command_fields(&writes[2].1), (1, CMD_RANDOM_WRITE));
        // Third chunk carries the remaining 2 pairs.
        assert_eq!(writes[2].1.len(), 4 + 16 + 4);
    }

    #[test]
    fn burst_write_prefixes_base_address() {
        let mock = MockTransport::default();
        mock.set_bulk_in(response_for(1));
        let chip = Mt7601u::new(mock, device_info());

        chip.mcu_burst_write_regs(0x100, &[1, 2, 3]).unwrap();
        let writes = chip.transport().bulk_writes.borrow();
        let buffer = &writes[0].1;
        assert_eq!(command_fields(buffer), (1, CMD_BURST_WRITE));
        let first_value = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        assert_eq!(first_value, MT_MCU_MEMMAP_WLAN + 0x100);
        assert_eq!(buffer.len(), 4 + 16 + 4);
    }

    #[test]
    fn seq_wraps_skipping_zero() {
        let chip = Mt7601u::new(MockTransport::default(), device_info());
        for _ in 0..15 {
            assert_ne!(chip.next_seq(), 0);
        }
        assert_eq!(chip.next_seq(), 1);
    }
}
