//! TX/RX DMA descriptor layout, transcribed from `dma.h` and `dma.c`.
//!
//! This is the single source of truth for the DMA framing shared by firmware
//! upload and MCU commands. All helpers are pure and unit-tested.

/// `MT_DMA_HDR_LEN`: leading DMA info word on every TX buffer.
pub const MT_DMA_HDR_LEN: usize = 4;
/// `MT_RX_INFO_LEN`: RX info word.
pub const MT_RX_INFO_LEN: usize = 4;
/// `MT_FCE_INFO_LEN`: trailing FCE descriptor word.
pub const MT_FCE_INFO_LEN: usize = 4;
/// `MT_DMA_HDRS` = `MT_DMA_HDR_LEN + MT_RX_INFO_LEN`.
pub const MT_DMA_HDRS: usize = MT_DMA_HDR_LEN + MT_RX_INFO_LEN;

// --- TX info word fields (`dma.h`) ---
/// `MT_TXD_INFO_LEN` (`GENMASK(15, 0)`).
const TXD_INFO_LEN_MASK: u32 = 0xffff;
/// `MT_TXD_INFO_D_PORT` (`GENMASK(29, 27)`).
const TXD_INFO_D_PORT_SHIFT: u32 = 27;
/// `MT_TXD_INFO_TYPE` (`GENMASK(31, 30)`).
const TXD_INFO_TYPE_SHIFT: u32 = 30;

/// `enum mt76_msg_port`: `CPU_TX_PORT`.
pub const PORT_CPU_TX: u32 = 2;
/// `enum mt76_msg_port`: `WLAN_PORT` (data/management frames).
pub const PORT_WLAN: u32 = 0;

/// `MT_TXD_PKT_INFO_80211`: the payload is an 802.11 frame.
pub const PKT_INFO_80211: u32 = 1 << 19;
/// `MT_TXD_PKT_INFO_WIV`: the frame carries its own IV (i.e. not hardware-encrypted).
pub const PKT_INFO_WIV: u32 = 1 << 24;
/// `MT_TXD_PKT_INFO_QSEL` shift (`GENMASK(26, 25)`).
pub const PKT_INFO_QSEL_SHIFT: u32 = 25;

/// `enum mt76_qsel`: management queue.
pub const QSEL_MGMT: u32 = 0;
/// `enum mt76_qsel`: HCCA queue.
pub const QSEL_HCCA: u32 = 1;
/// `enum mt76_qsel`: EDCA queue.
pub const QSEL_EDCA: u32 = 2;
/// `enum mt76_qsel`: secondary EDCA queue.
pub const QSEL_EDCA_2: u32 = 3;

/// `enum mt76_info_type`: a data packet.
pub const INFO_TYPE_DMA_PACKET: u32 = 0;
/// `enum mt76_info_type`: an MCU command.
pub const INFO_TYPE_DMA_COMMAND: u32 = 1;

// --- TX MCU-command info fields (`dma.h`) ---
/// `MT_TXD_CMD_INFO_SEQ` (`GENMASK(19, 16)`).
const TXD_CMD_INFO_SEQ_SHIFT: u32 = 16;
const TXD_CMD_INFO_SEQ_MASK: u32 = 0xf;
/// `MT_TXD_CMD_INFO_TYPE` (`GENMASK(26, 20)`).
const TXD_CMD_INFO_TYPE_SHIFT: u32 = 20;
const TXD_CMD_INFO_TYPE_MASK: u32 = 0x7f;

// --- RX info word fields (`dma.h`, `dma.c`) ---
/// `MT_RXD_INFO_LEN` (`GENMASK(13, 0)`).
const RXD_INFO_LEN_MASK: u32 = 0x3fff;
/// `MT_RXD_INFO_TYPE` (`GENMASK(31, 30)`).
const RXD_INFO_TYPE_SHIFT: u32 = 30;
/// `MT_RXD_CMD_INFO_CMD_SEQ` (`GENMASK(19, 16)`).
const RXD_CMD_INFO_SEQ_SHIFT: u32 = 16;
const RXD_CMD_INFO_SEQ_MASK: u32 = 0xf;
/// `MT_RXD_CMD_INFO_EVT_TYPE` (`GENMASK(23, 20)`).
const RXD_CMD_INFO_EVT_SHIFT: u32 = 20;
const RXD_CMD_INFO_EVT_MASK: u32 = 0xf;

/// `enum mt76_evt_type`: command completed successfully.
pub const EVT_CMD_DONE: u8 = 0;
/// `enum mt76_evt_type`: command failed.
pub const EVT_CMD_ERROR: u8 = 1;
/// `enum mt76_evt_type`: command should be retried.
pub const EVT_CMD_RETRY: u8 = 2;

/// Build a TX info word from its fields.
pub fn info_word(info_type: u32, d_port: u32, len: usize, flags: u32) -> u32 {
    flags
        | (len as u32 & TXD_INFO_LEN_MASK)
        | (d_port << TXD_INFO_D_PORT_SHIFT)
        | (info_type << TXD_INFO_TYPE_SHIFT)
}

/// Wrap a payload into a TX DMA buffer:
/// `[4B info][payload][zero pad to 4B][4B zero]`.
pub fn wrap_buffer(payload: &[u8], info: u32) -> Vec<u8> {
    let padded = payload.len().next_multiple_of(4);
    let mut buf = Vec::with_capacity(MT_DMA_HDR_LEN + padded + 4);
    buf.extend_from_slice(&info.to_le_bytes());
    buf.extend_from_slice(payload);
    buf.resize(MT_DMA_HDR_LEN + padded + 4, 0);
    buf
}

/// TX buffer for a firmware chunk (`__mt7601u_dma_fw`): the length field holds
/// the raw payload length.
pub fn packet_buffer(payload: &[u8]) -> Vec<u8> {
    wrap_buffer(
        payload,
        info_word(INFO_TYPE_DMA_PACKET, PORT_CPU_TX, payload.len(), 0),
    )
}

/// TX buffer for an MCU command (`mt7601u_dma_skb_wrap_cmd`): the length field
/// holds the 4-byte-rounded payload length.
pub fn command_buffer(payload: &[u8], seq: u8, cmd: u8) -> Vec<u8> {
    let flags = ((u32::from(seq) & TXD_CMD_INFO_SEQ_MASK) << TXD_CMD_INFO_SEQ_SHIFT)
        | ((u32::from(cmd) & TXD_CMD_INFO_TYPE_MASK) << TXD_CMD_INFO_TYPE_SHIFT);
    wrap_buffer(
        payload,
        info_word(
            INFO_TYPE_DMA_COMMAND,
            PORT_CPU_TX,
            payload.len().next_multiple_of(4),
            flags,
        ),
    )
}

/// `MT_TXD_CMD_INFO_SEQ` of a command buffer's info word.
pub fn command_seq(info: u32) -> u8 {
    ((info >> TXD_CMD_INFO_SEQ_SHIFT) & TXD_CMD_INFO_SEQ_MASK) as u8
}

/// `MT_TXD_CMD_INFO_TYPE` of a command buffer's info word.
pub fn command_id(info: u32) -> u8 {
    ((info >> TXD_CMD_INFO_TYPE_SHIFT) & TXD_CMD_INFO_TYPE_MASK) as u8
}

/// `MT_RXD_CMD_INFO_CMD_SEQ` of an MCU response word.
pub fn response_seq(rxfce: u32) -> u8 {
    ((rxfce >> RXD_CMD_INFO_SEQ_SHIFT) & RXD_CMD_INFO_SEQ_MASK) as u8
}

/// `MT_RXD_CMD_INFO_EVT_TYPE` of an MCU response word.
pub fn response_evt(rxfce: u32) -> u8 {
    ((rxfce >> RXD_CMD_INFO_EVT_SHIFT) & RXD_CMD_INFO_EVT_MASK) as u8
}

/// `MT_RXD_INFO_TYPE` of an RX info word.
pub fn rx_info_type(rxd: u32) -> u32 {
    (rxd >> RXD_INFO_TYPE_SHIFT) & 0x3
}

/// `MT_RXD_INFO_LEN` of an RX info word.
pub fn rx_info_len(rxd: u32) -> usize {
    (rxd & RXD_INFO_LEN_MASK) as usize
}

/// Read a little-endian `u32` from an RX buffer, if it is long enough.
pub fn read_le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let slice = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_info_word_encodes_port_and_raw_length() {
        assert_eq!(
            info_word(INFO_TYPE_DMA_PACKET, PORT_CPU_TX, 0, 0),
            PORT_CPU_TX << TXD_INFO_D_PORT_SHIFT
        );
        assert_eq!(
            info_word(INFO_TYPE_DMA_PACKET, PORT_CPU_TX, 0x40, 0),
            (PORT_CPU_TX << TXD_INFO_D_PORT_SHIFT) | 0x40
        );
    }

    #[test]
    fn packet_buffer_layout() {
        let buf = packet_buffer(&[1, 2, 3]);
        assert_eq!(buf.len(), 12);
        assert_eq!(
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            (PORT_CPU_TX << TXD_INFO_D_PORT_SHIFT) | 3
        );
        assert_eq!(&buf[4..7], &[1, 2, 3]);
        assert_eq!(&buf[7..12], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn packet_buffer_already_aligned() {
        assert_eq!(packet_buffer(&[0u8; 8]).len(), 16);
    }

    #[test]
    fn command_buffer_sets_type_seq_and_cmd() {
        let buf = command_buffer(&[0u8; 8], 5, 12);
        let info = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(info >> TXD_INFO_TYPE_SHIFT, INFO_TYPE_DMA_COMMAND);
        assert_eq!(command_seq(info), 5);
        assert_eq!(command_id(info), 12);
        // LEN is the 4-byte-rounded payload length.
        assert_eq!(info & TXD_INFO_LEN_MASK, 8);
    }

    #[test]
    fn command_buffer_rounds_length_field() {
        let buf = command_buffer(&[0u8; 5], 1, 1);
        let info = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(info & TXD_INFO_LEN_MASK, 8);
        assert_eq!(buf.len(), 4 + 8 + 4);
    }

    #[test]
    fn response_fields_round_trip() {
        let rxfce = (3u32 << RXD_CMD_INFO_SEQ_SHIFT) | (2u32 << RXD_CMD_INFO_EVT_SHIFT);
        assert_eq!(response_seq(rxfce), 3);
        assert_eq!(response_evt(rxfce), EVT_CMD_RETRY);
    }

    #[test]
    fn rx_info_fields() {
        let rxd = (INFO_TYPE_DMA_COMMAND << RXD_INFO_TYPE_SHIFT) | 0x1234;
        assert_eq!(rx_info_type(rxd), INFO_TYPE_DMA_COMMAND);
        assert_eq!(rx_info_len(rxd), 0x1234);
    }

    #[test]
    fn read_le_u32_bounds() {
        assert_eq!(read_le_u32(&[1, 0, 0, 0], 0), Some(1));
        assert_eq!(read_le_u32(&[1, 2, 3], 0), None);
    }
}
