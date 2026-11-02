//! Firmware image parsing.
//!
//! Pure functions transcribed from `mcu.c` (`struct mt76_fw_header`,
//! `mt7601u_load_firmware`). DMA framing lives in [`super::dma`].

/// Size of `struct mt76_fw_header` in bytes.
pub const FW_HEADER_LEN: usize = 32;

/// Maximum firmware payload per USB bulk transfer (`MCU_FW_URB_MAX_PAYLOAD`).
pub const MCU_FW_URB_MAX_PAYLOAD: usize = 0x3800;

/// Errors from parsing a firmware image.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FwError {
    #[error("firmware image too small: {0} bytes")]
    TooSmall(usize),
    #[error("invalid firmware ILM length: {0}")]
    InvalidIlmLen(u32),
    #[error("firmware size mismatch: header implies {expected} bytes but file is {actual}")]
    SizeMismatch { expected: usize, actual: usize },
}

/// Parsed firmware header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwHeader {
    pub ilm_len: u32,
    pub dlm_len: u32,
    pub build_ver: u16,
    pub fw_ver: u16,
}

impl FwHeader {
    /// Human-readable firmware version, matching the driver's formatting.
    pub fn version_string(&self) -> String {
        let val = self.fw_ver;
        format!(
            "{}.{}.{:02}",
            (val >> 12) & 0xf,
            (val >> 8) & 0xf,
            val & 0xf
        )
    }
}

/// A firmware image split into its transfer sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firmware<'a> {
    pub header: FwHeader,
    /// Interrupt vector block, sent via a separate vendor request.
    pub ivb: &'a [u8],
    /// ILM code, uploaded to address `MT_MCU_IVB_SIZE`.
    pub ilm: &'a [u8],
    /// DLM data, uploaded to `MT_MCU_DLM_OFFSET`.
    pub dlm: &'a [u8],
    /// Raw build-time string from the header.
    pub build_time: [u8; 16],
}

impl Firmware<'_> {
    /// Build-time string with trailing NULs trimmed.
    pub fn build_time_string(&self) -> String {
        let end = self
            .build_time
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.build_time.len());
        String::from_utf8_lossy(&self.build_time[..end]).into_owned()
    }
}

fn read_le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Parse and validate a `mt7601u.bin` image.
pub fn parse(data: &[u8]) -> Result<Firmware<'_>, FwError> {
    if data.len() < FW_HEADER_LEN {
        return Err(FwError::TooSmall(data.len()));
    }

    let ilm_len = read_le_u32(data, 0);
    let dlm_len = read_le_u32(data, 4);
    let header = FwHeader {
        ilm_len,
        dlm_len,
        build_ver: read_le_u16(data, 8),
        fw_ver: read_le_u16(data, 10),
    };

    if ilm_len as usize <= crate::mt7601u::regs::MT_MCU_IVB_SIZE {
        return Err(FwError::InvalidIlmLen(ilm_len));
    }

    let expected = FW_HEADER_LEN + ilm_len as usize + dlm_len as usize;
    if expected != data.len() {
        return Err(FwError::SizeMismatch {
            expected,
            actual: data.len(),
        });
    }

    let ivb_start = FW_HEADER_LEN;
    let ilm_start = ivb_start + crate::mt7601u::regs::MT_MCU_IVB_SIZE;
    let dlm_start = FW_HEADER_LEN + ilm_len as usize;

    let mut build_time = [0u8; 16];
    build_time.copy_from_slice(&data[16..32]);

    Ok(Firmware {
        header,
        ivb: &data[ivb_start..ilm_start],
        ilm: &data[ilm_start..dlm_start],
        dlm: &data[dlm_start..expected],
        build_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mt7601u::regs::MT_MCU_IVB_SIZE;

    fn fake_image(ilm_len: u32, dlm_len: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&ilm_len.to_le_bytes());
        data.extend_from_slice(&dlm_len.to_le_bytes());
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // build_ver
        data.extend_from_slice(&0x1002u16.to_le_bytes()); // fw_ver
        data.extend_from_slice(&[0u8; 4]); // pad
        let mut build_time = [0u8; 16];
        build_time[..5].copy_from_slice(b"build");
        data.extend_from_slice(&build_time);
        data.resize(FW_HEADER_LEN + ilm_len as usize + dlm_len as usize, 0xab);
        data
    }

    #[test]
    fn parses_sections_with_correct_offsets() {
        let image = fake_image(0x100, 0x40);
        let fw = parse(&image).expect("valid image");
        assert_eq!(fw.header.ilm_len, 0x100);
        assert_eq!(fw.header.dlm_len, 0x40);
        assert_eq!(fw.ivb.len(), MT_MCU_IVB_SIZE);
        assert_eq!(fw.ilm.len(), 0x100 - MT_MCU_IVB_SIZE);
        assert_eq!(fw.dlm.len(), 0x40);
        assert_eq!(fw.build_time_string(), "build");
        assert_eq!(fw.header.version_string(), "1.0.02");
    }

    #[test]
    fn rejects_short_ilm_length() {
        let image = fake_image(MT_MCU_IVB_SIZE as u32, 0);
        assert_eq!(
            parse(&image),
            Err(FwError::InvalidIlmLen(MT_MCU_IVB_SIZE as u32))
        );
    }

    #[test]
    fn rejects_size_mismatch() {
        let mut image = fake_image(0x100, 0x40);
        image.push(0);
        assert!(matches!(parse(&image), Err(FwError::SizeMismatch { .. })));
    }

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(parse(&[0u8; 8]), Err(FwError::TooSmall(8)));
    }
}
