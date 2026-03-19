use crate::error::AppError;

#[derive(Clone, Copy)]
pub(crate) struct RawAddrBuf {
    bytes: [u8; 16],
    len: usize,
}

impl RawAddrBuf {
    pub(crate) fn from_slice(value: &[u8], invalid_msg: &'static str) -> Result<Self, AppError> {
        if value.is_empty() || value.len() > 16 {
            return Err(AppError::netlink(invalid_msg));
        }
        let mut bytes = [0u8; 16];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            bytes,
            len: value.len(),
        })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
