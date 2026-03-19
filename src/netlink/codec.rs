use std::cell::Cell;
use std::mem::size_of;

use crate::error::AppError;

pub(crate) const IFA_F_TEMPORARY: u32 = 0x01;
pub(crate) const IFA_F_OPTIMISTIC: u32 = 0x04;
pub(crate) const IFA_F_DADFAILED: u32 = 0x08;
pub(crate) const IFA_F_DEPRECATED: u32 = 0x20;
pub(crate) const IFA_F_TENTATIVE: u32 = 0x40;
pub(crate) const IFA_F_MANAGETEMPADDR: u32 = 0x100;
pub(crate) const IFA_F_STABLE_PRIVACY: u32 = 0x800;

pub(crate) const IFA_ATTR_FLAGS: u16 = 8;

pub(crate) const FRA_ATTR_DST: u16 = 1;
pub(crate) const FRA_ATTR_PRIORITY: u16 = 6;
pub(crate) const FRA_ATTR_TABLE: u16 = 15;

pub(crate) const NLMSGERR_ATTR_MSG: u16 = 1;
pub(crate) const NLMSGERR_ATTR_OFFS: u16 = 2;
const EXT_ACK_TEXT_MAX: usize = 96;

const NLA_HEADER_LEN: usize = 4;
const NLA_ALIGN_TO: usize = 4;
const NLMSG_ALIGN_TO: usize = 4;

pub(crate) const ROUTE_EVENT_BUFFER_SIZE: usize = 64 * 1024;
pub(crate) const ROUTE_SOCKET_RECV_BUF: i32 = 4 * 1024 * 1024;

pub(crate) const CLEANUP_BATCH_SIZE: usize = 64;

thread_local! {
    static NEXT_SEQ: Cell<u32> = const { Cell::new(1) };
}

#[derive(Clone, Copy)]
pub(crate) struct NetlinkMessageView<'a> {
    pub(crate) header: libc::nlmsghdr,
    pub(crate) data: &'a [u8],
}

pub(crate) struct NetlinkMessageIter<'a> {
    raw: &'a [u8],
}

impl<'a> NetlinkMessageIter<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }
}

impl<'a> Iterator for NetlinkMessageIter<'a> {
    type Item = Result<NetlinkMessageView<'a>, AppError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }
        if self.raw.len() < size_of::<libc::nlmsghdr>() {
            self.raw = &[];
            return Some(Err(AppError::netlink("short nlmsghdr")));
        }

        let header =
            unsafe { std::ptr::read_unaligned(self.raw.as_ptr() as *const libc::nlmsghdr) };
        let len = header.nlmsg_len as usize;
        if len < size_of::<libc::nlmsghdr>() || len > self.raw.len() {
            self.raw = &[];
            return Some(Err(AppError::netlink("invalid nlmsg len")));
        }

        let body = &self.raw[size_of::<libc::nlmsghdr>()..len];
        let step = nlmsg_align(len);
        if step > self.raw.len() {
            self.raw = &[];
            return Some(Err(AppError::netlink("invalid nlmsg step")));
        }
        self.raw = &self.raw[step..];

        Some(Ok(NetlinkMessageView { header, data: body }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AckErrorInfo {
    pub(crate) errno: i32,
    pub(crate) ext_msg: Option<ExtAckText>,
    pub(crate) ext_offset: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExtAckText {
    len: u8,
    bytes: [u8; EXT_ACK_TEXT_MAX],
}

impl ExtAckText {
    pub(crate) fn from_str(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        let bytes = trimmed.as_bytes();
        if !bytes.is_ascii() {
            return None;
        }

        let take = bytes.len().min(EXT_ACK_TEXT_MAX);
        let mut out = [0u8; EXT_ACK_TEXT_MAX];
        out[..take].copy_from_slice(&bytes[..take]);
        Some(Self {
            len: take as u8,
            bytes: out,
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.bytes[..self.len as usize]) }
    }
}

pub(crate) fn nlmsg_align(n: usize) -> usize {
    (n + NLMSG_ALIGN_TO - 1) & !(NLMSG_ALIGN_TO - 1)
}

fn nla_align(n: usize) -> usize {
    (n + NLA_ALIGN_TO - 1) & !(NLA_ALIGN_TO - 1)
}

pub(crate) fn parse_ack_errno(data: &[u8]) -> Result<Option<i32>, AppError> {
    if data.len() < 4 {
        return Err(AppError::netlink("short nlmsg error"));
    }
    let code = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    if code == 0 {
        return Ok(None);
    }
    Ok(Some(-code))
}

pub(crate) fn parse_ack_error_info(data: &[u8]) -> Result<Option<AckErrorInfo>, AppError> {
    let Some(errno) = parse_ack_errno(data)? else {
        return Ok(None);
    };

    let mut ext_msg: Option<ExtAckText> = None;
    let mut ext_offset: Option<u32> = None;

    let nlmsgerr_len = size_of::<i32>() + size_of::<libc::nlmsghdr>();
    let attrs = data.get(nlmsg_align(nlmsgerr_len)..).unwrap_or(&[]);
    let _ = parse_nlas(attrs, |typ, value| {
        match typ {
            NLMSGERR_ATTR_MSG => {
                let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
                let text = std::str::from_utf8(&value[..end]).ok();
                if let Some(text) = text.and_then(ExtAckText::from_str) {
                    ext_msg = Some(text);
                }
            }
            NLMSGERR_ATTR_OFFS if value.len() >= 4 => {
                ext_offset = Some(u32::from_ne_bytes([value[0], value[1], value[2], value[3]]));
            }
            _ => {}
        }
        Ok(())
    });

    Ok(Some(AckErrorInfo {
        errno,
        ext_msg,
        ext_offset,
    }))
}

pub(crate) fn seq_to_batch_index(seq: u32, first_seq: u32, batch_len: usize) -> Option<usize> {
    if batch_len == 0 {
        return None;
    }
    if seq == 0 {
        return None;
    }
    let span = u32::MAX as u64;
    let start = normalize_seq(first_seq) as u64;
    let current = normalize_seq(seq) as u64;
    let delta = if current >= start {
        current - start
    } else {
        span - (start - current)
    };
    if delta < batch_len as u64 {
        Some(delta as usize)
    } else {
        None
    }
}

pub(crate) fn append_zeros(dst: &mut Vec<u8>, n: usize) {
    if n == 0 {
        return;
    }
    dst.resize(dst.len() + n, 0);
}

pub(crate) fn append_nla(dst: &mut Vec<u8>, typ: u16, payload: &[u8]) {
    let nla_len = NLA_HEADER_LEN + payload.len();
    let aligned = nla_align(nla_len);
    let start = dst.len();
    append_zeros(dst, aligned);

    dst[start..start + 2].copy_from_slice(&(nla_len as u16).to_ne_bytes());
    dst[start + 2..start + 4].copy_from_slice(&typ.to_ne_bytes());
    dst[start + NLA_HEADER_LEN..start + NLA_HEADER_LEN + payload.len()].copy_from_slice(payload);
}

pub(crate) fn append_nla_u32(dst: &mut Vec<u8>, typ: u16, value: u32) {
    append_nla(dst, typ, &value.to_ne_bytes());
}

pub(crate) fn build_netlink_request<T: Copy>(
    nlmsg_type: u16,
    nlmsg_flags: u16,
    seq: u32,
    body: &T,
) -> Vec<u8> {
    let body_len = size_of::<T>();
    let total = size_of::<libc::nlmsghdr>() + body_len;
    let mut msg = Vec::with_capacity(total + 16);
    append_zeros(&mut msg, total);

    unsafe {
        std::ptr::write_unaligned(
            msg.as_mut_ptr() as *mut libc::nlmsghdr,
            libc::nlmsghdr {
                nlmsg_len: total as u32,
                nlmsg_type,
                nlmsg_flags,
                nlmsg_seq: seq,
                nlmsg_pid: 0,
            },
        );
        std::ptr::write_unaligned(
            msg[size_of::<libc::nlmsghdr>()..].as_mut_ptr() as *mut T,
            *body,
        );
    }

    let aligned = nlmsg_align(msg.len());
    let pad = aligned.saturating_sub(msg.len());
    if pad > 0 {
        append_zeros(&mut msg, pad);
    }
    msg
}

pub(crate) fn parse_nlas<F>(mut raw: &[u8], mut cb: F) -> Result<(), AppError>
where
    F: FnMut(u16, &[u8]) -> Result<(), AppError>,
{
    while raw.len() >= NLA_HEADER_LEN {
        let nla_len = u16::from_ne_bytes([raw[0], raw[1]]) as usize;
        let nla_type = u16::from_ne_bytes([raw[2], raw[3]]);
        if nla_len < NLA_HEADER_LEN || nla_len > raw.len() {
            return Err(AppError::netlink("invalid nla len"));
        }
        let value = &raw[NLA_HEADER_LEN..nla_len];
        cb(nla_type, value)?;
        let step = nla_align(nla_len);
        if step > raw.len() {
            return Err(AppError::netlink("invalid nla step"));
        }
        raw = &raw[step..];
    }
    if !raw.is_empty() {
        return Err(AppError::netlink("unexpected trailing nla bytes"));
    }
    Ok(())
}

pub(crate) fn next_seq() -> u32 {
    reserve_seq_block(1)
}

pub(crate) fn reserve_seq_block(count: usize) -> u32 {
    let steps = count.max(1);
    NEXT_SEQ.with(|next| {
        let current = normalize_seq(next.get());
        let next_value = seq_advance(current, steps);
        next.set(next_value);
        current
    })
}

pub(crate) fn seq_with_offset(first_seq: u32, offset: usize) -> u32 {
    seq_advance(normalize_seq(first_seq), offset)
}

#[inline]
fn normalize_seq(value: u32) -> u32 {
    if value == 0 { 1 } else { value }
}

#[inline]
fn seq_advance(start: u32, steps: usize) -> u32 {
    let span = u32::MAX as u64;
    let start = normalize_seq(start) as u64;
    let offset = (steps as u64) % span;
    (((start - 1 + offset) % span) + 1) as u32
}

#[cfg(test)]
mod tests {
    use super::seq_to_batch_index;
    use super::{NetlinkMessageIter, parse_nlas, seq_with_offset};
    use proptest::prelude::*;

    #[test]
    fn seq_to_batch_index_contract() {
        assert_eq!(seq_to_batch_index(99, 100, 4), None);
        assert_eq!(seq_to_batch_index(100, 100, 4), Some(0));
        assert_eq!(seq_to_batch_index(103, 100, 4), Some(3));
        assert_eq!(seq_to_batch_index(104, 100, 4), None);
        assert_eq!(seq_to_batch_index(0, u32::MAX - 1, 4), None);
        assert_eq!(seq_to_batch_index(1, u32::MAX - 1, 4), Some(2));
        assert_eq!(seq_to_batch_index(2, u32::MAX - 1, 4), Some(3));
    }

    #[test]
    fn seq_with_offset_skips_zero_on_wrap() {
        assert_eq!(seq_with_offset(u32::MAX - 1, 0), u32::MAX - 1);
        assert_eq!(seq_with_offset(u32::MAX - 1, 1), u32::MAX);
        assert_eq!(seq_with_offset(u32::MAX - 1, 2), 1);
        assert_eq!(seq_with_offset(u32::MAX - 1, 3), 2);
    }

    proptest! {
        #[test]
        fn netlink_iter_does_not_panic_on_random_data(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let mut count = 0usize;
            for item in NetlinkMessageIter::new(&data) {
                let _ = item.is_ok();
                count += 1;
                if count > 2048 {
                    break;
                }
            }
        }

        #[test]
        fn parse_nlas_does_not_panic_on_random_data(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_nlas(&data, |_typ, _value| Ok(()));
        }
    }
}
