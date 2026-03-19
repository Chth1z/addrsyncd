use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use crate::error::AppError;
use crate::netlink::codec::{
    AckErrorInfo, ExtAckText, FRA_ATTR_DST, FRA_ATTR_PRIORITY, FRA_ATTR_TABLE, NetlinkMessageIter,
    append_nla, append_nla_u32, append_zeros, parse_ack_error_info, reserve_seq_block,
    seq_to_batch_index, seq_with_offset,
};
use crate::netlink::linux_types::RtMsg;
use crate::netlink::socket::{MmsgRxRing, MmsgTxBatch, NetlinkSocket, is_transient_recv_err};

pub(crate) const ACK_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RuleAction {
    Delete,
    Add,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RuleOp {
    pub(crate) addr: IpAddr,
    pub(crate) action: RuleAction,
}

impl RuleOp {
    pub(crate) fn is_add(&self) -> bool {
        matches!(self.action, RuleAction::Add)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RuleContext {
    pub(crate) pref: u32,
    pub(crate) table_id: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct NetlinkAckStatus {
    pub(crate) errno: i32,
    pub(crate) ext_msg: Option<ExtAckText>,
    pub(crate) ext_offset: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleAckClass {
    Ok,
    EexistNoop,
    EnoentNoop,
    KernelErr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AckWaitErrorKind {
    Timeout,
    SeqMismatch,
    NonAck,
}

#[derive(Debug, Clone)]
pub(crate) struct AckWaitError {
    pub(crate) kind: AckWaitErrorKind,
    pub(crate) pending: usize,
    pub(crate) count_seq_mismatch: usize,
    pub(crate) count_non_ack: usize,
}

impl AckWaitError {
    pub(crate) fn to_app_error(&self) -> AppError {
        let kind = match self.kind {
            AckWaitErrorKind::Timeout => "timeout",
            AckWaitErrorKind::SeqMismatch => "seq_mismatch",
            AckWaitErrorKind::NonAck => "non_ack",
        };
        AppError::netlink(format!(
            "ack_wait_failed kind={kind} pending={} count_seq_mismatch={} count_non_ack={}",
            self.pending, self.count_seq_mismatch, self.count_non_ack
        ))
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct AckTracker {
    seen: Vec<bool>,
    status: Vec<Option<NetlinkAckStatus>>,
    pending: usize,
    count_seq_mismatch: usize,
    count_non_ack: usize,
}

impl AckTracker {
    pub(crate) fn prepare(&mut self, batch_len: usize) {
        self.seen.clear();
        self.status.clear();
        self.seen.resize(batch_len, false);
        self.status.resize(batch_len, None);
        self.pending = batch_len;
        self.count_seq_mismatch = 0;
        self.count_non_ack = 0;
    }

    pub(crate) fn pending(&self) -> usize {
        self.pending
    }

    pub(crate) fn seen_at(&self, idx: usize) -> bool {
        self.seen.get(idx).copied().unwrap_or(false)
    }

    pub(crate) fn status_at(&self, idx: usize) -> Option<&NetlinkAckStatus> {
        self.status.get(idx).and_then(|v| v.as_ref())
    }

    fn mark_non_ack(&mut self) {
        self.count_non_ack = self.count_non_ack.saturating_add(1);
    }

    fn mark_seq_mismatch(&mut self) {
        self.count_seq_mismatch = self.count_seq_mismatch.saturating_add(1);
    }

    fn mark_status(&mut self, idx: usize, status: Option<NetlinkAckStatus>) {
        if idx >= self.seen.len() || self.seen[idx] {
            return;
        }
        self.seen[idx] = true;
        self.status[idx] = status;
        self.pending = self.pending.saturating_sub(1);
    }
}

pub(crate) struct ApplyScratch {
    outbound: Vec<Vec<u8>>,
    tx_ptrs: Vec<*const u8>,
    tx_lens: Vec<usize>,
    recv_ring: MmsgRxRing,
    tx_batch: MmsgTxBatch,
    pub(crate) blocking_tracker: AckTracker,
}

impl Default for ApplyScratch {
    fn default() -> Self {
        Self {
            outbound: Vec::new(),
            tx_ptrs: Vec::new(),
            tx_lens: Vec::new(),
            recv_ring: MmsgRxRing::default(),
            tx_batch: MmsgTxBatch::with_capacity(64),
            blocking_tracker: AckTracker::default(),
        }
    }
}

pub(crate) fn new_rule_context(pref: NonZeroU32, table_id: NonZeroU32) -> RuleContext {
    RuleContext {
        pref: pref.get(),
        table_id: table_id.get(),
    }
}

pub(crate) fn start_apply_rules_batch(
    socket: &NetlinkSocket,
    rule_ctx: RuleContext,
    ops: &[RuleOp],
    scratch: &mut ApplyScratch,
    tracker: &mut AckTracker,
) -> Result<u32, AppError> {
    if ops.is_empty() {
        tracker.prepare(0);
        return Ok(0);
    }

    let first_seq = reserve_seq_block(ops.len());

    if scratch.outbound.len() < ops.len() {
        scratch
            .outbound
            .resize_with(ops.len(), || Vec::with_capacity(128));
    }
    for msg in scratch.outbound.iter_mut().take(ops.len()) {
        msg.clear();
    }

    for (index, op) in ops.iter().enumerate() {
        build_rule_message_into(
            &mut scratch.outbound[index],
            rule_ctx,
            *op,
            seq_with_offset(first_seq, index),
        )?;
    }

    if scratch.tx_ptrs.len() < ops.len() {
        scratch.tx_ptrs.resize(ops.len(), std::ptr::null());
    }
    if scratch.tx_lens.len() < ops.len() {
        scratch.tx_lens.resize(ops.len(), 0);
    }
    for (idx, msg) in scratch.outbound.iter().take(ops.len()).enumerate() {
        scratch.tx_ptrs[idx] = msg.as_ptr();
        scratch.tx_lens[idx] = msg.len();
    }
    socket.send_many_raw(
        &scratch.tx_ptrs[..ops.len()],
        &scratch.tx_lens[..ops.len()],
        &mut scratch.tx_batch,
    )?;

    tracker.prepare(ops.len());
    Ok(first_seq)
}

pub(crate) fn drain_apply_ack_messages(
    socket: &NetlinkSocket,
    first_seq: u32,
    ops: &[RuleOp],
    scratch: &mut ApplyScratch,
    tracker: &mut AckTracker,
) -> Result<(), AppError> {
    loop {
        let count = match socket.recv_many(&mut scratch.recv_ring) {
            Ok(n) => n,
            Err(err) if is_transient_recv_err(&err) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        if count == 0 {
            return Ok(());
        }

        for idx in 0..count {
            let raw = scratch.recv_ring.packet(idx);
            for msg in NetlinkMessageIter::new(raw) {
                let msg = msg?;
                if msg.header.nlmsg_type != libc::NLMSG_ERROR as u16 {
                    tracker.mark_non_ack();
                    continue;
                }

                let Some(batch_idx) =
                    seq_to_batch_index(msg.header.nlmsg_seq, first_seq, ops.len())
                else {
                    tracker.mark_seq_mismatch();
                    continue;
                };

                let ack = parse_ack_error_info(msg.data)?.map(
                    |AckErrorInfo {
                         errno,
                         ext_msg,
                         ext_offset,
                     }| NetlinkAckStatus {
                        errno,
                        ext_msg,
                        ext_offset,
                    },
                );
                tracker.mark_status(batch_idx, ack);
            }
        }
    }
}

pub(crate) fn classify_ack_for_op(op: RuleOp, status: Option<&NetlinkAckStatus>) -> RuleAckClass {
    let Some(status) = status else {
        return RuleAckClass::Ok;
    };
    if op.is_add() && status.errno == libc::EEXIST {
        return RuleAckClass::EexistNoop;
    }
    if !op.is_add() && (status.errno == libc::ENOENT || status.errno == libc::ESRCH) {
        return RuleAckClass::EnoentNoop;
    }
    RuleAckClass::KernelErr
}

pub(crate) fn classify_wait_error(tracker: &AckTracker) -> AckWaitError {
    let kind = if tracker.count_seq_mismatch > 0 && tracker.count_non_ack == 0 {
        AckWaitErrorKind::SeqMismatch
    } else if tracker.count_non_ack > 0 && tracker.count_seq_mismatch == 0 {
        AckWaitErrorKind::NonAck
    } else {
        AckWaitErrorKind::Timeout
    };
    AckWaitError {
        kind,
        pending: tracker.pending,
        count_seq_mismatch: tracker.count_seq_mismatch,
        count_non_ack: tracker.count_non_ack,
    }
}

pub(crate) fn build_rule_message_into(
    dst: &mut Vec<u8>,
    rule_ctx: RuleContext,
    op: RuleOp,
    seq: u32,
) -> Result<(), AppError> {
    let (family, addr, addr_len, dst_len) = addr_to_netlink(op.addr)?;

    let req_type = if op.is_add() {
        libc::RTM_NEWRULE
    } else {
        libc::RTM_DELRULE
    };
    let mut req_flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16;
    if op.is_add() {
        req_flags |= libc::NLM_F_CREATE as u16 | libc::NLM_F_EXCL as u16;
    }

    let mut rtm: RtMsg = unsafe { std::mem::zeroed() };
    rtm.rtm_family = family as u8;
    rtm.rtm_dst_len = dst_len;
    rtm.rtm_protocol = libc::RTPROT_BOOT;
    rtm.rtm_scope = libc::RT_SCOPE_UNIVERSE;
    rtm.rtm_type = libc::RTN_UNICAST;
    if rule_ctx.table_id <= 255 {
        rtm.rtm_table = rule_ctx.table_id as u8;
    }

    let start = dst.len();
    append_zeros(
        dst,
        std::mem::size_of::<libc::nlmsghdr>() + std::mem::size_of::<RtMsg>(),
    );
    let body_start = start + std::mem::size_of::<libc::nlmsghdr>();
    unsafe {
        std::ptr::write_unaligned(dst[body_start..].as_mut_ptr() as *mut RtMsg, rtm);
    }

    append_nla(dst, FRA_ATTR_DST, &addr[..addr_len]);
    append_nla_u32(dst, FRA_ATTR_PRIORITY, rule_ctx.pref);
    append_nla_u32(dst, FRA_ATTR_TABLE, rule_ctx.table_id);

    let msg_len = dst.len() - start;
    let hdr = libc::nlmsghdr {
        nlmsg_len: msg_len as u32,
        nlmsg_type: req_type,
        nlmsg_flags: req_flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    };
    unsafe {
        std::ptr::write_unaligned(dst[start..].as_mut_ptr() as *mut libc::nlmsghdr, hdr);
    }

    let aligned = crate::netlink::codec::nlmsg_align(msg_len);
    if aligned > msg_len {
        append_zeros(dst, aligned - msg_len);
    }

    Ok(())
}

pub(crate) fn addr_from_netlink(family: u8, raw: &[u8]) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET => {
            if raw.len() < 4 {
                return None;
            }
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                raw[0], raw[1], raw[2], raw[3],
            )))
        }
        libc::AF_INET6 => {
            if raw.len() < 16 {
                return None;
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&raw[..16]);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

fn addr_to_netlink(addr: IpAddr) -> Result<(i32, [u8; 16], usize, u8), AppError> {
    match addr {
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[..4].copy_from_slice(&v4.octets());
            Ok((libc::AF_INET, buf, 4, 32))
        }
        IpAddr::V6(v6) => {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&v6.octets());
            Ok((libc::AF_INET6, buf, 16, 128))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::linux_types::RtMsg;
    use std::mem::size_of;

    #[test]
    fn classify_wait_error_kind_contract() {
        let mut tracker = AckTracker::default();
        tracker.prepare(3);
        assert_eq!(
            classify_wait_error(&tracker).kind,
            AckWaitErrorKind::Timeout
        );

        tracker.count_seq_mismatch = 1;
        tracker.count_non_ack = 0;
        assert_eq!(
            classify_wait_error(&tracker).kind,
            AckWaitErrorKind::SeqMismatch
        );

        tracker.count_seq_mismatch = 0;
        tracker.count_non_ack = 1;
        assert_eq!(classify_wait_error(&tracker).kind, AckWaitErrorKind::NonAck);
    }

    #[test]
    fn ack_anomaly_timeout_classifies() {
        let mut tracker = AckTracker::default();
        tracker.prepare(2);
        let err = classify_wait_error(&tracker);
        assert_eq!(err.kind, AckWaitErrorKind::Timeout);
        assert_eq!(err.pending, 2);
        assert!(err.to_app_error().to_string().contains("timeout"));
    }

    #[test]
    fn ack_anomaly_seq_mismatch_classifies() {
        let mut tracker = AckTracker::default();
        tracker.prepare(2);
        tracker.count_seq_mismatch = 3;
        let err = classify_wait_error(&tracker);
        assert_eq!(err.kind, AckWaitErrorKind::SeqMismatch);
        assert!(err.to_app_error().to_string().contains("seq_mismatch"));
    }

    #[test]
    fn ack_anomaly_non_ack_classifies() {
        let mut tracker = AckTracker::default();
        tracker.prepare(2);
        tracker.count_non_ack = 4;
        let err = classify_wait_error(&tracker);
        assert_eq!(err.kind, AckWaitErrorKind::NonAck);
        assert!(err.to_app_error().to_string().contains("non_ack"));
    }

    #[test]
    fn ack_anomaly_kernel_errno_classifies() {
        let op = RuleOp {
            addr: "10.0.0.1".parse().expect("ip"),
            action: RuleAction::Add,
        };
        let status = NetlinkAckStatus {
            errno: libc::EPERM,
            ext_msg: ExtAckText::from_str("operation not permitted"),
            ext_offset: Some(12),
        };
        assert_eq!(
            classify_ack_for_op(op, Some(&status)),
            RuleAckClass::KernelErr
        );
    }

    #[test]
    fn classify_ack_for_op_contract() {
        let add = RuleOp {
            addr: "10.0.0.1".parse().expect("ip"),
            action: RuleAction::Add,
        };
        let del = RuleOp {
            addr: "10.0.0.1".parse().expect("ip"),
            action: RuleAction::Delete,
        };

        assert_eq!(classify_ack_for_op(add, None), RuleAckClass::Ok);
        assert_eq!(classify_ack_for_op(del, None), RuleAckClass::Ok);

        let exist = NetlinkAckStatus {
            errno: libc::EEXIST,
            ext_msg: None,
            ext_offset: None,
        };
        let enoent = NetlinkAckStatus {
            errno: libc::ENOENT,
            ext_msg: None,
            ext_offset: None,
        };
        let failed = NetlinkAckStatus {
            errno: libc::EPERM,
            ext_msg: None,
            ext_offset: None,
        };

        assert_eq!(
            classify_ack_for_op(add, Some(&exist)),
            RuleAckClass::EexistNoop
        );
        assert_eq!(
            classify_ack_for_op(del, Some(&enoent)),
            RuleAckClass::EnoentNoop
        );
        assert_eq!(
            classify_ack_for_op(add, Some(&failed)),
            RuleAckClass::KernelErr
        );
    }

    #[test]
    fn build_rule_message_fields() {
        let mut buf = Vec::new();
        let ctx = RuleContext {
            pref: 1900,
            table_id: 254,
        };
        let op = RuleOp {
            addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3)),
            action: RuleAction::Add,
        };

        build_rule_message_into(&mut buf, ctx, op, 777).expect("build");
        assert!(buf.len() >= size_of::<libc::nlmsghdr>() + size_of::<RtMsg>());

        let hdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const libc::nlmsghdr) };
        assert_eq!(hdr.nlmsg_type, libc::RTM_NEWRULE);
        assert_eq!(hdr.nlmsg_seq, 777);

        let rtm = unsafe {
            std::ptr::read_unaligned(buf[size_of::<libc::nlmsghdr>()..].as_ptr() as *const RtMsg)
        };
        assert_eq!(rtm.rtm_family as i32, libc::AF_INET);
        assert_eq!(rtm.rtm_dst_len, 32);
    }
}
