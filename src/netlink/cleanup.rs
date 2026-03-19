use std::mem::size_of;
use std::net::IpAddr;

use rustc_hash::FxHashSet;

use crate::error::AppError;
use crate::netlink::codec::{
    FRA_ATTR_DST, FRA_ATTR_PRIORITY, FRA_ATTR_TABLE, build_netlink_request, next_seq, parse_nlas,
};
use crate::netlink::dump_engine::{DumpEngine, DumpPoll, DumpStep};
use crate::netlink::linux_types::RtMsg;
use crate::netlink::raw_addr::RawAddrBuf;
use crate::netlink::rule::{RuleAction, RuleContext, RuleOp, addr_from_netlink};
use crate::netlink::socket::NetlinkSocket;

#[derive(Default)]
pub(crate) struct CleanupDumpScratch {
    engine: DumpEngine,
    seen: FxHashSet<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupDumpPoll {
    Pending,
    Done,
}

impl CleanupDumpScratch {
    pub(crate) fn begin_family(&mut self) {
        self.seen.clear();
    }
}

pub(crate) fn start_cleanup_dump_family(
    socket: &NetlinkSocket,
    family: i32,
    seq: u32,
    scratch: &mut CleanupDumpScratch,
) -> Result<(), AppError> {
    let msg = build_rule_dump_message(family, seq);
    socket.send(&msg)?;
    scratch.begin_family();
    Ok(())
}

pub(crate) fn poll_cleanup_targets_stream_with_scratch<F>(
    socket: &NetlinkSocket,
    rule_ctx: RuleContext,
    family: i32,
    seq: u32,
    scratch: &mut CleanupDumpScratch,
    mut on_target: F,
) -> Result<CleanupDumpPoll, AppError>
where
    F: FnMut(RuleOp) -> Result<(), AppError>,
{
    match scratch.engine.recv_step(socket, seq, |msg| {
        if msg.header.nlmsg_type as i32 != libc::RTM_NEWRULE as i32 {
            return Ok(DumpStep::Continue);
        }
        if let Some(addr) = parse_cleanup_rule_addr(msg, rule_ctx, family)?
            && scratch.seen.insert(addr)
        {
            on_target(RuleOp {
                addr,
                action: RuleAction::Delete,
            })?;
        }
        Ok(DumpStep::Continue)
    })? {
        DumpPoll::Pending | DumpPoll::Continue => Ok(CleanupDumpPoll::Pending),
        DumpPoll::Done => Ok(CleanupDumpPoll::Done),
    }
}

pub(crate) fn dump_cleanup_targets_stream_with_scratch<F>(
    socket: &NetlinkSocket,
    rule_ctx: RuleContext,
    family: i32,
    scratch: &mut CleanupDumpScratch,
    mut on_target: F,
) -> Result<usize, AppError>
where
    F: FnMut(RuleOp) -> Result<(), AppError>,
{
    let seq = next_seq();
    start_cleanup_dump_family(socket, family, seq, scratch)?;
    let mut count = 0usize;

    scratch.engine.recv_until_done(socket, seq, |msg| {
        if msg.header.nlmsg_type as i32 != libc::RTM_NEWRULE as i32 {
            return Ok(DumpStep::Continue);
        }
        if let Some(addr) = parse_cleanup_rule_addr(msg, rule_ctx, family)?
            && scratch.seen.insert(addr)
        {
            on_target(RuleOp {
                addr,
                action: RuleAction::Delete,
            })?;
            count += 1;
        }
        Ok(DumpStep::Continue)
    })?;

    Ok(count)
}

pub(crate) fn build_rule_dump_message(family: i32, seq: u32) -> Vec<u8> {
    let mut rtm: RtMsg = unsafe { std::mem::zeroed() };
    rtm.rtm_family = family as u8;
    build_netlink_request(
        libc::RTM_GETRULE,
        (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
        seq,
        &rtm,
    )
}

pub(crate) fn parse_cleanup_rule_addr(
    msg: crate::netlink::codec::NetlinkMessageView<'_>,
    rule_ctx: RuleContext,
    family: i32,
) -> Result<Option<IpAddr>, AppError> {
    if msg.data.len() < size_of::<RtMsg>() {
        return Ok(None);
    }

    let rtm = unsafe { std::ptr::read_unaligned(msg.data.as_ptr() as *const RtMsg) };
    if rtm.rtm_family as i32 != family {
        return Ok(None);
    }
    if family == libc::AF_INET && rtm.rtm_dst_len != 32 {
        return Ok(None);
    }
    if family == libc::AF_INET6 && rtm.rtm_dst_len != 128 {
        return Ok(None);
    }

    let mut table_id = rtm.rtm_table as u32;
    let mut pref = 0u32;
    let mut has_pref = false;
    let mut dst: Option<RawAddrBuf> = None;

    parse_nlas(&msg.data[size_of::<RtMsg>()..], |typ, value| {
        match typ {
            FRA_ATTR_PRIORITY if value.len() >= 4 => {
                pref = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                has_pref = true;
            }
            FRA_ATTR_TABLE if value.len() >= 4 => {
                table_id = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
            }
            FRA_ATTR_DST => {
                dst = Some(RawAddrBuf::from_slice(
                    value,
                    "rule dump invalid FRA_DST length",
                )?);
            }
            _ => {}
        }
        Ok(())
    })?;

    let Some(dst) = dst else {
        return Ok(None);
    };

    if !has_pref || pref != rule_ctx.pref || table_id != rule_ctx.table_id {
        return Ok(None);
    }

    Ok(addr_from_netlink(rtm.rtm_family, dst.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::codec::{
        FRA_ATTR_DST, FRA_ATTR_PRIORITY, FRA_ATTR_TABLE, NetlinkMessageView, append_nla,
        append_nla_u32, append_zeros,
    };
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn build_rule_dump_message_fields() {
        let msg = build_rule_dump_message(libc::AF_INET6, 123);
        let hdr = unsafe { std::ptr::read_unaligned(msg.as_ptr() as *const libc::nlmsghdr) };
        assert_eq!(hdr.nlmsg_type, libc::RTM_GETRULE);
        assert_eq!(hdr.nlmsg_seq, 123);

        let rtm = unsafe {
            std::ptr::read_unaligned(msg[size_of::<libc::nlmsghdr>()..].as_ptr() as *const RtMsg)
        };
        assert_eq!(rtm.rtm_family as i32, libc::AF_INET6);
    }

    #[test]
    fn parse_cleanup_rule_addr_matches_context() {
        let mut data = Vec::new();
        let mut rtm: RtMsg = unsafe { std::mem::zeroed() };
        rtm.rtm_family = libc::AF_INET6 as u8;
        rtm.rtm_dst_len = 128;
        append_zeros(&mut data, size_of::<RtMsg>());
        unsafe {
            std::ptr::write_unaligned(data.as_mut_ptr() as *mut RtMsg, rtm);
        }

        let target = Ipv6Addr::new(
            0x240e, 0x0440, 0x0006, 0x07de, 0x5b6b, 0x04d7, 0x4147, 0x8af8,
        );
        append_nla_u32(&mut data, FRA_ATTR_PRIORITY, 1900);
        append_nla_u32(&mut data, FRA_ATTR_TABLE, 254);
        append_nla(&mut data, FRA_ATTR_DST, &target.octets());

        let view = NetlinkMessageView {
            header: libc::nlmsghdr {
                nlmsg_len: data.len() as u32,
                nlmsg_type: libc::RTM_NEWRULE,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
            data: &data,
        };

        let ctx = RuleContext {
            pref: 1900,
            table_id: 254,
        };

        let parsed = parse_cleanup_rule_addr(view, ctx, libc::AF_INET6)
            .expect("parse")
            .expect("must match");
        assert_eq!(parsed, IpAddr::V6(target));
    }
}
