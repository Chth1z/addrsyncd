use std::ffi::CString;
use std::time::{Duration, Instant};

use crate::cli::{PbrAction, PbrRequest};
use crate::error::AppError;
use crate::netlink::codec::{
    FRA_ATTR_PRIORITY, FRA_ATTR_TABLE, NetlinkMessageIter, append_nla_u32, append_zeros,
    next_seq, parse_ack_error_info,
};
use crate::netlink::linux_types::RtMsg;
use crate::netlink::socket::{MmsgRxRing, NetlinkSocket, is_transient_recv_err};

pub(crate) const FRA_ATTR_FWMARK: u16 = 10;
pub(crate) const FRA_ATTR_FWMASK: u16 = 16;
pub(crate) const RTA_ATTR_OIF: u16 = 4;
pub(crate) const PBR_ACK_TIMEOUT: Duration = Duration::from_secs(5);
const DELETE_RULE_LIMIT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PbrAckClass {
    Ok,
    Noop,
    KernelErr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PbrOp {
    AddRule,
    DeleteRule,
    ReplaceRoute,
    DeleteRoute,
}

pub(crate) fn run_request(request: PbrRequest) -> Result<(), AppError> {
    let socket = NetlinkSocket::open_rule().map_err(AppError::from_required_syscall_io)?;
    let lo_ifindex = loopback_ifindex()?;
    let mut ring = MmsgRxRing::default();

    match request.action {
        PbrAction::Apply => {
            cleanup_request(&socket, &mut ring, request, lo_ifindex)?;
            send_pbr_message(
                &socket,
                &mut ring,
                PbrOp::ReplaceRoute,
                build_pbr_route_message(
                    libc::RTM_NEWROUTE,
                    request.family.as_i32(),
                    request.table,
                    lo_ifindex,
                    next_seq(),
                ),
            )?;
            send_pbr_message(
                &socket,
                &mut ring,
                PbrOp::AddRule,
                build_pbr_rule_message(
                    libc::RTM_NEWRULE,
                    request.family.as_i32(),
                    request.mark,
                    request.mask,
                    request.table,
                    request.pref,
                    next_seq(),
                ),
            )?;
            println!(
                "pbr applied family={} mark=0x{:x}/0x{:x} table={} pref={}",
                family_name(request.family.as_i32()),
                request.mark,
                request.mask,
                request.table,
                request.pref
            );
        }
        PbrAction::Cleanup => {
            cleanup_request(&socket, &mut ring, request, lo_ifindex)?;
            println!(
                "pbr cleaned family={} mark=0x{:x}/0x{:x} table={} pref={}",
                family_name(request.family.as_i32()),
                request.mark,
                request.mask,
                request.table,
                request.pref
            );
        }
        PbrAction::Status => {
            println!(
                "pbr target family={} mark=0x{:x}/0x{:x} table={} pref={}",
                family_name(request.family.as_i32()),
                request.mark,
                request.mask,
                request.table,
                request.pref
            );
        }
    }
    Ok(())
}

fn cleanup_request(
    socket: &NetlinkSocket,
    ring: &mut MmsgRxRing,
    request: PbrRequest,
    lo_ifindex: u32,
) -> Result<(), AppError> {
    for _ in 0..DELETE_RULE_LIMIT {
        let seq = next_seq();
        let class = send_pbr_message_classified(
            socket,
            ring,
            PbrOp::DeleteRule,
            build_pbr_rule_message(
                libc::RTM_DELRULE,
                request.family.as_i32(),
                request.mark,
                request.mask,
                request.table,
                request.pref,
                seq,
            ),
        )?;
        if class == PbrAckClass::Noop {
            break;
        }
    }

    send_pbr_message(
        socket,
        ring,
        PbrOp::DeleteRoute,
        build_pbr_route_message(
            libc::RTM_DELROUTE,
            request.family.as_i32(),
            request.table,
            lo_ifindex,
            next_seq(),
        ),
    )
}

pub(crate) fn build_pbr_rule_message(
    nlmsg_type: u16,
    family: i32,
    mark: u32,
    mask: u32,
    table: u32,
    pref: u32,
    seq: u32,
) -> Vec<u8> {
    let mut flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16;
    if nlmsg_type == libc::RTM_NEWRULE {
        flags |= libc::NLM_F_CREATE as u16 | libc::NLM_F_EXCL as u16;
    }

    let mut rtm: RtMsg = unsafe { std::mem::zeroed() };
    rtm.rtm_family = family as u8;
    rtm.rtm_protocol = libc::RTPROT_BOOT;
    rtm.rtm_scope = libc::RT_SCOPE_UNIVERSE;
    rtm.rtm_type = libc::RTN_UNICAST;
    if table <= u8::MAX as u32 {
        rtm.rtm_table = table as u8;
    }

    let mut msg = start_rt_message(nlmsg_type, flags, seq, rtm);
    append_nla_u32(&mut msg, FRA_ATTR_FWMARK, mark);
    append_nla_u32(&mut msg, FRA_ATTR_FWMASK, mask);
    append_nla_u32(&mut msg, FRA_ATTR_PRIORITY, pref);
    append_nla_u32(&mut msg, FRA_ATTR_TABLE, table);
    finish_rt_message(&mut msg);
    msg
}

pub(crate) fn build_pbr_route_message(
    nlmsg_type: u16,
    family: i32,
    table: u32,
    oif: u32,
    seq: u32,
) -> Vec<u8> {
    let mut flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16;
    if nlmsg_type == libc::RTM_NEWROUTE {
        flags |= libc::NLM_F_CREATE as u16 | libc::NLM_F_REPLACE as u16;
    }

    let mut rtm: RtMsg = unsafe { std::mem::zeroed() };
    rtm.rtm_family = family as u8;
    rtm.rtm_dst_len = 0;
    rtm.rtm_protocol = libc::RTPROT_BOOT;
    rtm.rtm_scope = libc::RT_SCOPE_HOST;
    rtm.rtm_type = libc::RTN_LOCAL;
    if table <= u8::MAX as u32 {
        rtm.rtm_table = table as u8;
    }

    let mut msg = start_rt_message(nlmsg_type, flags, seq, rtm);
    append_nla_u32(&mut msg, RTA_ATTR_OIF, oif);
    append_nla_u32(&mut msg, FRA_ATTR_TABLE, table);
    finish_rt_message(&mut msg);
    msg
}

fn start_rt_message(nlmsg_type: u16, flags: u16, seq: u32, rtm: RtMsg) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128);
    append_zeros(
        &mut msg,
        std::mem::size_of::<libc::nlmsghdr>() + std::mem::size_of::<RtMsg>(),
    );
    unsafe {
        std::ptr::write_unaligned(
            msg.as_mut_ptr() as *mut libc::nlmsghdr,
            libc::nlmsghdr {
                nlmsg_len: msg.len() as u32,
                nlmsg_type,
                nlmsg_flags: flags,
                nlmsg_seq: seq,
                nlmsg_pid: 0,
            },
        );
        std::ptr::write_unaligned(
            msg[std::mem::size_of::<libc::nlmsghdr>()..].as_mut_ptr() as *mut RtMsg,
            rtm,
        );
    }
    msg
}

fn finish_rt_message(msg: &mut Vec<u8>) {
    let len = msg.len();
    unsafe {
        let hdr = &mut *(msg.as_mut_ptr() as *mut libc::nlmsghdr);
        hdr.nlmsg_len = len as u32;
    }
    let aligned = crate::netlink::codec::nlmsg_align(len);
    if aligned > len {
        append_zeros(msg, aligned - len);
    }
}

fn send_pbr_message(
    socket: &NetlinkSocket,
    ring: &mut MmsgRxRing,
    op: PbrOp,
    msg: Vec<u8>,
) -> Result<(), AppError> {
    match send_pbr_message_classified(socket, ring, op, msg)? {
        PbrAckClass::Ok | PbrAckClass::Noop => Ok(()),
        PbrAckClass::KernelErr => Err(AppError::netlink("pbr operation failed")),
    }
}

fn send_pbr_message_classified(
    socket: &NetlinkSocket,
    ring: &mut MmsgRxRing,
    op: PbrOp,
    msg: Vec<u8>,
) -> Result<PbrAckClass, AppError> {
    let hdr = unsafe { std::ptr::read_unaligned(msg.as_ptr() as *const libc::nlmsghdr) };
    socket.send(&msg)?;
    wait_pbr_ack(socket, ring, hdr.nlmsg_seq, op)
}

fn wait_pbr_ack(
    socket: &NetlinkSocket,
    ring: &mut MmsgRxRing,
    seq: u32,
    op: PbrOp,
) -> Result<PbrAckClass, AppError> {
    let deadline = Instant::now() + PBR_ACK_TIMEOUT;
    loop {
        let count = match socket.recv_many(ring) {
            Ok(n) => n,
            Err(err) if is_transient_recv_err(&err) => {
                if !crate::kernel::wait_readable(socket.fd(), deadline)? {
                    return Err(AppError::netlink("pbr ack timeout"));
                }
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        if count == 0 {
            if !crate::kernel::wait_readable(socket.fd(), deadline)? {
                return Err(AppError::netlink("pbr ack timeout"));
            }
            continue;
        }

        for idx in 0..count {
            let raw = ring.packet(idx);
            for item in NetlinkMessageIter::new(raw) {
                let msg = item?;
                if msg.header.nlmsg_seq != seq {
                    continue;
                }
                if msg.header.nlmsg_type != libc::NLMSG_ERROR as u16 {
                    continue;
                }
                let status = parse_ack_error_info(msg.data)?;
                return Ok(classify_pbr_ack(op, status.as_ref()));
            }
        }
    }
}

fn classify_pbr_ack(
    op: PbrOp,
    status: Option<&crate::netlink::codec::AckErrorInfo>,
) -> PbrAckClass {
    let Some(status) = status else {
        return PbrAckClass::Ok;
    };
    match op {
        PbrOp::AddRule if status.errno == libc::EEXIST => PbrAckClass::Noop,
        PbrOp::ReplaceRoute if status.errno == libc::EEXIST => PbrAckClass::Noop,
        PbrOp::DeleteRule | PbrOp::DeleteRoute
            if status.errno == libc::ENOENT || status.errno == libc::ESRCH =>
        {
            PbrAckClass::Noop
        }
        _ => PbrAckClass::KernelErr,
    }
}

fn loopback_ifindex() -> Result<u32, AppError> {
    let lo = CString::new("lo").map_err(|_| AppError::message("invalid loopback name"))?;
    let idx = unsafe { libc::if_nametoindex(lo.as_ptr()) };
    if idx == 0 {
        return Err(AppError::message("loopback interface not found"));
    }
    Ok(idx)
}

fn family_name(family: i32) -> &'static str {
    match family {
        libc::AF_INET => "ipv4",
        libc::AF_INET6 => "ipv6",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use crate::netlink::codec::parse_nlas;
    use crate::netlink::linux_types::RtMsg;

    #[test]
    fn build_pbr_rule_message_contains_mark_mask_table_and_pref() {
        let msg = super::build_pbr_rule_message(
            libc::RTM_NEWRULE,
            libc::AF_INET,
            0x14,
            0xff,
            2025,
            2025,
            77,
        );

        let hdr = unsafe { std::ptr::read_unaligned(msg.as_ptr() as *const libc::nlmsghdr) };
        assert_eq!(hdr.nlmsg_type, libc::RTM_NEWRULE);
        assert_eq!(hdr.nlmsg_seq, 77);

        let body_start = size_of::<libc::nlmsghdr>();
        let rtm = unsafe {
            std::ptr::read_unaligned(msg[body_start..].as_ptr() as *const RtMsg)
        };
        assert_eq!(rtm.rtm_family as i32, libc::AF_INET);

        let mut mark = None;
        let mut mask = None;
        let mut table = None;
        let mut pref = None;
        parse_nlas(&msg[body_start + size_of::<RtMsg>()..hdr.nlmsg_len as usize], |typ, value| {
            let value = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
            match typ {
                super::FRA_ATTR_FWMARK => mark = Some(value),
                super::FRA_ATTR_FWMASK => mask = Some(value),
                crate::netlink::codec::FRA_ATTR_TABLE => table = Some(value),
                crate::netlink::codec::FRA_ATTR_PRIORITY => pref = Some(value),
                _ => {}
            }
            Ok(())
        })
        .expect("parse nlas");

        assert_eq!(mark, Some(0x14));
        assert_eq!(mask, Some(0xff));
        assert_eq!(table, Some(2025));
        assert_eq!(pref, Some(2025));
    }

    #[test]
    fn build_pbr_route_message_targets_local_default_route() {
        let msg = super::build_pbr_route_message(
            libc::RTM_NEWROUTE,
            libc::AF_INET6,
            2025,
            1,
            88,
        );

        let hdr = unsafe { std::ptr::read_unaligned(msg.as_ptr() as *const libc::nlmsghdr) };
        assert_eq!(hdr.nlmsg_type, libc::RTM_NEWROUTE);
        assert_eq!(hdr.nlmsg_seq, 88);

        let body_start = size_of::<libc::nlmsghdr>();
        let rtm = unsafe {
            std::ptr::read_unaligned(msg[body_start..].as_ptr() as *const RtMsg)
        };
        assert_eq!(rtm.rtm_family as i32, libc::AF_INET6);
        assert_eq!(rtm.rtm_dst_len, 0);
        assert_eq!(rtm.rtm_table, 0);
        assert_eq!(rtm.rtm_type, libc::RTN_LOCAL);
        assert_eq!(rtm.rtm_scope, libc::RT_SCOPE_HOST);

        let mut table = None;
        let mut oif = None;
        parse_nlas(&msg[body_start + size_of::<RtMsg>()..hdr.nlmsg_len as usize], |typ, value| {
            let value = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
            match typ {
                crate::netlink::codec::FRA_ATTR_TABLE => table = Some(value),
                super::RTA_ATTR_OIF => oif = Some(value),
                _ => {}
            }
            Ok(())
        })
        .expect("parse nlas");

        assert_eq!(table, Some(2025));
        assert_eq!(oif, Some(1));
    }
}
