use std::mem::size_of;
use std::net::IpAddr;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::error::AppError;
use crate::ip_key::IpKey;
use crate::netlink::codec::{IFA_ATTR_FLAGS, build_netlink_request, next_seq, parse_nlas};
use crate::netlink::dump_engine::{DumpEngine, DumpStep};
use crate::netlink::linux_types::IfAddrMsg;
use crate::netlink::raw_addr::RawAddrBuf;
use crate::netlink::rule::{RuleAction, RuleOp, addr_from_netlink};
use crate::netlink::socket::NetlinkSocket;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AddrEvent {
    pub(crate) op: RuleOp,
    pub(crate) family: u8,
    pub(crate) ifindex: i32,
    pub(crate) flags: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct IgnoreFilters {
    ip_set: FxHashSet<IpAddr>,
    cidr_matcher: CidrMatcher,
    pub(crate) flag_mask: u32,
}

impl IgnoreFilters {
    pub(crate) fn new(
        ignore_ips: &[IpAddr],
        ignore_cidrs: &[(IpAddr, u8)],
        flag_mask: u32,
    ) -> Self {
        let mut ip_set = FxHashSet::default();
        for ip in ignore_ips {
            ip_set.insert(unmap_addr(*ip));
        }

        Self {
            ip_set,
            cidr_matcher: CidrMatcher::new(ignore_cidrs),
            flag_mask,
        }
    }

    pub(crate) fn should_ignore_addr(&self, addr: IpAddr) -> bool {
        let addr = unmap_addr(addr);
        if self.ip_set.contains(&addr) {
            return true;
        }
        self.cidr_matcher.contains(addr)
    }
}

#[derive(Debug, Clone)]
struct CidrMatcher {
    v4_buckets: Vec<(u8, FxHashSet<u32>)>,
    v6_buckets: Vec<(u8, FxHashSet<u128>)>,
}

impl CidrMatcher {
    fn new(cidrs: &[(IpAddr, u8)]) -> Self {
        if cidrs.is_empty() {
            return Self {
                v4_buckets: Vec::new(),
                v6_buckets: Vec::new(),
            };
        }

        let mut v4_map: FxHashMap<u8, FxHashSet<u32>> = FxHashMap::default();
        let mut v6_map: FxHashMap<u8, FxHashSet<u128>> = FxHashMap::default();

        for &(addr, prefix) in cidrs {
            match addr {
                IpAddr::V4(v4) => {
                    let masked = mask_v4(u32::from(v4), prefix);
                    v4_map.entry(prefix).or_default().insert(masked);
                }
                IpAddr::V6(v6) => {
                    let masked = mask_v6(u128::from_be_bytes(v6.octets()), prefix);
                    v6_map.entry(prefix).or_default().insert(masked);
                }
            }
        }

        let mut v4_buckets: Vec<(u8, FxHashSet<u32>)> = v4_map.into_iter().collect();
        let mut v6_buckets: Vec<(u8, FxHashSet<u128>)> = v6_map.into_iter().collect();
        v4_buckets.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
        v6_buckets.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));

        Self {
            v4_buckets,
            v6_buckets,
        }
    }

    fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                let value = u32::from(v4);
                for (prefix, bucket) in &self.v4_buckets {
                    let masked = mask_v4(value, *prefix);
                    if bucket.contains(&masked) {
                        return true;
                    }
                }
                false
            }
            IpAddr::V6(v6) => {
                let value = u128::from_be_bytes(v6.octets());
                for (prefix, bucket) in &self.v6_buckets {
                    let masked = mask_v6(value, *prefix);
                    if bucket.contains(&masked) {
                        return true;
                    }
                }
                false
            }
        }
    }
}

#[inline]
fn mask_v4(value: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        return 0;
    }
    let mask = u32::MAX << (32 - prefix);
    value & mask
}

#[inline]
fn mask_v6(value: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    let mask = u128::MAX << (128 - prefix);
    value & mask
}

#[derive(Default)]
pub(crate) struct AddrDumpScratch {
    engine: DumpEngine,
}

pub(crate) fn parse_addr_event(
    msg: crate::netlink::codec::NetlinkMessageView<'_>,
    ipv6_enabled: bool,
    filters: &IgnoreFilters,
) -> Result<Option<AddrEvent>, AppError> {
    if msg.data.len() < size_of::<IfAddrMsg>() {
        return Ok(None);
    }
    let ifa = unsafe { std::ptr::read_unaligned(msg.data.as_ptr() as *const IfAddrMsg) };
    let (flags, raw_addr) =
        parse_ifaddr_attrs(&msg.data[size_of::<IfAddrMsg>()..], ifa.ifa_family)?;
    let Some((addr, flags)) = parse_addr_from_ifaddr(ifa, flags, raw_addr, ipv6_enabled, filters)
    else {
        return Ok(None);
    };

    let action = if msg.header.nlmsg_type == libc::RTM_DELADDR {
        RuleAction::Delete
    } else {
        RuleAction::Add
    };

    let ifindex = i32::try_from(ifa.ifa_index).unwrap_or(i32::MAX);
    Ok(Some(AddrEvent {
        op: RuleOp { addr, action },
        family: ifa.ifa_family,
        ifindex,
        flags,
    }))
}

pub(crate) fn snapshot_interface_keys_sorted_with_socket_inplace(
    socket: &NetlinkSocket,
    ipv6_enabled: bool,
    filters: &IgnoreFilters,
    scratch: &mut AddrDumpScratch,
    out: &mut Vec<IpKey>,
) -> Result<(), AppError> {
    out.clear();
    dump_interface_keys_family(
        socket,
        libc::AF_INET as u8,
        ipv6_enabled,
        filters,
        scratch,
        out,
    )?;
    if ipv6_enabled {
        dump_interface_keys_family(
            socket,
            libc::AF_INET6 as u8,
            ipv6_enabled,
            filters,
            scratch,
            out,
        )?;
    }
    out.sort_unstable();
    out.dedup();
    Ok(())
}

fn parse_ifaddr_attrs(raw: &[u8], family: u8) -> Result<(u32, RawAddrBuf), AppError> {
    let mut flags = u32::MAX;
    let mut addr: Option<RawAddrBuf> = None;

    parse_nlas(raw, |typ, value| {
        match typ {
            IFA_ATTR_FLAGS if value.len() >= 4 => {
                flags = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
            }
            x if x == libc::IFA_LOCAL => {
                if family as i32 == libc::AF_INET {
                    addr = Some(RawAddrBuf::from_slice(
                        value,
                        "ifaddr invalid IFA_ADDRESS length",
                    )?);
                }
            }
            x if x == libc::IFA_ADDRESS => {
                if family as i32 != libc::AF_INET || addr.is_none() {
                    addr = Some(RawAddrBuf::from_slice(
                        value,
                        "ifaddr invalid IFA_ADDRESS length",
                    )?);
                }
            }
            _ => {}
        }
        Ok(())
    })?;

    let Some(addr) = addr else {
        return Err(AppError::netlink("ifaddr missing IFA_ADDRESS"));
    };
    Ok((flags, addr))
}

fn parse_addr_from_ifaddr(
    ifa: IfAddrMsg,
    mut flags: u32,
    raw_addr: RawAddrBuf,
    ipv6_enabled: bool,
    filters: &IgnoreFilters,
) -> Option<(IpAddr, u32)> {
    if ifa.ifa_scope != 0 {
        return None;
    }
    if ifa.ifa_family as i32 == libc::AF_INET6 && !ipv6_enabled {
        return None;
    }
    if flags == u32::MAX {
        flags = ifa.ifa_flags as u32;
    }

    if filters.flag_mask != 0 && (flags & filters.flag_mask) != 0 {
        return None;
    }

    let mut addr = addr_from_netlink(ifa.ifa_family, raw_addr.as_slice())?;
    addr = unmap_addr(addr);
    if !is_valid_addr(addr) {
        return None;
    }
    if filters.should_ignore_addr(addr) {
        return None;
    }
    Some((addr, flags))
}

fn dump_interface_keys_family(
    socket: &NetlinkSocket,
    family: u8,
    ipv6_enabled: bool,
    filters: &IgnoreFilters,
    scratch: &mut AddrDumpScratch,
    out: &mut Vec<IpKey>,
) -> Result<(), AppError> {
    let seq = next_seq();
    let msg = build_addr_dump_message(family, seq);
    socket.send(&msg)?;

    scratch.engine.recv_until_done(socket, seq, |msg| {
        if msg.header.nlmsg_type as i32 != libc::RTM_NEWADDR as i32 {
            return Ok(DumpStep::Continue);
        }
        if msg.data.len() < size_of::<IfAddrMsg>() {
            return Ok(DumpStep::Continue);
        }

        let ifa = unsafe { std::ptr::read_unaligned(msg.data.as_ptr() as *const IfAddrMsg) };
        let parsed = parse_ifaddr_attrs(&msg.data[size_of::<IfAddrMsg>()..], ifa.ifa_family);
        let Ok((flags, raw_addr)) = parsed else {
            return Ok(DumpStep::Continue);
        };
        if let Some(addr) = parse_addr_from_ifaddr(ifa, flags, raw_addr, ipv6_enabled, filters)
            .map(|(addr, _)| addr)
        {
            out.push(IpKey::from_ip(addr));
        }

        Ok(DumpStep::Continue)
    })
}

fn build_addr_dump_message(family: u8, seq: u32) -> Vec<u8> {
    let mut ifa: IfAddrMsg = unsafe { std::mem::zeroed() };
    ifa.ifa_family = family;
    build_netlink_request(
        libc::RTM_GETADDR,
        (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
        seq,
        &ifa,
    )
}

fn is_valid_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local(),
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_loopback() {
                return false;
            }
            !v6.is_unicast_link_local()
        }
    }
}

fn unmap_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        _ => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::Ipv6Addr;

    use crate::netlink::codec::{IFA_F_TEMPORARY, NetlinkMessageView, append_nla, append_zeros};

    #[test]
    fn ignore_filters_works_with_flag_mask() {
        let filters = IgnoreFilters::new(&[], &[], IFA_F_TEMPORARY);
        assert_eq!(filters.flag_mask, IFA_F_TEMPORARY);
    }

    #[test]
    fn parse_addr_event_respects_flag_and_ip_filters() {
        let addr = Ipv6Addr::new(
            0x240e, 0x0440, 0x0006, 0x07de, 0x4754, 0x00fa, 0x0eea, 0xbc5e,
        );
        let msg = build_ipv6_addr_event(addr, libc::RTM_NEWADDR, 0x01);

        let filters_by_flag = IgnoreFilters::new(&[], &[], IFA_F_TEMPORARY);
        let parsed = parse_addr_event(msg, true, &filters_by_flag).expect("parse");
        assert!(parsed.is_none());

        let filters_by_ip = IgnoreFilters::new(&[IpAddr::V6(addr)], &[], 0);
        let parsed = parse_addr_event(msg, true, &filters_by_ip).expect("parse");
        assert!(parsed.is_none());

        let no_filter = IgnoreFilters::new(&[], &[], 0);
        let parsed = parse_addr_event(msg, true, &no_filter)
            .expect("parse")
            .expect("must pass");
        assert_eq!(parsed.op.addr, IpAddr::V6(addr));
        assert!(matches!(parsed.op.action, RuleAction::Add));
    }

    #[test]
    fn cidr_matcher_matches_prefixes() {
        let matcher = CidrMatcher::new(&[
            ("10.0.0.0".parse::<IpAddr>().expect("ip"), 8),
            ("2001:db8::".parse::<IpAddr>().expect("ip"), 32),
        ]);
        assert!(matcher.contains("10.1.2.3".parse().expect("ip")));
        assert!(!matcher.contains("11.1.2.3".parse().expect("ip")));
        assert!(matcher.contains("2001:db8::1".parse().expect("ip")));
        assert!(!matcher.contains("2001:db9::1".parse().expect("ip")));
    }

    proptest! {
        #[test]
        fn parse_addr_event_no_panic_on_random_payload(
            payload in proptest::collection::vec(any::<u8>(), 0..256),
            is_del in any::<bool>()
        ) {
            let msg_type = if is_del { libc::RTM_DELADDR } else { libc::RTM_NEWADDR };
            let leaked = Box::leak(payload.into_boxed_slice());
            let view = NetlinkMessageView {
                header: libc::nlmsghdr {
                    nlmsg_len: leaked.len() as u32,
                    nlmsg_type: msg_type,
                    nlmsg_flags: 0,
                    nlmsg_seq: 1,
                    nlmsg_pid: 0,
                },
                data: leaked,
            };
            let filters = IgnoreFilters::new(&[], &[], 0);
            let _ = parse_addr_event(view, true, &filters);
        }
    }

    fn build_ipv6_addr_event(
        addr: Ipv6Addr,
        msg_type: u16,
        flags: u32,
    ) -> NetlinkMessageView<'static> {
        let mut data = Vec::new();
        let mut ifa: IfAddrMsg = unsafe { std::mem::zeroed() };
        ifa.ifa_family = libc::AF_INET6 as u8;
        ifa.ifa_scope = 0;
        append_zeros(&mut data, size_of::<IfAddrMsg>());
        unsafe {
            std::ptr::write_unaligned(data.as_mut_ptr() as *mut IfAddrMsg, ifa);
        }

        append_nla(&mut data, libc::IFA_ADDRESS, &addr.octets());
        append_nla(&mut data, IFA_ATTR_FLAGS, &flags.to_ne_bytes());

        let leaked = Box::leak(data.into_boxed_slice());
        NetlinkMessageView {
            header: libc::nlmsghdr {
                nlmsg_len: leaked.len() as u32,
                nlmsg_type: msg_type,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
            data: leaked,
        }
    }
}
