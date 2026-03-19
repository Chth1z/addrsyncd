#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RtMsg {
    pub(crate) rtm_family: u8,
    pub(crate) rtm_dst_len: u8,
    pub(crate) rtm_src_len: u8,
    pub(crate) rtm_tos: u8,
    pub(crate) rtm_table: u8,
    pub(crate) rtm_protocol: u8,
    pub(crate) rtm_scope: u8,
    pub(crate) rtm_type: u8,
    pub(crate) rtm_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IfAddrMsg {
    pub(crate) ifa_family: u8,
    pub(crate) ifa_prefixlen: u8,
    pub(crate) ifa_flags: u8,
    pub(crate) ifa_scope: u8,
    pub(crate) ifa_index: u32,
}

pub(crate) const RTNLGRP_IPV4_IFADDR: u32 = 5;
pub(crate) const RTNLGRP_IPV6_IFADDR: u32 = 9;
