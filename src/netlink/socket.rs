use std::io;
use std::mem;
use std::os::fd::RawFd;

use crate::kernel::is_required_syscall_errno;
use crate::netlink::codec::ROUTE_SOCKET_RECV_BUF;
use crate::netlink::linux_types::{RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR};

const MMSG_SLOTS: usize = 8;

const SOL_NETLINK: i32 = 270;
const NETLINK_EXT_ACK: i32 = 11;

pub(crate) struct NetlinkSocket {
    fd: RawFd,
}

/// Batch receive ring for `recvmmsg`.
///
/// # Safety invariant
///
/// `_iovecs[i].iov_base` points into `slab`. After construction, `slab`
/// must never be resized, swapped, or otherwise reallocated; doing so would
/// invalidate the raw pointers stored in `_iovecs` (and transitively in `hdrs`).
pub(crate) struct MmsgRxRing {
    slab: Box<[u8]>,
    buf_size: usize,
    lengths: Vec<usize>,
    _iovecs: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
}

pub(crate) struct MmsgTxBatch {
    iovecs: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
    addr: libc::sockaddr_nl,
}

impl MmsgTxBatch {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let mut out = Self {
            iovecs: Vec::new(),
            hdrs: Vec::new(),
            addr: unsafe { mem::zeroed() },
        };
        out.addr.nl_family = libc::AF_NETLINK as u16;
        out.ensure_capacity(capacity.max(1));
        out
    }

    fn ensure_capacity(&mut self, capacity: usize) {
        if self.iovecs.len() < capacity {
            self.iovecs
                .resize_with(capacity, || unsafe { mem::zeroed::<libc::iovec>() });
        }
        if self.hdrs.len() < capacity {
            self.hdrs
                .resize_with(capacity, || unsafe { mem::zeroed::<libc::mmsghdr>() });
        }
    }

    fn prepare_raw(&mut self, ptrs: &[*const u8], lens: &[usize]) {
        self.ensure_capacity(ptrs.len());
        for (idx, ptr) in ptrs.iter().enumerate() {
            self.prepare_slot(idx, *ptr, lens[idx]);
        }
    }

    fn prepare_slot(&mut self, idx: usize, ptr: *const u8, len: usize) {
        self.iovecs[idx].iov_base = ptr as *mut libc::c_void;
        self.iovecs[idx].iov_len = len;

        let mut msg_hdr: libc::msghdr = unsafe { mem::zeroed() };
        msg_hdr.msg_name = (&mut self.addr as *mut libc::sockaddr_nl).cast::<libc::c_void>();
        msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        msg_hdr.msg_iov = (&mut self.iovecs[idx] as *mut libc::iovec).cast::<libc::iovec>();
        msg_hdr.msg_iovlen = 1;
        self.hdrs[idx].msg_hdr = msg_hdr;
        self.hdrs[idx].msg_len = 0;
    }
}

impl Default for MmsgRxRing {
    fn default() -> Self {
        Self::default_route_ring()
    }
}

impl MmsgRxRing {
    pub(crate) fn new(slots: usize, buf_size: usize) -> Self {
        let slots = slots.max(1);
        let buf_size = buf_size.max(1);
        let slab = vec![0u8; slots * buf_size].into_boxed_slice();
        let mut out = Self {
            slab,
            buf_size,
            lengths: vec![0; slots],
            _iovecs: Vec::with_capacity(slots),
            hdrs: Vec::with_capacity(slots),
        };
        out._iovecs
            .resize_with(slots, || unsafe { mem::zeroed::<libc::iovec>() });
        out.hdrs
            .resize_with(slots, || unsafe { mem::zeroed::<libc::mmsghdr>() });
        out.rebuild_headers();
        out
    }

    pub(crate) fn default_route_ring() -> Self {
        Self::new(MMSG_SLOTS, crate::netlink::codec::ROUTE_EVENT_BUFFER_SIZE)
    }

    pub(crate) fn packet(&self, idx: usize) -> &[u8] {
        let len = self.lengths[idx];
        let start = idx.saturating_mul(self.buf_size);
        &self.slab[start..start + len]
    }

    pub(crate) fn slots(&self) -> usize {
        self.hdrs.len()
    }

    pub(crate) fn ensure_slots(&mut self, slots: usize) {
        if slots <= self.hdrs.len() {
            return;
        }
        self.resize_slots(slots.max(1));
    }

    pub(crate) fn shrink_slots(&mut self, slots: usize) {
        if slots >= self.hdrs.len() {
            return;
        }
        self.resize_slots(slots.max(1));
    }

    fn clear_lengths(&mut self) {
        for len in &mut self.lengths {
            *len = 0;
        }
        for hdr in &mut self.hdrs {
            hdr.msg_len = 0;
        }
    }

    fn headers_ptr(&mut self) -> *mut libc::mmsghdr {
        self.hdrs.as_mut_ptr()
    }

    fn headers_len(&self) -> usize {
        self.hdrs.len()
    }

    fn update_lengths_from_headers(&mut self, count: usize) {
        for (idx, hdr) in self.hdrs.iter().take(count).enumerate() {
            let len = hdr.msg_len as usize;
            self.lengths[idx] = len.min(self.buf_size);
        }
    }

    fn resize_slots(&mut self, slots: usize) {
        let slots = slots.max(1);
        let mut next_slab = vec![0u8; slots * self.buf_size].into_boxed_slice();
        let copy_slots = self.hdrs.len().min(slots);
        let copy_bytes = copy_slots.saturating_mul(self.buf_size);
        if copy_bytes > 0 {
            next_slab[..copy_bytes].copy_from_slice(&self.slab[..copy_bytes]);
        }
        self.slab = next_slab;
        self.lengths.resize(slots, 0);
        self._iovecs
            .resize_with(slots, || unsafe { mem::zeroed::<libc::iovec>() });
        self.hdrs
            .resize_with(slots, || unsafe { mem::zeroed::<libc::mmsghdr>() });
        self.rebuild_headers();
    }

    fn rebuild_headers(&mut self) {
        for idx in 0..self.hdrs.len() {
            let start = idx.saturating_mul(self.buf_size);
            let ptr = unsafe { self.slab.as_mut_ptr().add(start) }.cast::<libc::c_void>();
            self._iovecs[idx].iov_base = ptr;
            self._iovecs[idx].iov_len = self.buf_size;
            let mut msg_hdr: libc::msghdr = unsafe { mem::zeroed() };
            msg_hdr.msg_iov = (&mut self._iovecs[idx] as *mut libc::iovec).cast::<libc::iovec>();
            msg_hdr.msg_iovlen = 1;
            self.hdrs[idx].msg_hdr = msg_hdr;
            self.hdrs[idx].msg_len = 0;
        }
    }
}

impl NetlinkSocket {
    pub(crate) fn open_route(ipv6_enabled: bool) -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(map_required_syscall_io(io::Error::last_os_error()));
        }

        let groups = route_addr_groups(ipv6_enabled);
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = groups;

        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = map_required_syscall_io(io::Error::last_os_error());
            unsafe { libc::close(fd) };
            return Err(err);
        }

        set_route_recv_opts(fd)?;
        Ok(Self { fd })
    }

    pub(crate) fn open_rule() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(map_required_syscall_io(io::Error::last_os_error()));
        }

        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;

        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = map_required_syscall_io(io::Error::last_os_error());
            unsafe { libc::close(fd) };
            return Err(err);
        }

        set_rule_recv_opts(fd)?;
        Ok(Self { fd })
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.fd
    }

    pub(crate) fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;

        let rc = unsafe {
            libc::sendto(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(map_required_syscall_io(io::Error::last_os_error()));
        }
        Ok(())
    }

    pub(crate) fn send_many_raw(
        &self,
        ptrs: &[*const u8],
        lens: &[usize],
        batch: &mut MmsgTxBatch,
    ) -> io::Result<()> {
        if ptrs.len() != lens.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ptr/lens size mismatch",
            ));
        }
        if ptrs.is_empty() {
            return Ok(());
        }

        let mut sent = 0usize;
        while sent < ptrs.len() {
            let ptr_chunk = &ptrs[sent..];
            let len_chunk = &lens[sent..];
            batch.prepare_raw(ptr_chunk, len_chunk);
            let rc = unsafe {
                libc::sendmmsg(
                    self.fd,
                    batch.hdrs.as_mut_ptr(),
                    ptr_chunk.len() as libc::c_uint,
                    0,
                )
            };
            if rc < 0 {
                return Err(map_required_syscall_io(io::Error::last_os_error()));
            }
            if rc == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "sendmmsg wrote 0"));
            }
            sent += rc as usize;
        }
        Ok(())
    }

    pub(crate) fn recv_many(&self, ring: &mut MmsgRxRing) -> io::Result<usize> {
        ring.clear_lengths();

        let rc = unsafe {
            libc::recvmmsg(
                self.fd,
                ring.headers_ptr(),
                ring.headers_len() as libc::c_uint,
                0,
                std::ptr::null_mut(),
            )
        };
        if rc < 0 {
            return Err(map_required_syscall_io(io::Error::last_os_error()));
        }

        let count = rc as usize;
        ring.update_lengths_from_headers(count);
        Ok(count)
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

fn set_route_recv_opts(fd: RawFd) -> io::Result<()> {
    set_common_recv_opts(fd)
}

fn set_rule_recv_opts(fd: RawFd) -> io::Result<()> {
    set_common_recv_opts(fd)?;
    set_sockopt_i32(fd, SOL_NETLINK, NETLINK_EXT_ACK, 1)?;
    Ok(())
}

fn set_common_recv_opts(fd: RawFd) -> io::Result<()> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socket fd",
        ));
    }
    set_sockopt_i32(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, ROUTE_SOCKET_RECV_BUF)?;
    set_fd_nonblocking(fd)?;
    Ok(())
}

fn set_fd_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(map_required_syscall_io(io::Error::last_os_error()));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(map_required_syscall_io(io::Error::last_os_error()));
    }
    Ok(())
}

fn set_sockopt_i32(fd: RawFd, level: i32, name: i32, value: i32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const i32).cast::<libc::c_void>(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(map_required_syscall_io(io::Error::last_os_error()));
    }
    Ok(())
}

fn map_required_syscall_io(err: io::Error) -> io::Error {
    if matches!(err.raw_os_error(), Some(code) if is_required_syscall_errno(code)) {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{}; required kernel >= {}",
                crate::kernel::KernelContract::UNSUPPORTED_SYSCALL_MSG,
                crate::kernel::KernelContract::MIN_VERSION
            ),
        );
    }
    err
}

pub(crate) fn route_addr_groups(ipv6_enabled: bool) -> u32 {
    let mut groups = 1u32 << (RTNLGRP_IPV4_IFADDR - 1);
    if ipv6_enabled {
        groups |= 1u32 << (RTNLGRP_IPV6_IFADDR - 1);
    }
    groups
}

pub(crate) fn is_transient_recv_err(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code) if code == libc::EINTR || code == libc::EAGAIN || code == libc::EWOULDBLOCK
    )
}

#[cfg(test)]
mod tests {
    use super::{MmsgRxRing, route_addr_groups};
    use crate::netlink::linux_types::{RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR};

    #[test]
    fn route_addr_groups_ipv4_ipv6() {
        let v4_only = route_addr_groups(false);
        let v4_mask = 1u32 << (RTNLGRP_IPV4_IFADDR - 1);
        let v6_mask = 1u32 << (RTNLGRP_IPV6_IFADDR - 1);
        assert_eq!(v4_only, v4_mask);

        let dual = route_addr_groups(true);
        assert_eq!(dual, v4_mask | v6_mask);
    }

    #[test]
    fn mmsg_ring_ensure_slots_grows() {
        let mut ring = MmsgRxRing::new(2, 4096);
        assert_eq!(ring.slots(), 2);
        ring.ensure_slots(8);
        assert_eq!(ring.slots(), 8);
    }

    #[test]
    fn mmsg_ring_shrink_slots_contract() {
        let mut ring = MmsgRxRing::new(8, 4096);
        ring.shrink_slots(2);
        assert_eq!(ring.slots(), 2);
        ring.shrink_slots(0);
        assert_eq!(ring.slots(), 1);
    }
}
