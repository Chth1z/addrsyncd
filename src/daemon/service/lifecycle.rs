use std::io;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::time::Instant;

use crate::error::AppError;

use super::{EPOLL_TAG_ROUTE, EPOLL_TAG_RULE, EPOLL_TAG_SIGNAL, EPOLL_TAG_TIMER};

pub(super) fn setup_signalfd() -> Result<RawFd, AppError> {
    let mut mask = MaybeUninit::<libc::sigset_t>::zeroed();
    let mask_ptr = mask.as_mut_ptr();
    let rc_empty = unsafe { libc::sigemptyset(mask_ptr) };
    if rc_empty < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }
    let rc_term = unsafe { libc::sigaddset(mask_ptr, libc::SIGTERM) };
    if rc_term < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }
    let rc_int = unsafe { libc::sigaddset(mask_ptr, libc::SIGINT) };
    if rc_int < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }
    let rc_usr1 = unsafe { libc::sigaddset(mask_ptr, libc::SIGUSR1) };
    if rc_usr1 < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }
    let rc_block = unsafe { libc::sigprocmask(libc::SIG_BLOCK, mask_ptr, std::ptr::null_mut()) };
    if rc_block < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }

    let fd = unsafe {
        libc::signalfd(
            -1,
            mask_ptr.cast_const(),
            libc::SFD_NONBLOCK | libc::SFD_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }
    Ok(fd)
}

pub(super) fn setup_timerfd() -> Result<RawFd, AppError> {
    let fd = unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }
    Ok(fd)
}

pub(super) fn setup_epoll(
    route_fd: RawFd,
    rule_fd: RawFd,
    signal_fd: RawFd,
    timer_fd: RawFd,
) -> Result<RawFd, AppError> {
    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }

    if let Err(err) = epoll_add(epoll_fd, route_fd, EPOLL_TAG_ROUTE) {
        unsafe { libc::close(epoll_fd) };
        return Err(err);
    }
    if let Err(err) = epoll_add(epoll_fd, rule_fd, EPOLL_TAG_RULE) {
        unsafe { libc::close(epoll_fd) };
        return Err(err);
    }
    if let Err(err) = epoll_add(epoll_fd, signal_fd, EPOLL_TAG_SIGNAL) {
        unsafe { libc::close(epoll_fd) };
        return Err(err);
    }
    if let Err(err) = epoll_add(epoll_fd, timer_fd, EPOLL_TAG_TIMER) {
        unsafe { libc::close(epoll_fd) };
        return Err(err);
    }

    Ok(epoll_fd)
}

fn epoll_add(epoll_fd: RawFd, fd: RawFd, tag: u64) -> Result<(), AppError> {
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: tag,
    };
    let rc = unsafe {
        libc::epoll_ctl(
            epoll_fd,
            libc::EPOLL_CTL_ADD,
            fd,
            &mut event as *mut libc::epoll_event,
        )
    };
    if rc < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

pub(super) fn arm_timer(timer_fd: RawFd, deadline: Option<Instant>) -> Result<(), AppError> {
    let mut spec: libc::itimerspec = unsafe { std::mem::zeroed() };
    if let Some(deadline) = deadline {
        let now = Instant::now();
        let remain = deadline.saturating_duration_since(now);
        let nanos = remain.as_nanos().max(1);
        spec.it_value.tv_sec = (nanos / 1_000_000_000) as libc::time_t;
        spec.it_value.tv_nsec = (nanos % 1_000_000_000) as libc::c_long;
    }

    let rc = unsafe {
        libc::timerfd_settime(
            timer_fd,
            0,
            &spec as *const libc::itimerspec,
            std::ptr::null_mut(),
        )
    };
    if rc < 0 {
        return Err(AppError::from_required_syscall_io(
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

pub(super) fn flush_timerfd(timer_fd: RawFd) -> Result<(), AppError> {
    let mut value = 0u64;
    loop {
        let rc = unsafe {
            libc::read(
                timer_fd,
                (&mut value as *mut u64).cast::<libc::c_void>(),
                std::mem::size_of::<u64>(),
            )
        };
        if rc == std::mem::size_of::<u64>() as isize {
            continue;
        }
        if rc < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK)
            {
                return Ok(());
            }
            if matches!(err.raw_os_error(), Some(code) if code == libc::EINTR) {
                continue;
            }
            return Err(AppError::Io(err));
        }
        return Ok(());
    }
}

pub(super) fn wait_readable(fd: RawFd, deadline: Instant) -> Result<bool, AppError> {
    crate::kernel::wait_readable(fd, deadline)
}
