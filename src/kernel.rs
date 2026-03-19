use std::io;
use std::time::Instant;

use crate::error::AppError;

pub(crate) struct KernelContract;

impl KernelContract {
    pub(crate) const MIN_VERSION: &str = "5.10";
    pub(crate) const UNSUPPORTED_SYSCALL_MSG: &str =
        "unsupported kernel (<5.10 or missing required syscall)";
}

pub(crate) fn is_required_syscall_errno(code: i32) -> bool {
    code == libc::ENOSYS || code == libc::EOPNOTSUPP || code == libc::EPROTONOSUPPORT
}

pub(crate) fn wait_readable(fd: libc::c_int, deadline: Instant) -> Result<bool, AppError> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }

        let remain = deadline.saturating_duration_since(now);
        let timeout_ms = remain.as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
        if rc == 0 {
            return Ok(false);
        }
        if rc < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(code) if code == libc::EINTR) {
                continue;
            }
            return Err(AppError::Io(err));
        }
        return Ok(true);
    }
}
