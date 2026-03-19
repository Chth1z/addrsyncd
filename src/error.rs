use std::fmt;
use std::io;

use crate::kernel::{KernelContract, is_required_syscall_errno};

#[derive(Debug)]
pub(crate) enum AppError {
    Message(String),
    Io(io::Error),
    Config(String),
    Netlink(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(s) => f.write_str(s),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Config(s) => write!(f, "config: {s}"),
            Self::Netlink(s) => write!(f, "netlink: {s}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<io::Error> for AppError {
    fn from(value: io::Error) -> Self {
        if value.kind() == io::ErrorKind::Unsupported
            && value
                .to_string()
                .contains(KernelContract::UNSUPPORTED_SYSCALL_MSG)
        {
            return Self::message(value.to_string());
        }
        Self::Io(value)
    }
}

impl AppError {
    pub(crate) fn message(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }

    pub(crate) fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub(crate) fn netlink(msg: impl Into<String>) -> Self {
        Self::Netlink(msg.into())
    }

    pub(crate) fn from_required_syscall_io(err: io::Error) -> Self {
        if matches!(err.raw_os_error(), Some(code) if is_required_syscall_errno(code)) {
            return Self::message(format!(
                "{}; required kernel >= {}",
                KernelContract::UNSUPPORTED_SYSCALL_MSG,
                KernelContract::MIN_VERSION
            ));
        }
        Self::Io(err)
    }
}
