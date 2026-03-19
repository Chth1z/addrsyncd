use crate::error::AppError;
use crate::netlink::codec::{NetlinkMessageIter, NetlinkMessageView, parse_ack_errno};
use crate::netlink::socket::{MmsgRxRing, NetlinkSocket, is_transient_recv_err};

const DUMP_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DumpStep {
    Continue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DumpPoll {
    Pending,
    Continue,
    Done,
}

#[derive(Default)]
pub(crate) struct DumpEngine {
    ring: MmsgRxRing,
}

impl DumpEngine {
    pub(crate) fn recv_step<F>(
        &mut self,
        socket: &NetlinkSocket,
        seq: u32,
        mut on_msg: F,
    ) -> Result<DumpPoll, AppError>
    where
        F: FnMut(NetlinkMessageView<'_>) -> Result<DumpStep, AppError>,
    {
        let count = match socket.recv_many(&mut self.ring) {
            Ok(n) => n,
            Err(err) if is_transient_recv_err(&err) => return Ok(DumpPoll::Pending),
            Err(err) => return Err(err.into()),
        };
        if count == 0 {
            return Ok(DumpPoll::Pending);
        }

        let mut done = false;
        for idx in 0..count {
            let raw = self.ring.packet(idx);
            for msg in NetlinkMessageIter::new(raw) {
                let msg = msg?;
                if msg.header.nlmsg_seq != seq {
                    continue;
                }
                match msg.header.nlmsg_type as i32 {
                    libc::NLMSG_DONE => {
                        done = true;
                    }
                    libc::NLMSG_ERROR => {
                        if let Some(errno) = parse_ack_errno(msg.data)? {
                            return Err(AppError::netlink(format!("dump ack errno={errno}")));
                        }
                    }
                    _ => {
                        let _ = on_msg(msg)?;
                    }
                }
            }
        }

        if done {
            Ok(DumpPoll::Done)
        } else {
            Ok(DumpPoll::Continue)
        }
    }

    pub(crate) fn recv_until_done<F>(
        &mut self,
        socket: &NetlinkSocket,
        seq: u32,
        mut on_msg: F,
    ) -> Result<(), AppError>
    where
        F: FnMut(NetlinkMessageView<'_>) -> Result<DumpStep, AppError>,
    {
        let deadline = std::time::Instant::now() + DUMP_WAIT_TIMEOUT;
        loop {
            match self.recv_step(socket, seq, &mut on_msg)? {
                DumpPoll::Pending => {
                    if !crate::kernel::wait_readable(socket.fd(), deadline)? {
                        return Err(AppError::netlink("dump wait timeout"));
                    }
                    continue;
                }
                DumpPoll::Continue => continue,
                DumpPoll::Done => {
                    return Ok(());
                }
            }
        }
    }
}
