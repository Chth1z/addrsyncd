use std::io;
use std::time::Instant;

use crate::error::AppError;
use crate::ip_key::IpKey;
use crate::logger::{FieldValue as V, NetlinkAddrEvent};
use crate::netlink::addr::AddrDumpScratch;
use crate::netlink::cleanup::CleanupDumpScratch;
use crate::netlink::codec::NetlinkMessageIter;
use crate::netlink::rule::ApplyScratch;
use crate::netlink::socket::{MmsgRxRing, NetlinkSocket, is_transient_recv_err};

use super::{
    EPOLL_TAG_ROUTE, EPOLL_TAG_RULE, EPOLL_TAG_SIGNAL, EPOLL_TAG_TIMER, EventLoopState,
    MaintenanceJob, ROUTE_RING_MAX_SLOTS, ROUTE_RING_MIN_SLOTS, lifecycle,
};

impl super::Daemon {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn event_loop(
        &mut self,
        route_socket: &NetlinkSocket,
        rule_socket: &NetlinkSocket,
        epoll_fd: libc::c_int,
        timer_fd: libc::c_int,
        signal_fd: libc::c_int,
        route_ring: &mut MmsgRxRing,
        apply_scratch: &mut ApplyScratch,
        addr_scratch: &mut AddrDumpScratch,
        cleanup_scratch: &mut CleanupDumpScratch,
        state: &mut EventLoopState,
        batch_pool: &mut Vec<Vec<crate::netlink::rule::RuleOp>>,
    ) -> Result<(), AppError> {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 32];
        lifecycle::arm_timer(timer_fd, self.next_deadline(state))?;

        loop {
            let n = unsafe {
                libc::epoll_wait(
                    epoll_fd,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    -1, // timerfd provides all deadlines.
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(code) if code == libc::EINTR) {
                    continue;
                }
                return Err(AppError::Io(err));
            }

            for event in events.iter().take(n as usize) {
                match event.u64 {
                    EPOLL_TAG_ROUTE => self.handle_route_events(route_socket, route_ring, state)?,
                    EPOLL_TAG_RULE => {
                        self.drain_rule_acks_once(rule_socket, apply_scratch, state, batch_pool)?
                    }
                    EPOLL_TAG_SIGNAL => self.handle_signals(signal_fd, state)?,
                    EPOLL_TAG_TIMER => lifecycle::flush_timerfd(timer_fd)?,
                    _ => {}
                }
            }

            self.drive_reactor(
                route_socket,
                rule_socket,
                apply_scratch,
                addr_scratch,
                cleanup_scratch,
                state,
                batch_pool,
            )?;

            if state.shutdown_requested
                && state.pending.is_empty()
                && state.inflight.is_none()
                && matches!(state.maintenance, MaintenanceJob::Idle)
                && state.shutdown_cleanup_done
            {
                break;
            }

            lifecycle::arm_timer(timer_fd, self.next_deadline(state))?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn drive_reactor(
        &mut self,
        route_socket: &NetlinkSocket,
        rule_socket: &NetlinkSocket,
        apply_scratch: &mut ApplyScratch,
        addr_scratch: &mut AddrDumpScratch,
        cleanup_scratch: &mut CleanupDumpScratch,
        state: &mut EventLoopState,
        batch_pool: &mut Vec<Vec<crate::netlink::rule::RuleOp>>,
    ) -> Result<(), AppError> {
        let now = Instant::now();

        if let Some(inflight) = &state.inflight
            && now >= inflight.ack_deadline
        {
            self.handle_ack_timeout(state, batch_pool);
        }

        if state.inflight.is_none()
            && self.should_flush_pending(state, now, state.shutdown_requested)
        {
            let _ = self.start_pending_batch(rule_socket, apply_scratch, state, batch_pool)?;
        }

        if state.inflight.is_none() {
            self.drive_maintenance_slice(
                route_socket,
                rule_socket,
                apply_scratch,
                addr_scratch,
                cleanup_scratch,
                state,
                batch_pool,
            )?;
        }

        Ok(())
    }

    fn handle_route_events(
        &mut self,
        route_socket: &NetlinkSocket,
        route_ring: &mut MmsgRxRing,
        state: &mut EventLoopState,
    ) -> Result<(), AppError> {
        let mut packets_left = state.route_budget.current;
        let mut processed_packets = 0usize;
        let mut budget_hit = false;
        let mut saw_ring_full = false;
        let mut parse_failed = 0u64;
        let mut touched_pending = false;

        while packets_left > 0 {
            let count = match route_socket.recv_many(route_ring) {
                Ok(value) => value,
                Err(err) if is_transient_recv_err(&err) => break,
                Err(err) => return Err(err.into()),
            };
            if count == 0 {
                break;
            }
            if count == route_ring.slots() {
                saw_ring_full = true;
                if route_ring.slots() < ROUTE_RING_MAX_SLOTS {
                    let next_slots =
                        (route_ring.slots().saturating_mul(2)).min(ROUTE_RING_MAX_SLOTS);
                    route_ring.ensure_slots(next_slots);
                }
            }

            for idx in 0..count {
                if packets_left == 0 {
                    budget_hit = true;
                    break;
                }
                packets_left -= 1;
                processed_packets += 1;

                let raw = route_ring.packet(idx);
                for item in NetlinkMessageIter::new(raw) {
                    let msg = match item {
                        Ok(value) => value,
                        Err(_) => {
                            parse_failed = parse_failed.saturating_add(1);
                            continue;
                        }
                    };
                    match msg.header.nlmsg_type as i32 {
                        x if x == libc::RTM_NEWADDR as i32 || x == libc::RTM_DELADDR as i32 => {}
                        _ => continue,
                    }
                    match crate::netlink::addr::parse_addr_event(msg, self.opts.ipv6, &self.filters)
                    {
                        Ok(Some(event)) => {
                            self.logger.emit_netlink_addr_event(NetlinkAddrEvent {
                                nlmsg_type: msg.header.nlmsg_type as u32,
                                nlmsg_seq: msg.header.nlmsg_seq,
                                family: event.family as u32,
                                ifindex: event.ifindex,
                                addr: &event.op.addr,
                                flags: event.flags,
                                op_action: super::rule_action_name(event.op.action),
                            });
                            state
                                .pending
                                .insert(IpKey::from_ip(event.op.addr), event.op.action);
                            touched_pending = true;
                        }
                        Ok(None) => {}
                        Err(_) => {
                            parse_failed = parse_failed.saturating_add(1);
                        }
                    }
                }
            }
        }
        state
            .route_budget
            .update(processed_packets, budget_hit || saw_ring_full);
        if touched_pending {
            let now = Instant::now();
            state.quiet_deadline = Some(now + self.opts.debounce);
            if state.max_deadline.is_none() {
                state.max_deadline = Some(now + self.opts.debounce_max);
            }
        }

        let low_threshold = (route_ring.slots() / 4).max(1);
        if processed_packets <= low_threshold {
            state.route_ring_calm_streak = state.route_ring_calm_streak.saturating_add(1);
            if state.route_ring_calm_streak >= 12 && route_ring.slots() > ROUTE_RING_MIN_SLOTS {
                let target = (route_ring.slots() / 2).max(ROUTE_RING_MIN_SLOTS);
                route_ring.shrink_slots(target);
                state.route_ring_calm_streak = 0;
            }
        } else {
            state.route_ring_calm_streak = 0;
        }

        if parse_failed > 0 {
            state.dropped_count = state.dropped_count.saturating_add(parse_failed);
            self.note_event_drop(state.dropped_count);
            state.resync_requested = true;
            if !state.resync_compensate_pending {
                state.resync_compensate_pending = true;
                self.logger.warn(
                    "sync.compensate_resync",
                    &[
                        ("reason", V::Str("parse_failed")),
                        ("count_failed", V::U64(parse_failed)),
                    ],
                );
            }
        }

        Ok(())
    }

    fn handle_signals(
        &mut self,
        signal_fd: libc::c_int,
        state: &mut EventLoopState,
    ) -> Result<(), AppError> {
        loop {
            let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::read(
                    signal_fd,
                    (&mut info as *mut libc::signalfd_siginfo).cast::<libc::c_void>(),
                    std::mem::size_of::<libc::signalfd_siginfo>(),
                )
            };
            if rc == std::mem::size_of::<libc::signalfd_siginfo>() as isize {
                match info.ssi_signo as i32 {
                    libc::SIGUSR1 => {
                        state.resync_requested = true;
                        self.logger.info(
                            "daemon.signal",
                            &[
                                ("signo", V::U32(info.ssi_signo)),
                                ("action", V::Str("resync")),
                            ],
                        );
                    }
                    _ => {
                        state.shutdown_requested = true;
                        self.logger.info(
                            "daemon.signal",
                            &[
                                ("signo", V::U32(info.ssi_signo)),
                                ("action", V::Str("stop")),
                            ],
                        );
                    }
                }
                continue;
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK)
                {
                    break;
                }
                if matches!(err.raw_os_error(), Some(code) if code == libc::EINTR) {
                    continue;
                }
                return Err(AppError::Io(err));
            }
            break;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn epoll_tag_constants_are_distinct() {
        assert_ne!(super::EPOLL_TAG_ROUTE, super::EPOLL_TAG_SIGNAL);
        assert_ne!(super::EPOLL_TAG_ROUTE, super::EPOLL_TAG_TIMER);
        assert_ne!(super::EPOLL_TAG_ROUTE, super::EPOLL_TAG_RULE);
    }
}
