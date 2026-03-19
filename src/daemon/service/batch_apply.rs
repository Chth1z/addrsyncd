use std::time::{Duration, Instant};

use crate::error::AppError;
use crate::ip_key::IpKey;
use crate::logger::{FieldValue as V, RuleAckFailedEvent, RuleBatchEvent};
use crate::netlink::codec::seq_with_offset;
use crate::netlink::rule::{
    ACK_WAIT_TIMEOUT, AckTracker, ApplyScratch, RuleAckClass, RuleOp, classify_ack_for_op,
    classify_wait_error, drain_apply_ack_messages, start_apply_rules_batch,
};
use crate::netlink::socket::NetlinkSocket;

use super::{
    ApplyResult, BATCH_NOOP_LOG_INTERVAL, EVENT_DROP_LOG_INTERVAL, EventLoopState, InflightBatch,
    InflightOwner, MaintenanceJob, rule_action_name,
};

#[derive(Clone, Copy)]
struct AckCommitCtx {
    batch_id: u64,
    first_seq: u32,
    started_at: Instant,
    input_count: usize,
    noop_prefilter: usize,
}

impl super::Daemon {
    pub(super) fn start_pending_batch(
        &mut self,
        rule_socket: &NetlinkSocket,
        apply_scratch: &mut ApplyScratch,
        state: &mut EventLoopState,
        batch_pool: &mut Vec<Vec<RuleOp>>,
    ) -> Result<bool, AppError> {
        if state.inflight.is_some() || state.pending.is_empty() {
            return Ok(false);
        }

        let mut ops = batch_pool
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.opts.batch_max.max(16)));
        ops.clear();

        let take_n = self.opts.batch_max.min(state.pending.len());
        let mut pulled = 0usize;
        for (key, action) in state.pending.extract_if(|_, _| {
            if pulled < take_n {
                pulled += 1;
                true
            } else {
                false
            }
        }) {
            ops.push(RuleOp {
                addr: key.into_ip(),
                action,
            });
        }
        let input_count = ops.len();

        if !state.pending.is_empty() {
            let now = Instant::now();
            state.quiet_deadline = Some(now + self.opts.debounce);
            state.max_deadline = Some(now + self.opts.debounce_max);
        } else {
            state.quiet_deadline = None;
            state.max_deadline = None;
        }

        if ops.is_empty() {
            batch_pool.push(ops);
            return Ok(false);
        }

        let mut write_idx = 0usize;
        let mut noop_prefilter = input_count.saturating_sub(ops.len());
        for idx in 0..ops.len() {
            let op = ops[idx];
            let key = IpKey::from_ip(op.addr);
            let should_skip = match op.action {
                crate::netlink::rule::RuleAction::Add => self.owned_ips.contains(&key),
                crate::netlink::rule::RuleAction::Delete => !self.owned_ips.contains(&key),
            };
            if should_skip {
                noop_prefilter += 1;
                continue;
            }
            if write_idx != idx {
                ops[write_idx] = op;
            }
            write_idx += 1;
        }
        ops.truncate(write_idx);

        if ops.is_empty() {
            self.logger.debug_every(
                "rule_batch_noop_prefilter",
                BATCH_NOOP_LOG_INTERVAL,
                "rule.batch.noop_prefilter",
                &[
                    ("count_input", V::Usize(input_count)),
                    ("count_noop", V::Usize(noop_prefilter)),
                ],
            );
            batch_pool.push(ops);
            return Ok(false);
        }

        state.batch_id = state.batch_id.wrapping_add(1);
        let batch_id = state.batch_id;
        let mut tracker = std::mem::take(&mut state.ack_tracker_reuse);
        let first_seq = match start_apply_rules_batch(
            rule_socket,
            self.rule_ctx,
            &ops,
            apply_scratch,
            &mut tracker,
        ) {
            Ok(seq) => seq,
            Err(err) => {
                state.ack_tracker_reuse = tracker;
                return Err(err);
            }
        };
        let started_at = Instant::now();
        state.inflight = Some(InflightBatch {
            batch_id,
            started_at,
            ack_deadline: started_at + ACK_WAIT_TIMEOUT,
            input_count,
            noop_prefilter,
            first_seq,
            tracker,
            owner: InflightOwner::Pending,
            ops,
        });

        Ok(true)
    }

    pub(super) fn start_maintenance_batch(
        &mut self,
        rule_socket: &NetlinkSocket,
        apply_scratch: &mut ApplyScratch,
        state: &mut EventLoopState,
        batch_id: u64,
        mut ops: Vec<RuleOp>,
    ) -> Result<bool, AppError> {
        if state.inflight.is_some() {
            return Ok(false);
        }
        if ops.is_empty() {
            return Ok(false);
        }

        let input_count = ops.len();
        let mut tracker = std::mem::take(&mut state.ack_tracker_reuse);
        let first_seq = match start_apply_rules_batch(
            rule_socket,
            self.rule_ctx,
            &ops,
            apply_scratch,
            &mut tracker,
        ) {
            Ok(seq) => seq,
            Err(err) => {
                state.ack_tracker_reuse = tracker;
                return Err(err);
            }
        };
        let started_at = Instant::now();
        state.inflight = Some(InflightBatch {
            batch_id,
            started_at,
            ack_deadline: started_at + ACK_WAIT_TIMEOUT,
            input_count,
            noop_prefilter: 0,
            first_seq,
            tracker,
            owner: InflightOwner::Maintenance,
            ops: std::mem::take(&mut ops),
        });
        Ok(true)
    }

    pub(super) fn handle_ack_timeout(
        &mut self,
        state: &mut EventLoopState,
        batch_pool: &mut Vec<Vec<RuleOp>>,
    ) {
        let Some(mut inflight) = state.inflight.take() else {
            return;
        };

        self.logger.warn(
            "rule.ack_timeout",
            &[
                ("batch_id", V::U64(inflight.batch_id)),
                ("count_input", V::Usize(inflight.input_count)),
                ("count_pending", V::Usize(inflight.tracker.pending())),
            ],
        );

        for (idx, op) in inflight.ops.iter().enumerate() {
            if inflight.tracker.seen_at(idx) {
                continue;
            }
            let seq = seq_with_offset(inflight.first_seq, idx);
            self.logger.emit_rule_ack_failed(RuleAckFailedEvent {
                batch_id: inflight.batch_id,
                seq,
                errno: libc::ETIMEDOUT,
                op_action: rule_action_name(op.action),
                op_addr: &op.addr,
                ext_msg: None,
                ext_offset: None,
            });
        }

        if matches!(inflight.owner, InflightOwner::Pending) {
            self.queue_compensate_resync(state, "ack_timeout");
        }

        if matches!(inflight.owner, InflightOwner::Maintenance) {
            state.completed_batch = Some(super::CompletedBatch {
                batch_id: inflight.batch_id,
                owner: inflight.owner,
                result: ApplyResult {
                    input: inflight.input_count,
                    noop: inflight.noop_prefilter,
                    added: 0,
                    deleted: 0,
                    failed: inflight.input_count.saturating_sub(inflight.noop_prefilter),
                    duration: Instant::now().saturating_duration_since(inflight.started_at),
                },
            });
        }
        state.ack_tracker_reuse = std::mem::take(&mut inflight.tracker);
        inflight.ops.clear();
        if batch_pool.len() < 8 {
            batch_pool.push(inflight.ops);
        }
    }

    pub(super) fn finish_inflight_batch(
        &mut self,
        state: &mut EventLoopState,
        batch_pool: &mut Vec<Vec<RuleOp>>,
    ) -> Result<(), AppError> {
        let Some(mut inflight) = state.inflight.take() else {
            return Ok(());
        };

        let result = self.commit_ack_outcomes(
            AckCommitCtx {
                batch_id: inflight.batch_id,
                first_seq: inflight.first_seq,
                started_at: inflight.started_at,
                input_count: inflight.input_count,
                noop_prefilter: inflight.noop_prefilter,
            },
            &inflight.ops,
            &inflight.tracker,
        )?;

        self.log_batch_result(inflight.batch_id, result);
        if matches!(inflight.owner, InflightOwner::Maintenance) {
            state.completed_batch = Some(super::CompletedBatch {
                batch_id: inflight.batch_id,
                result,
                owner: inflight.owner,
            });
        }
        state.ack_tracker_reuse = std::mem::take(&mut inflight.tracker);
        inflight.ops.clear();
        if batch_pool.len() < 8 {
            batch_pool.push(inflight.ops);
        }
        Ok(())
    }

    pub(super) fn apply_batch_blocking(
        &mut self,
        rule_socket: &NetlinkSocket,
        ops: &[RuleOp],
        apply_scratch: &mut ApplyScratch,
        batch_id: u64,
    ) -> Result<ApplyResult, AppError> {
        if ops.is_empty() {
            return Ok(ApplyResult::default());
        }

        let started = Instant::now();
        let mut tracker = std::mem::take(&mut apply_scratch.blocking_tracker);
        let first_seq = match start_apply_rules_batch(
            rule_socket,
            self.rule_ctx,
            ops,
            apply_scratch,
            &mut tracker,
        ) {
            Ok(seq) => seq,
            Err(err) => {
                apply_scratch.blocking_tracker = tracker;
                return Err(err);
            }
        };

        let deadline = started + ACK_WAIT_TIMEOUT;
        while tracker.pending() > 0 {
            drain_apply_ack_messages(rule_socket, first_seq, ops, apply_scratch, &mut tracker)?;
            if tracker.pending() == 0 {
                break;
            }
            if !super::lifecycle::wait_readable(rule_socket.fd(), deadline)? {
                let wait_err = classify_wait_error(&tracker);
                apply_scratch.blocking_tracker = tracker;
                return Err(wait_err.to_app_error());
            }
        }

        let result = self.commit_ack_outcomes(
            AckCommitCtx {
                batch_id,
                first_seq,
                started_at: started,
                input_count: ops.len(),
                noop_prefilter: 0,
            },
            ops,
            &tracker,
        )?;
        apply_scratch.blocking_tracker = tracker;
        self.log_batch_result(batch_id, result);
        Ok(result)
    }

    pub(super) fn note_event_drop(&self, dropped: u64) {
        self.logger.info_every(
            "netlink_event_drop",
            EVENT_DROP_LOG_INTERVAL,
            "netlink.event_drop",
            &[("count_dropped", V::U64(dropped))],
        );
    }

    fn queue_compensate_resync(&mut self, state: &mut EventLoopState, reason: &'static str) {
        state.resync_requested = true;
        if state.resync_compensate_pending {
            return;
        }
        state.resync_compensate_pending = true;
        self.logger.warn(
            "sync.compensate_resync",
            &[
                ("reason", V::Str(reason)),
                ("count_event_drop", V::U64(state.dropped_count)),
            ],
        );
    }

    fn commit_ack_outcomes(
        &mut self,
        ctx: AckCommitCtx,
        ops: &[RuleOp],
        tracker: &AckTracker,
    ) -> Result<ApplyResult, AppError> {
        let batch_id = ctx.batch_id;
        let first_seq = ctx.first_seq;
        let mut add = 0usize;
        let mut del = 0usize;
        let mut noop = ctx.noop_prefilter;
        let mut failed = 0usize;

        for (idx, op) in ops.iter().enumerate() {
            let seq = seq_with_offset(first_seq, idx);
            if !tracker.seen_at(idx) {
                failed += 1;
                self.logger.emit_rule_ack_failed(RuleAckFailedEvent {
                    batch_id,
                    seq,
                    errno: libc::ETIMEDOUT,
                    op_action: rule_action_name(op.action),
                    op_addr: &op.addr,
                    ext_msg: None,
                    ext_offset: None,
                });
                self.logger.debug(
                    "rule.op",
                    &[
                        ("batch_id", V::U64(batch_id)),
                        ("seq", V::U32(seq)),
                        ("op_action", V::Str(rule_action_name(op.action))),
                        ("op_addr", V::display(&op.addr)),
                        ("result", V::Str("timeout")),
                    ],
                );
                continue;
            }

            let status = tracker.status_at(idx);
            match classify_ack_for_op(*op, status) {
                RuleAckClass::Ok => {
                    let key = IpKey::from_ip(op.addr);
                    match op.action {
                        crate::netlink::rule::RuleAction::Add => {
                            self.owned_ips.insert(key);
                            add += 1;
                        }
                        crate::netlink::rule::RuleAction::Delete => {
                            self.owned_ips.remove(&key);
                            del += 1;
                        }
                    }
                    self.logger.debug(
                        "rule.op",
                        &[
                            ("batch_id", V::U64(batch_id)),
                            ("seq", V::U32(seq)),
                            ("op_action", V::Str(rule_action_name(op.action))),
                            ("op_addr", V::display(&op.addr)),
                            ("result", V::Str("applied")),
                        ],
                    );
                }
                RuleAckClass::EexistNoop => {
                    noop += 1;
                    self.logger.debug(
                        "rule.op",
                        &[
                            ("batch_id", V::U64(batch_id)),
                            ("seq", V::U32(seq)),
                            ("op_action", V::Str(rule_action_name(op.action))),
                            ("op_addr", V::display(&op.addr)),
                            ("result", V::Str("noop_eexist")),
                        ],
                    );
                }
                RuleAckClass::EnoentNoop => {
                    noop += 1;
                    self.logger.debug(
                        "rule.op",
                        &[
                            ("batch_id", V::U64(batch_id)),
                            ("seq", V::U32(seq)),
                            ("op_action", V::Str(rule_action_name(op.action))),
                            ("op_addr", V::display(&op.addr)),
                            ("result", V::Str("noop_enoent")),
                        ],
                    );
                }
                RuleAckClass::KernelErr => {
                    failed += 1;
                    if let Some(status) = status {
                        self.logger.emit_rule_ack_failed(RuleAckFailedEvent {
                            batch_id,
                            seq,
                            errno: status.errno,
                            op_action: rule_action_name(op.action),
                            op_addr: &op.addr,
                            ext_msg: status.ext_msg.as_ref().map(|text| text.as_str()),
                            ext_offset: status.ext_offset,
                        });
                        self.logger.debug(
                            "rule.op",
                            &[
                                ("batch_id", V::U64(batch_id)),
                                ("seq", V::U32(seq)),
                                ("op_action", V::Str(rule_action_name(op.action))),
                                ("op_addr", V::display(&op.addr)),
                                ("result", V::Str("failed_errno")),
                                ("errno", V::I32(status.errno)),
                            ],
                        );
                    } else {
                        self.logger.warn(
                            "rule.ack_invariant",
                            &[
                                ("batch_id", V::U64(batch_id)),
                                ("seq", V::U32(seq)),
                                ("op_action", V::Str(rule_action_name(op.action))),
                                ("op_addr", V::display(&op.addr)),
                                ("reason", V::Str("kernel_err_without_status")),
                            ],
                        );
                    }
                }
            }
        }

        if failed > 0 {
            self.logger.warn(
                "rule.batch.failed",
                &[
                    ("batch_id", V::U64(batch_id)),
                    ("count_failed", V::Usize(failed)),
                ],
            );
        }

        Ok(ApplyResult {
            input: ctx.input_count,
            noop,
            added: add,
            deleted: del,
            failed,
            duration: Instant::now().saturating_duration_since(ctx.started_at),
        })
    }

    fn log_batch_result(&self, batch_id: u64, result: ApplyResult) {
        self.logger.emit_rule_batch(RuleBatchEvent {
            batch_id,
            count_input: result.input,
            count_add: result.added,
            count_del: result.deleted,
            count_noop: result.noop,
            count_failed: result.failed,
            duration_ms: result.duration.as_millis(),
        });
    }

    pub(super) fn drain_rule_acks_once(
        &mut self,
        rule_socket: &NetlinkSocket,
        apply_scratch: &mut ApplyScratch,
        state: &mut EventLoopState,
        batch_pool: &mut Vec<Vec<RuleOp>>,
    ) -> Result<(), AppError> {
        let Some(inflight) = state.inflight.as_mut() else {
            return Ok(());
        };
        drain_apply_ack_messages(
            rule_socket,
            inflight.first_seq,
            &inflight.ops,
            apply_scratch,
            &mut inflight.tracker,
        )?;
        if inflight.tracker.pending() == 0 {
            self.finish_inflight_batch(state, batch_pool)?;
        }
        Ok(())
    }

    pub(super) fn should_flush_pending(
        &self,
        state: &EventLoopState,
        now: Instant,
        force: bool,
    ) -> bool {
        if state.pending.is_empty() {
            return false;
        }
        if force {
            return true;
        }
        if let Some(deadline) = state.quiet_deadline
            && now >= deadline
        {
            return true;
        }
        if let Some(deadline) = state.max_deadline
            && now >= deadline
        {
            return true;
        }
        false
    }

    pub(super) fn next_deadline(&self, state: &EventLoopState) -> Option<Instant> {
        let mut deadline: Option<Instant> = None;
        if let Some(v) = state.quiet_deadline {
            min_deadline(&mut deadline, v);
        }
        if let Some(v) = state.max_deadline {
            min_deadline(&mut deadline, v);
        }
        if let Some(inflight) = &state.inflight {
            let v = inflight.ack_deadline;
            min_deadline(&mut deadline, v);
        }
        let soon = Instant::now() + Duration::from_millis(1);
        if !matches!(state.maintenance, MaintenanceJob::Idle) {
            min_deadline(&mut deadline, soon);
        }
        if state.resync_requested && state.inflight.is_none() {
            min_deadline(&mut deadline, soon);
        }
        if state.shutdown_requested && !state.shutdown_cleanup_done && state.inflight.is_none() {
            min_deadline(&mut deadline, soon);
        }
        if state.startup_cleanup_pending && state.inflight.is_none() {
            let v = state.startup_cleanup_retry_deadline.unwrap_or(soon);
            min_deadline(&mut deadline, v);
        }
        deadline
    }
}

#[inline]
fn min_deadline(deadline: &mut Option<Instant>, value: Instant) {
    match deadline {
        Some(current) => {
            if value < *current {
                *current = value;
            }
        }
        None => *deadline = Some(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn noop_log_interval_nonzero() {
        assert!(BATCH_NOOP_LOG_INTERVAL >= Duration::from_secs(1));
    }
}
