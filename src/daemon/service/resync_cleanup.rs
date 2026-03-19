use std::time::Instant;

use crate::error::AppError;
use crate::ip_key::IpKey;
use crate::logger::FieldValue as V;
use crate::netlink::addr::{AddrDumpScratch, snapshot_interface_keys_sorted_with_socket_inplace};
use crate::netlink::cleanup::{
    CleanupDumpPoll, CleanupDumpScratch, dump_cleanup_targets_stream_with_scratch,
    poll_cleanup_targets_stream_with_scratch, start_cleanup_dump_family,
};
use crate::netlink::codec::{CLEANUP_BATCH_SIZE, next_seq};
use crate::netlink::rule::{ApplyScratch, RuleAction, RuleOp};
use crate::netlink::socket::NetlinkSocket;

use super::{
    CleanupSource, CleanupSummary, EventLoopState, InflightOwner, MAINTENANCE_OP_BUDGET,
    MAINTENANCE_TIME_BUDGET, MaintenanceJob, ResyncResult, STARTUP_CLEANUP_RETRY_DELAY,
    STARTUP_CLEANUP_RETRY_LIMIT, cleanup_source_name,
};

impl super::Daemon {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn drive_maintenance_slice(
        &mut self,
        route_socket: &NetlinkSocket,
        rule_socket: &NetlinkSocket,
        apply_scratch: &mut ApplyScratch,
        addr_scratch: &mut AddrDumpScratch,
        cleanup_scratch: &mut CleanupDumpScratch,
        state: &mut EventLoopState,
        batch_pool: &mut Vec<Vec<RuleOp>>,
    ) -> Result<(), AppError> {
        let slice_started = Instant::now();
        let mut budget_ops = MAINTENANCE_OP_BUDGET;

        while budget_ops > 0 && slice_started.elapsed() < MAINTENANCE_TIME_BUDGET {
            let job = std::mem::take(&mut state.maintenance);
            match job {
                MaintenanceJob::Idle => {
                    if state.shutdown_requested
                        && state.pending.is_empty()
                        && !state.shutdown_cleanup_done
                    {
                        self.prepare_shutdown_cleanup_job(state);
                        continue;
                    }
                    if state.startup_cleanup_pending {
                        if let Some(deadline) = state.startup_cleanup_retry_deadline
                            && Instant::now() < deadline
                        {
                            state.maintenance = MaintenanceJob::Idle;
                            break;
                        }

                        state.startup_cleanup_pending = false;
                        state.startup_cleanup_retry_deadline = None;
                        state.startup_cleanup_started_at = Some(Instant::now());
                        self.resync_scratch.startup_cleanup_keys.clear();
                        state.maintenance = MaintenanceJob::StartupCleanupDumpCollect {
                            family_idx: 0,
                            seq: None,
                            batch_id: state.batch_id,
                            summary: CleanupSummary::default(),
                        };
                        continue;
                    }
                    if state.resync_requested {
                        state.resync_requested = false;
                        state.maintenance = MaintenanceJob::ResyncBuild {
                            batch_id: state.batch_id,
                        };
                        continue;
                    }
                    state.maintenance = MaintenanceJob::Idle;
                    break;
                }
                MaintenanceJob::StartupCleanupDumpCollect {
                    mut family_idx,
                    mut seq,
                    batch_id,
                    summary,
                } => {
                    budget_ops = budget_ops.saturating_sub(1);

                    let Some((active_idx, family)) =
                        next_startup_cleanup_family(family_idx, self.opts.ipv6)
                    else {
                        if self.resync_scratch.startup_cleanup_keys.is_empty() {
                            state.startup_cleanup_retry_count = 0;
                            let duration_ms = state
                                .startup_cleanup_started_at
                                .take()
                                .map(|started| started.elapsed().as_millis())
                                .unwrap_or(0);
                            self.logger.info(
                                "daemon.startup_cleanup",
                                &[
                                    ("source", V::Str(cleanup_source_name(CleanupSource::Dump))),
                                    ("count_removed", V::Usize(summary.removed)),
                                    ("count_noop", V::Usize(summary.noop)),
                                    ("count_failed", V::Usize(summary.failed)),
                                    ("duration_ms", V::U128(duration_ms)),
                                ],
                            );
                            state.resync_requested = true;
                            state.batch_id = batch_id;
                            state.maintenance = MaintenanceJob::Idle;
                            continue;
                        }

                        state.maintenance = MaintenanceJob::StartupCleanupDumpApply {
                            offset: 0,
                            batch_id,
                            summary,
                            waiting_batch_id: None,
                            next_family_idx: family_idx + 1,
                        };
                        continue;
                    };
                    family_idx = active_idx;

                    if seq.is_none() {
                        let dump_seq = next_seq();
                        if let Err(err) = start_cleanup_dump_family(
                            rule_socket,
                            family,
                            dump_seq,
                            cleanup_scratch,
                        ) {
                            self.schedule_startup_cleanup_retry(state, &err, "dump_start");
                            continue;
                        }
                        seq = Some(dump_seq);
                    }

                    let Some(dump_seq) = seq else {
                        let err = AppError::netlink("startup cleanup dump seq not initialized");
                        self.schedule_startup_cleanup_retry(state, &err, "dump_collect_seq");
                        continue;
                    };
                    match poll_cleanup_targets_stream_with_scratch(
                        rule_socket,
                        self.rule_ctx,
                        family,
                        dump_seq,
                        cleanup_scratch,
                        |target| {
                            self.resync_scratch
                                .startup_cleanup_keys
                                .push(IpKey::from_ip(target.addr));
                            Ok(())
                        },
                    ) {
                        Ok(CleanupDumpPoll::Pending) => {
                            state.maintenance = MaintenanceJob::StartupCleanupDumpCollect {
                                family_idx,
                                seq,
                                batch_id,
                                summary,
                            };
                            break;
                        }
                        Ok(CleanupDumpPoll::Done) => {
                            if self.resync_scratch.startup_cleanup_keys.is_empty() {
                                state.maintenance = MaintenanceJob::StartupCleanupDumpCollect {
                                    family_idx: family_idx + 1,
                                    seq: None,
                                    batch_id,
                                    summary,
                                };
                            } else {
                                state.maintenance = MaintenanceJob::StartupCleanupDumpApply {
                                    offset: 0,
                                    batch_id,
                                    summary,
                                    waiting_batch_id: None,
                                    next_family_idx: family_idx + 1,
                                };
                            }
                            continue;
                        }
                        Err(err) => {
                            self.schedule_startup_cleanup_retry(state, &err, "dump_collect");
                            continue;
                        }
                    }
                }
                MaintenanceJob::StartupCleanupDumpApply {
                    mut offset,
                    mut batch_id,
                    mut summary,
                    mut waiting_batch_id,
                    next_family_idx,
                } => {
                    if let Some(waiting_id) = waiting_batch_id {
                        let Some(done) = state.completed_batch.take() else {
                            state.maintenance = MaintenanceJob::StartupCleanupDumpApply {
                                offset,
                                batch_id,
                                summary,
                                waiting_batch_id,
                                next_family_idx,
                            };
                            break;
                        };
                        if done.owner != InflightOwner::Maintenance || done.batch_id != waiting_id {
                            state.completed_batch = Some(done);
                            state.maintenance = MaintenanceJob::StartupCleanupDumpApply {
                                offset,
                                batch_id,
                                summary,
                                waiting_batch_id,
                                next_family_idx,
                            };
                            break;
                        }
                        waiting_batch_id = None;
                        summary.removed += done.result.deleted;
                        summary.noop += done.result.noop;
                        summary.failed += done.result.failed;
                        budget_ops = budget_ops.saturating_sub(done.result.input.max(1));
                    }

                    if waiting_batch_id.is_none() {
                        let chunk_size = self.opts.batch_max.max(1).min(budget_ops.max(1));
                        let mut chunk = batch_pool
                            .pop()
                            .unwrap_or_else(|| Vec::with_capacity(self.opts.batch_max.max(16)));
                        chunk.clear();
                        fill_tracked_cleanup_chunk(
                            &self.resync_scratch.startup_cleanup_keys,
                            &mut offset,
                            chunk_size,
                            &mut chunk,
                        );

                        if chunk.is_empty() {
                            self.resync_scratch.startup_cleanup_keys.clear();
                            if next_startup_cleanup_family(next_family_idx, self.opts.ipv6)
                                .is_some()
                            {
                                state.batch_id = batch_id;
                                state.maintenance = MaintenanceJob::StartupCleanupDumpCollect {
                                    family_idx: next_family_idx,
                                    seq: None,
                                    batch_id,
                                    summary,
                                };
                            } else {
                                state.startup_cleanup_retry_count = 0;
                                let duration_ms = state
                                    .startup_cleanup_started_at
                                    .take()
                                    .map(|started| started.elapsed().as_millis())
                                    .unwrap_or(0);
                                self.logger.info(
                                    "daemon.startup_cleanup",
                                    &[
                                        (
                                            "source",
                                            V::Str(cleanup_source_name(CleanupSource::Dump)),
                                        ),
                                        ("count_removed", V::Usize(summary.removed)),
                                        ("count_noop", V::Usize(summary.noop)),
                                        ("count_failed", V::Usize(summary.failed)),
                                        ("duration_ms", V::U128(duration_ms)),
                                    ],
                                );
                                state.resync_requested = true;
                                state.batch_id = batch_id;
                                state.maintenance = MaintenanceJob::Idle;
                            }
                            batch_pool.push(chunk);
                            continue;
                        }

                        batch_id = batch_id.wrapping_add(1);
                        match self.start_maintenance_batch(
                            rule_socket,
                            apply_scratch,
                            state,
                            batch_id,
                            chunk,
                        ) {
                            Ok(true) => {
                                waiting_batch_id = Some(batch_id);
                            }
                            Ok(false) => {
                                state.maintenance = MaintenanceJob::StartupCleanupDumpApply {
                                    offset,
                                    batch_id,
                                    summary,
                                    waiting_batch_id,
                                    next_family_idx,
                                };
                                break;
                            }
                            Err(err) => {
                                self.schedule_startup_cleanup_retry(state, &err, "dump_apply");
                                continue;
                            }
                        }
                    }

                    state.maintenance = MaintenanceJob::StartupCleanupDumpApply {
                        offset,
                        batch_id,
                        summary,
                        waiting_batch_id,
                        next_family_idx,
                    };
                    break;
                }
                MaintenanceJob::ResyncBuild { batch_id } => {
                    budget_ops = budget_ops.saturating_sub(1);
                    match self.build_resync_plan(route_socket, addr_scratch) {
                        Ok(metrics) => {
                            state.maintenance = MaintenanceJob::ResyncApply {
                                target_idx: 0,
                                current_idx: 0,
                                batch_id,
                                metrics,
                                waiting_batch_id: None,
                            };
                        }
                        Err(err) => {
                            state.resync_requested = true;
                            self.logger.warn(
                                "daemon.resync_failed",
                                &[("error", V::display(&err)), ("retry", V::Bool(true))],
                            );
                            state.maintenance = MaintenanceJob::Idle;
                            budget_ops = 0;
                        }
                    }
                    continue;
                }
                MaintenanceJob::ResyncApply {
                    mut target_idx,
                    mut current_idx,
                    mut batch_id,
                    mut metrics,
                    mut waiting_batch_id,
                } => {
                    if let Some(waiting_id) = waiting_batch_id {
                        let Some(done) = state.completed_batch.take() else {
                            state.maintenance = MaintenanceJob::ResyncApply {
                                target_idx,
                                current_idx,
                                batch_id,
                                metrics,
                                waiting_batch_id,
                            };
                            break;
                        };
                        if done.owner != InflightOwner::Maintenance || done.batch_id != waiting_id {
                            state.completed_batch = Some(done);
                            state.maintenance = MaintenanceJob::ResyncApply {
                                target_idx,
                                current_idx,
                                batch_id,
                                metrics,
                                waiting_batch_id,
                            };
                            break;
                        }
                        waiting_batch_id = None;
                        metrics.add += done.result.added;
                        metrics.del += done.result.deleted;
                        metrics.failed += done.result.failed;
                        budget_ops = budget_ops.saturating_sub(done.result.input.max(1));
                    }

                    if waiting_batch_id.is_none() {
                        let chunk_size = self.opts.batch_max.max(1).min(budget_ops.max(1));
                        let mut chunk = batch_pool
                            .pop()
                            .unwrap_or_else(|| Vec::with_capacity(self.opts.batch_max.max(16)));
                        chunk.clear();
                        fill_resync_chunk(
                            &self.resync_scratch.target_keys,
                            &self.resync_scratch.current_keys,
                            &mut target_idx,
                            &mut current_idx,
                            chunk_size,
                            &mut chunk,
                        );

                        if chunk.is_empty() {
                            state.resync_compensate_pending = false;
                            self.log_resync_summary(metrics);
                            state.batch_id = batch_id;
                            state.maintenance = MaintenanceJob::Idle;
                            batch_pool.push(chunk);
                            continue;
                        }

                        batch_id = batch_id.wrapping_add(1);
                        if !self.start_maintenance_batch(
                            rule_socket,
                            apply_scratch,
                            state,
                            batch_id,
                            chunk,
                        )? {
                            state.maintenance = MaintenanceJob::ResyncApply {
                                target_idx,
                                current_idx,
                                batch_id,
                                metrics,
                                waiting_batch_id,
                            };
                            break;
                        }
                        waiting_batch_id = Some(batch_id);
                    }

                    state.maintenance = MaintenanceJob::ResyncApply {
                        target_idx,
                        current_idx,
                        batch_id,
                        metrics,
                        waiting_batch_id,
                    };
                    break;
                }
                MaintenanceJob::CleanupTracked {
                    mut offset,
                    mut batch_id,
                    mut summary,
                    mut waiting_batch_id,
                } => {
                    if let Some(waiting_id) = waiting_batch_id {
                        let Some(done) = state.completed_batch.take() else {
                            state.maintenance = MaintenanceJob::CleanupTracked {
                                offset,
                                batch_id,
                                summary,
                                waiting_batch_id,
                            };
                            break;
                        };
                        if done.owner != InflightOwner::Maintenance || done.batch_id != waiting_id {
                            state.completed_batch = Some(done);
                            state.maintenance = MaintenanceJob::CleanupTracked {
                                offset,
                                batch_id,
                                summary,
                                waiting_batch_id,
                            };
                            break;
                        }
                        waiting_batch_id = None;
                        summary.removed += done.result.deleted;
                        summary.noop += done.result.noop;
                        summary.failed += done.result.failed;
                        budget_ops = budget_ops.saturating_sub(done.result.input.max(1));
                    }

                    if waiting_batch_id.is_none() {
                        let chunk_size = self.opts.batch_max.max(1).min(budget_ops.max(1));
                        let mut chunk = batch_pool
                            .pop()
                            .unwrap_or_else(|| Vec::with_capacity(self.opts.batch_max.max(16)));
                        chunk.clear();
                        fill_tracked_cleanup_chunk(
                            &self.resync_scratch.tracked_keys,
                            &mut offset,
                            chunk_size,
                            &mut chunk,
                        );

                        if chunk.is_empty() {
                            state.shutdown_cleanup_done = true;
                            state.shutdown_cleanup = summary;
                            state.batch_id = batch_id;
                            self.logger.info(
                                "cleanup.result",
                                &[
                                    (
                                        "source",
                                        V::Str(cleanup_source_name(CleanupSource::Tracked)),
                                    ),
                                    ("count_removed", V::Usize(summary.removed)),
                                    ("count_noop", V::Usize(summary.noop)),
                                    ("count_failed", V::Usize(summary.failed)),
                                    ("duration_ms", V::U128(0)),
                                ],
                            );
                            state.maintenance = MaintenanceJob::Idle;
                            batch_pool.push(chunk);
                            continue;
                        }

                        batch_id = batch_id.wrapping_add(1);
                        if !self.start_maintenance_batch(
                            rule_socket,
                            apply_scratch,
                            state,
                            batch_id,
                            chunk,
                        )? {
                            state.maintenance = MaintenanceJob::CleanupTracked {
                                offset,
                                batch_id,
                                summary,
                                waiting_batch_id,
                            };
                            break;
                        }
                        waiting_batch_id = Some(batch_id);
                    }

                    state.maintenance = MaintenanceJob::CleanupTracked {
                        offset,
                        batch_id,
                        summary,
                        waiting_batch_id,
                    };
                    break;
                }
            }
        }

        Ok(())
    }

    pub(super) fn cleanup_rules(
        &mut self,
        source: CleanupSource,
        rule_socket: &NetlinkSocket,
        apply_scratch: &mut ApplyScratch,
        cleanup_scratch: &mut CleanupDumpScratch,
    ) -> Result<usize, AppError> {
        let started = Instant::now();
        let mut removed = 0usize;
        let mut noop = 0usize;
        let mut failed = 0usize;
        let mut batch_id = 0u64;
        let batch_size = self.opts.batch_max.max(CLEANUP_BATCH_SIZE).max(1);
        let mut chunk_ops = Vec::with_capacity(batch_size);

        match source {
            CleanupSource::Tracked => {
                let tracked = std::mem::take(&mut self.owned_ips);
                for key in tracked {
                    chunk_ops.push(RuleOp {
                        addr: key.into_ip(),
                        action: RuleAction::Delete,
                    });
                    if chunk_ops.len() >= batch_size {
                        batch_id = batch_id.wrapping_add(1);
                        let result = self.apply_batch_blocking(
                            rule_socket,
                            &chunk_ops,
                            apply_scratch,
                            batch_id,
                        )?;
                        removed += result.deleted;
                        noop += result.noop;
                        failed += result.failed;
                        chunk_ops.clear();
                    }
                }
                if !chunk_ops.is_empty() {
                    batch_id = batch_id.wrapping_add(1);
                    let result = self.apply_batch_blocking(
                        rule_socket,
                        &chunk_ops,
                        apply_scratch,
                        batch_id,
                    )?;
                    removed += result.deleted;
                    noop += result.noop;
                    failed += result.failed;
                    chunk_ops.clear();
                }
            }
            CleanupSource::Dump => {
                let mut families = [libc::AF_INET, libc::AF_INET6];
                for family in &mut families {
                    if *family == libc::AF_INET6 && !self.opts.ipv6 {
                        continue;
                    }
                    dump_cleanup_targets_stream_with_scratch(
                        rule_socket,
                        self.rule_ctx,
                        *family,
                        cleanup_scratch,
                        |target| {
                            chunk_ops.push(target);
                            if chunk_ops.len() < batch_size {
                                return Ok(());
                            }
                            batch_id = batch_id.wrapping_add(1);
                            let result = self.apply_batch_blocking(
                                rule_socket,
                                &chunk_ops,
                                apply_scratch,
                                batch_id,
                            )?;
                            removed += result.deleted;
                            noop += result.noop;
                            failed += result.failed;
                            chunk_ops.clear();
                            Ok(())
                        },
                    )?;
                }
                if !chunk_ops.is_empty() {
                    batch_id = batch_id.wrapping_add(1);
                    let result = self.apply_batch_blocking(
                        rule_socket,
                        &chunk_ops,
                        apply_scratch,
                        batch_id,
                    )?;
                    removed += result.deleted;
                    noop += result.noop;
                    failed += result.failed;
                    chunk_ops.clear();
                }
            }
        }

        self.logger.info(
            "cleanup.result",
            &[
                ("source", V::Str(cleanup_source_name(source))),
                ("count_removed", V::Usize(removed)),
                ("count_noop", V::Usize(noop)),
                ("count_failed", V::Usize(failed)),
                ("duration_ms", V::U128(started.elapsed().as_millis())),
            ],
        );
        Ok(removed)
    }

    fn build_resync_plan(
        &mut self,
        route_socket: &NetlinkSocket,
        addr_scratch: &mut AddrDumpScratch,
    ) -> Result<ResyncResult, AppError> {
        snapshot_interface_keys_sorted_with_socket_inplace(
            route_socket,
            self.opts.ipv6,
            &self.filters,
            addr_scratch,
            &mut self.resync_scratch.target_keys,
        )?;
        self.resync_scratch.current_keys.clear();
        self.resync_scratch
            .current_keys
            .reserve(self.owned_ips.len());
        self.resync_scratch
            .current_keys
            .extend(self.owned_ips.iter().copied());
        self.resync_scratch.current_keys.sort_unstable();
        self.resync_scratch.current_keys.dedup();

        Ok(ResyncResult {
            target: self.resync_scratch.target_keys.len(),
            current: self.resync_scratch.current_keys.len(),
            add: 0,
            del: 0,
            failed: 0,
        })
    }

    fn prepare_shutdown_cleanup_job(&mut self, state: &mut EventLoopState) {
        self.resync_scratch.tracked_keys.clear();
        let tracked = std::mem::take(&mut self.owned_ips);
        self.resync_scratch.tracked_keys.reserve(tracked.len());
        self.resync_scratch.tracked_keys.extend(tracked);
        self.resync_scratch.tracked_keys.sort_unstable();

        if self.resync_scratch.tracked_keys.is_empty() {
            state.shutdown_cleanup_done = true;
            state.shutdown_cleanup = CleanupSummary::default();
            state.maintenance = MaintenanceJob::Idle;
            return;
        }
        state.maintenance = MaintenanceJob::CleanupTracked {
            offset: 0,
            batch_id: state.batch_id,
            summary: CleanupSummary::default(),
            waiting_batch_id: None,
        };
    }

    fn schedule_startup_cleanup_retry(
        &mut self,
        state: &mut EventLoopState,
        err: &AppError,
        phase: &'static str,
    ) {
        state.startup_cleanup_retry_count = state.startup_cleanup_retry_count.saturating_add(1);
        let retry = state.startup_cleanup_retry_count <= STARTUP_CLEANUP_RETRY_LIMIT;
        self.logger.warn(
            "daemon.startup_cleanup_failed",
            &[
                ("phase", V::Str(phase)),
                ("error", V::display(err)),
                ("retry", V::Bool(retry)),
                ("attempt", V::U32(state.startup_cleanup_retry_count as u32)),
            ],
        );
        self.resync_scratch.startup_cleanup_keys.clear();
        state.startup_cleanup_started_at = None;
        state.maintenance = MaintenanceJob::Idle;
        state.resync_requested = true;
        if retry {
            state.startup_cleanup_pending = true;
            state.startup_cleanup_retry_deadline =
                Some(Instant::now() + STARTUP_CLEANUP_RETRY_DELAY);
        } else {
            state.startup_cleanup_pending = false;
            state.startup_cleanup_retry_deadline = None;
        }
    }

    fn log_resync_summary(&self, result: ResyncResult) {
        self.logger.info(
            "daemon.resync",
            &[
                ("count_target", V::Usize(result.target)),
                ("count_current", V::Usize(result.current)),
                ("count_add", V::Usize(result.add)),
                ("count_del", V::Usize(result.del)),
                ("count_failed", V::Usize(result.failed)),
            ],
        );
    }
}

fn next_startup_cleanup_family(start_idx: usize, ipv6_enabled: bool) -> Option<(usize, i32)> {
    let families = [libc::AF_INET, libc::AF_INET6];
    let mut idx = start_idx;
    while idx < families.len() {
        let family = families[idx];
        if family == libc::AF_INET6 && !ipv6_enabled {
            idx += 1;
            continue;
        }
        return Some((idx, family));
    }
    None
}

fn fill_resync_chunk(
    target: &[IpKey],
    current: &[IpKey],
    target_idx: &mut usize,
    current_idx: &mut usize,
    max_ops: usize,
    out: &mut Vec<RuleOp>,
) {
    if max_ops == 0 {
        return;
    }

    while out.len() < max_ops && *target_idx < target.len() && *current_idx < current.len() {
        let target_key = target[*target_idx];
        let current_key = current[*current_idx];
        if target_key < current_key {
            out.push(RuleOp {
                addr: target_key.into_ip(),
                action: RuleAction::Add,
            });
            *target_idx += 1;
            continue;
        }
        if target_key > current_key {
            out.push(RuleOp {
                addr: current_key.into_ip(),
                action: RuleAction::Delete,
            });
            *current_idx += 1;
            continue;
        }
        *target_idx += 1;
        *current_idx += 1;
    }

    while out.len() < max_ops && *target_idx < target.len() {
        out.push(RuleOp {
            addr: target[*target_idx].into_ip(),
            action: RuleAction::Add,
        });
        *target_idx += 1;
    }
    while out.len() < max_ops && *current_idx < current.len() {
        out.push(RuleOp {
            addr: current[*current_idx].into_ip(),
            action: RuleAction::Delete,
        });
        *current_idx += 1;
    }
}

fn fill_tracked_cleanup_chunk(
    tracked: &[IpKey],
    offset: &mut usize,
    max_ops: usize,
    out: &mut Vec<RuleOp>,
) {
    if max_ops == 0 || *offset >= tracked.len() {
        return;
    }
    let end = (*offset + max_ops).min(tracked.len());
    for key in &tracked[*offset..end] {
        out.push(RuleOp {
            addr: key.into_ip(),
            action: RuleAction::Delete,
        });
    }
    *offset = end;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hash::FxHashSet;
    use std::net::IpAddr;

    #[test]
    fn ip_key_mapping_roundtrip() {
        let ip: IpAddr = "192.0.2.9".parse().expect("ip");
        let key = IpKey::from_ip(ip);
        assert_eq!(key.into_ip(), ip);
    }

    #[test]
    fn sort_merge_diff_matches_set_diff() {
        let target = vec![
            IpKey::from_ip("10.0.0.1".parse().expect("ip")),
            IpKey::from_ip("10.0.0.2".parse().expect("ip")),
            IpKey::from_ip("2001:db8::1".parse().expect("ip")),
        ];
        let current = vec![
            IpKey::from_ip("10.0.0.2".parse().expect("ip")),
            IpKey::from_ip("10.0.0.3".parse().expect("ip")),
            IpKey::from_ip("2001:db8::2".parse().expect("ip")),
        ];

        let mut target_sorted = target.clone();
        target_sorted.sort_unstable();
        let mut current_sorted = current.clone();
        current_sorted.sort_unstable();

        let mut i = 0usize;
        let mut j = 0usize;
        let mut all_ops = Vec::new();
        loop {
            let mut chunk = Vec::new();
            fill_resync_chunk(
                &target_sorted,
                &current_sorted,
                &mut i,
                &mut j,
                2,
                &mut chunk,
            );
            if chunk.is_empty() {
                break;
            }
            all_ops.extend(chunk);
        }

        let mut adds = FxHashSet::default();
        let mut dels = FxHashSet::default();
        for op in all_ops {
            match op.action {
                RuleAction::Add => {
                    adds.insert(IpKey::from_ip(op.addr));
                }
                RuleAction::Delete => {
                    dels.insert(IpKey::from_ip(op.addr));
                }
            }
        }

        assert!(adds.contains(&IpKey::from_ip("10.0.0.1".parse().expect("ip"))));
        assert!(adds.contains(&IpKey::from_ip("2001:db8::1".parse().expect("ip"))));
        assert!(dels.contains(&IpKey::from_ip("10.0.0.3".parse().expect("ip"))));
        assert!(dels.contains(&IpKey::from_ip("2001:db8::2".parse().expect("ip"))));
        assert_eq!(adds.len(), 2);
        assert_eq!(dels.len(), 2);
    }

    #[test]
    fn tracked_cleanup_chunk_respects_batch_boundary() {
        let tracked = vec![
            IpKey::from_ip("10.0.0.1".parse().expect("ip")),
            IpKey::from_ip("10.0.0.2".parse().expect("ip")),
            IpKey::from_ip("10.0.0.3".parse().expect("ip")),
        ];

        let mut offset = 0usize;
        let mut first = Vec::new();
        fill_tracked_cleanup_chunk(&tracked, &mut offset, 2, &mut first);
        assert_eq!(first.len(), 2);
        assert_eq!(offset, 2);

        let mut second = Vec::new();
        fill_tracked_cleanup_chunk(&tracked, &mut offset, 2, &mut second);
        assert_eq!(second.len(), 1);
        assert_eq!(offset, 3);
    }
}
