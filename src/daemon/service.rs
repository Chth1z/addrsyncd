mod batch_apply;
mod event_loop;
mod lifecycle;
mod resync_cleanup;

use std::time::{Duration, Instant};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::config::Options;
use crate::error::AppError;
use crate::ip_key::IpKey;
use crate::logger::{FieldValue as V, Logger, schema as log_schema};
use crate::netlink::addr::{AddrDumpScratch, IgnoreFilters};
use crate::netlink::cleanup::CleanupDumpScratch;
use crate::netlink::rule::{
    AckTracker, ApplyScratch, RuleAction, RuleContext, RuleOp, new_rule_context,
};
use crate::netlink::socket::{MmsgRxRing, NetlinkSocket};

pub(super) const BATCH_NOOP_LOG_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const EVENT_DROP_LOG_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const MAINTENANCE_OP_BUDGET: usize = 256;
pub(super) const MAINTENANCE_TIME_BUDGET: Duration = Duration::from_millis(8);
pub(super) const STARTUP_CLEANUP_RETRY_LIMIT: u8 = 3;
pub(super) const STARTUP_CLEANUP_RETRY_DELAY: Duration = Duration::from_millis(500);
pub(super) const ROUTE_DRAIN_MIN_BUDGET: usize = 64;
pub(super) const ROUTE_DRAIN_DEFAULT_BUDGET: usize = 256;
pub(super) const ROUTE_DRAIN_MAX_BUDGET: usize = 1024;
pub(super) const ROUTE_RING_MIN_SLOTS: usize = 8;
pub(super) const ROUTE_RING_MAX_SLOTS: usize = 32;

pub(super) const EPOLL_TAG_ROUTE: u64 = 1;
pub(super) const EPOLL_TAG_SIGNAL: u64 = 2;
pub(super) const EPOLL_TAG_TIMER: u64 = 3;
pub(super) const EPOLL_TAG_RULE: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupSource {
    Tracked,
    Dump,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct ApplyResult {
    pub(super) input: usize,
    pub(super) noop: usize,
    pub(super) added: usize,
    pub(super) deleted: usize,
    pub(super) failed: usize,
    pub(super) duration: Duration,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct ResyncResult {
    pub(super) target: usize,
    pub(super) current: usize,
    pub(super) add: usize,
    pub(super) del: usize,
    pub(super) failed: usize,
}

pub(super) struct InflightBatch {
    pub(super) batch_id: u64,
    pub(super) started_at: Instant,
    pub(super) ack_deadline: Instant,
    pub(super) input_count: usize,
    pub(super) noop_prefilter: usize,
    pub(super) first_seq: u32,
    pub(super) tracker: AckTracker,
    pub(super) owner: InflightOwner,
    pub(super) ops: Vec<RuleOp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InflightOwner {
    Pending,
    Maintenance,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CompletedBatch {
    pub(super) batch_id: u64,
    pub(super) result: ApplyResult,
    pub(super) owner: InflightOwner,
}

#[derive(Default)]
pub(super) struct ResyncScratch {
    pub(super) target_keys: Vec<IpKey>,
    pub(super) current_keys: Vec<IpKey>,
    pub(super) tracked_keys: Vec<IpKey>,
    pub(super) startup_cleanup_keys: Vec<IpKey>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct CleanupSummary {
    pub(super) removed: usize,
    pub(super) noop: usize,
    pub(super) failed: usize,
}

#[derive(Debug, Default)]
pub(super) enum MaintenanceJob {
    #[default]
    Idle,
    StartupCleanupDumpCollect {
        family_idx: usize,
        seq: Option<u32>,
        batch_id: u64,
        summary: CleanupSummary,
    },
    StartupCleanupDumpApply {
        offset: usize,
        batch_id: u64,
        summary: CleanupSummary,
        waiting_batch_id: Option<u64>,
        next_family_idx: usize,
    },
    ResyncBuild {
        batch_id: u64,
    },
    ResyncApply {
        target_idx: usize,
        current_idx: usize,
        batch_id: u64,
        metrics: ResyncResult,
        waiting_batch_id: Option<u64>,
    },
    CleanupTracked {
        offset: usize,
        batch_id: u64,
        summary: CleanupSummary,
        waiting_batch_id: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RouteBudgetState {
    pub(super) current: usize,
    full_streak: u8,
    low_streak: u8,
}

impl Default for RouteBudgetState {
    fn default() -> Self {
        Self {
            current: ROUTE_DRAIN_DEFAULT_BUDGET,
            full_streak: 0,
            low_streak: 0,
        }
    }
}

impl RouteBudgetState {
    pub(super) fn update(&mut self, processed: usize, budget_hit: bool) {
        if budget_hit {
            self.full_streak = self.full_streak.saturating_add(1);
            self.low_streak = 0;
            if self.full_streak >= 2 {
                self.current = (self.current.saturating_mul(2)).min(ROUTE_DRAIN_MAX_BUDGET);
                self.full_streak = 0;
            }
            return;
        }

        let low_threshold = (self.current / 4).max(1);
        if processed <= low_threshold {
            self.low_streak = self.low_streak.saturating_add(1);
            self.full_streak = 0;
            if self.low_streak >= 8 {
                self.current = (self.current / 2).max(ROUTE_DRAIN_MIN_BUDGET);
                self.low_streak = 0;
            }
            return;
        }

        self.low_streak = 0;
        self.full_streak = 0;
    }
}

#[derive(Default)]
pub(super) struct EventLoopState {
    pub(super) pending: FxHashMap<IpKey, RuleAction>,
    pub(super) quiet_deadline: Option<Instant>,
    pub(super) max_deadline: Option<Instant>,
    pub(super) inflight: Option<InflightBatch>,
    pub(super) ack_tracker_reuse: AckTracker,
    pub(super) dropped_count: u64,
    pub(super) batch_id: u64,
    pub(super) shutdown_requested: bool,
    pub(super) resync_requested: bool,
    pub(super) resync_compensate_pending: bool,
    pub(super) maintenance: MaintenanceJob,
    pub(super) shutdown_cleanup_done: bool,
    pub(super) shutdown_cleanup: CleanupSummary,
    pub(super) route_budget: RouteBudgetState,
    pub(super) route_ring_calm_streak: u8,
    pub(super) completed_batch: Option<CompletedBatch>,
    pub(super) startup_cleanup_pending: bool,
    pub(super) startup_cleanup_retry_deadline: Option<Instant>,
    pub(super) startup_cleanup_retry_count: u8,
    pub(super) startup_cleanup_started_at: Option<Instant>,
}

pub(crate) struct Daemon {
    pub(super) opts: Options,
    pub(super) logger: Logger,
    pub(super) owned_ips: FxHashSet<IpKey>,
    pub(super) rule_ctx: RuleContext,
    pub(super) filters: IgnoreFilters,
    pub(super) resync_scratch: ResyncScratch,
}

impl Daemon {
    pub(crate) fn new(opts: Options, logger: Logger) -> Result<Self, AppError> {
        let rule_ctx = new_rule_context(opts.pref, opts.table_id);
        let filters = IgnoreFilters::new(
            &opts.ignore_ips,
            &opts.ignore_cidrs,
            opts.ignore_addr_flag_mask,
        );
        let batch_cap = opts.batch_max.max(16);
        Ok(Self {
            opts,
            logger,
            owned_ips: FxHashSet::default(),
            rule_ctx,
            filters,
            resync_scratch: ResyncScratch {
                target_keys: Vec::with_capacity(batch_cap * 2),
                current_keys: Vec::with_capacity(batch_cap * 2),
                tracked_keys: Vec::with_capacity(batch_cap * 2),
                startup_cleanup_keys: Vec::with_capacity(batch_cap * 2),
            },
        })
    }

    pub(crate) fn run(&mut self, ready_fd: Option<libc::c_int>) -> Result<(), AppError> {
        let route_socket = NetlinkSocket::open_route(self.opts.ipv6)
            .map_err(AppError::from_required_syscall_io)?;
        let rule_socket = NetlinkSocket::open_rule().map_err(AppError::from_required_syscall_io)?;

        let mut apply_scratch = ApplyScratch::default();
        let mut addr_scratch = AddrDumpScratch::default();
        let mut cleanup_scratch = CleanupDumpScratch::default();

        let signal_fd = lifecycle::setup_signalfd()?;
        let timer_fd = lifecycle::setup_timerfd()?;
        let epoll_fd =
            lifecycle::setup_epoll(route_socket.fd(), rule_socket.fd(), signal_fd, timer_fd)?;

        self.logger.info_schema(
            log_schema::DAEMON_STARTED,
            &[
                ("pref", V::U32(self.opts.pref.get())),
                ("table_id", V::U32(self.opts.table_id.get())),
                ("ipv6_enabled", V::Bool(self.opts.ipv6)),
                ("debounce_ms", V::U128(self.opts.debounce.as_millis())),
                (
                    "debounce_max_ms",
                    V::U128(self.opts.debounce_max.as_millis()),
                ),
                ("batch_max", V::Usize(self.opts.batch_max)),
                ("count_cleanup_removed", V::Usize(0)),
                ("count_resync_add", V::Usize(0)),
                ("count_resync_del", V::Usize(0)),
                ("count_resync_failed", V::Usize(0)),
            ],
        );

        let mut state = EventLoopState {
            startup_cleanup_pending: true,
            ..EventLoopState::default()
        };
        let mut route_ring = MmsgRxRing::default_route_ring();
        let mut batch_pool: Vec<Vec<RuleOp>> = Vec::with_capacity(8);
        for _ in 0..8 {
            batch_pool.push(Vec::with_capacity(self.opts.batch_max));
        }

        if let Some(fd) = ready_fd {
            crate::control::notify_ready_fd(fd)?;
        }

        let loop_result = self.event_loop(
            &route_socket,
            &rule_socket,
            epoll_fd,
            timer_fd,
            signal_fd,
            &mut route_ring,
            &mut apply_scratch,
            &mut addr_scratch,
            &mut cleanup_scratch,
            &mut state,
            &mut batch_pool,
        );
        if let Err(err) = &loop_result {
            self.logger.error(
                "daemon.loop_error",
                &[("error", V::display(err)), ("phase", V::Str("event_loop"))],
            );
        }

        let cleanup_res = if state.shutdown_cleanup_done {
            Ok(state.shutdown_cleanup.removed)
        } else {
            self.cleanup_rules(
                CleanupSource::Tracked,
                &rule_socket,
                &mut apply_scratch,
                &mut cleanup_scratch,
            )
        };

        unsafe {
            libc::close(epoll_fd);
            libc::close(timer_fd);
            libc::close(signal_fd);
        }

        let cleanup_removed = cleanup_res?;
        self.logger.info_schema(
            log_schema::DAEMON_STOPPED,
            &[
                ("count_cleanup_removed", V::Usize(cleanup_removed)),
                ("count_dropped_events", V::U64(state.dropped_count)),
                ("count_cleanup_noop", V::Usize(state.shutdown_cleanup.noop)),
                (
                    "count_cleanup_failed",
                    V::Usize(state.shutdown_cleanup.failed),
                ),
            ],
        );

        loop_result
    }
}

pub(crate) fn cleanup_once(
    opts: Options,
    logger: Logger,
    source: CleanupSource,
) -> Result<(), AppError> {
    let mut daemon = Daemon::new(opts, logger)?;
    let rule_socket = NetlinkSocket::open_rule().map_err(AppError::from_required_syscall_io)?;
    let mut apply_scratch = ApplyScratch::default();
    let mut cleanup_scratch = CleanupDumpScratch::default();
    let _ = daemon.cleanup_rules(
        source,
        &rule_socket,
        &mut apply_scratch,
        &mut cleanup_scratch,
    )?;
    Ok(())
}

pub(super) fn cleanup_source_name(source: CleanupSource) -> &'static str {
    match source {
        CleanupSource::Tracked => "tracked",
        CleanupSource::Dump => "dump",
    }
}

pub(super) fn rule_action_name(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Delete => "delete",
        RuleAction::Add => "add",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_source_name_values() {
        assert_eq!(cleanup_source_name(CleanupSource::Tracked), "tracked");
        assert_eq!(cleanup_source_name(CleanupSource::Dump), "dump");
    }

    #[test]
    fn route_budget_state_scales_up_and_down() {
        let mut budget = RouteBudgetState::default();
        let base = budget.current;

        budget.update(base, true);
        budget.update(base, true);
        assert!(budget.current >= base);

        for _ in 0..8 {
            budget.update(1, false);
        }
        assert!(budget.current <= ROUTE_DRAIN_MAX_BUDGET);
        assert!(budget.current >= ROUTE_DRAIN_MIN_BUDGET);
    }
}
