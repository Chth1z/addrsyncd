use std::cell::RefCell;
use std::fmt::{self, Write as _};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::config::Options;
use crate::error::AppError;

pub(crate) type Field<'a> = (&'a str, FieldValue<'a>);

pub(crate) struct RuleBatchEvent {
    pub(crate) batch_id: u64,
    pub(crate) count_input: usize,
    pub(crate) count_add: usize,
    pub(crate) count_del: usize,
    pub(crate) count_noop: usize,
    pub(crate) count_failed: usize,
    pub(crate) duration_ms: u128,
}

pub(crate) struct RuleAckFailedEvent<'a> {
    pub(crate) batch_id: u64,
    pub(crate) seq: u32,
    pub(crate) errno: i32,
    pub(crate) op_action: &'static str,
    pub(crate) op_addr: &'a dyn fmt::Display,
    pub(crate) ext_msg: Option<&'a str>,
    pub(crate) ext_offset: Option<u32>,
}

pub(crate) struct NetlinkAddrEvent<'a> {
    pub(crate) nlmsg_type: u32,
    pub(crate) nlmsg_seq: u32,
    pub(crate) family: u32,
    pub(crate) ifindex: i32,
    pub(crate) addr: &'a dyn fmt::Display,
    pub(crate) flags: u32,
    pub(crate) op_action: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) enum FieldValue<'a> {
    Str(&'a str),
    Bool(bool),
    Usize(usize),
    U64(u64),
    U32(u32),
    I32(i32),
    U128(u128),
    Display(&'a dyn fmt::Display),
}

impl<'a> FieldValue<'a> {
    pub(crate) fn display(value: &'a dyn fmt::Display) -> Self {
        Self::Display(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
}

impl Level {
    pub(crate) fn parse(raw: &str) -> Result<Self, &'static str> {
        match raw {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            _ => Err("must be exactly one of error|warn|info|debug"),
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Self::Error => "E",
            Self::Warn => "W",
            Self::Info => "I",
            Self::Debug => "D",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LogEventSchema {
    pub(crate) event: &'static str,
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(crate) required_fields: &'static [&'static str],
}

pub(crate) mod schema {
    use super::LogEventSchema;

    pub(crate) const DAEMON_STARTED: LogEventSchema = LogEventSchema {
        event: "daemon.started",
        required_fields: &[
            "pref",
            "table_id",
            "batch_max",
            "count_cleanup_removed",
            "count_resync_add",
            "count_resync_del",
            "count_resync_failed",
        ],
    };

    pub(crate) const DAEMON_STOPPED: LogEventSchema = LogEventSchema {
        event: "daemon.stopped",
        required_fields: &["count_cleanup_removed", "count_dropped_events"],
    };

    pub(crate) const RULE_BATCH: LogEventSchema = LogEventSchema {
        event: "rule.batch",
        required_fields: &[
            "batch_id",
            "count_input",
            "count_add",
            "count_del",
            "count_noop",
            "duration_ms",
        ],
    };

    pub(crate) const RULE_ACK_FAILED: LogEventSchema = LogEventSchema {
        event: "rule.ack_failed",
        required_fields: &["batch_id", "seq", "errno", "op_action", "op_addr"],
    };

    pub(crate) const NETLINK_ADDR_EVENT: LogEventSchema = LogEventSchema {
        event: "netlink.addr_event",
        required_fields: &[
            "nlmsg_type",
            "nlmsg_seq",
            "family",
            "ifindex",
            "addr",
            "flags",
            "op_action",
        ],
    };
}

#[derive(Clone)]
pub(crate) struct Logger {
    inner: Rc<Inner>,
}

struct Inner {
    level: Level,
    writer: RefCell<BufWriter<std::fs::File>>,
    rate: RefCell<RateLimiter>,
    timestamp_cache: RefCell<TimestampCache>,
    line_buf: RefCell<String>,
    flush_state: RefCell<FlushState>,
}

#[derive(Default)]
struct TimestampCache {
    sec: libc::time_t,
    prefix: String,
}

struct FlushState {
    last_flush_at: Instant,
    buffered_bytes: usize,
}

const RATE_LIMIT_SLOTS: usize = 16;
const SOFT_FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const SOFT_FLUSH_BYTES: usize = 2 * 1024;

#[derive(Clone, Copy)]
struct RateEntry {
    key: &'static str,
    at: Instant,
}

struct RateLimiter {
    entries: [Option<RateEntry>; RATE_LIMIT_SLOTS],
    len: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            entries: [None; RATE_LIMIT_SLOTS],
            len: 0,
        }
    }
}

impl RateLimiter {
    fn should_log(&mut self, key: &'static str, interval: Duration, now: Instant) -> bool {
        for idx in 0..self.len {
            let Some(entry) = self.entries[idx] else {
                continue;
            };
            if entry.key != key {
                continue;
            }
            if now.duration_since(entry.at) < interval {
                return false;
            }
            self.entries[idx] = Some(RateEntry { key, at: now });
            return true;
        }

        if self.len < RATE_LIMIT_SLOTS {
            self.entries[self.len] = Some(RateEntry { key, at: now });
            self.len += 1;
            return true;
        }

        // Replace the oldest slot when all slots are used.
        let mut oldest_idx = 0usize;
        let mut oldest_at = self.entries[0].map(|entry| entry.at).unwrap_or(now);
        for idx in 1..RATE_LIMIT_SLOTS {
            let at = self.entries[idx].map(|entry| entry.at).unwrap_or(now);
            if at < oldest_at {
                oldest_at = at;
                oldest_idx = idx;
            }
        }
        self.entries[oldest_idx] = Some(RateEntry { key, at: now });
        true
    }
}

impl Logger {
    pub(crate) fn new(opts: &Options) -> Result<Self, AppError> {
        if let Some(parent) = opts.log_file.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                AppError::config(format!(
                    "create log dir failed ({}): {err}",
                    parent.display()
                ))
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&opts.log_file)
            .map_err(|err| {
                AppError::config(format!(
                    "open log file failed ({}): {err}",
                    opts.log_file.display()
                ))
            })?;

        Ok(Self {
            inner: Rc::new(Inner {
                level: opts.log_level,
                writer: RefCell::new(BufWriter::with_capacity(32 * 1024, file)),
                rate: RefCell::new(RateLimiter::default()),
                timestamp_cache: RefCell::new(TimestampCache::default()),
                line_buf: RefCell::new(String::with_capacity(224)),
                flush_state: RefCell::new(FlushState {
                    last_flush_at: Instant::now(),
                    buffered_bytes: 0,
                }),
            }),
        })
    }

    pub(crate) fn enabled(&self, level: Level) -> bool {
        self.inner.level >= level
    }

    pub(crate) fn warn(&self, event: &str, fields: &[Field<'_>]) {
        self.log(Level::Warn, event, fields);
    }

    pub(crate) fn error(&self, event: &str, fields: &[Field<'_>]) {
        self.log(Level::Error, event, fields);
    }

    pub(crate) fn info(&self, event: &str, fields: &[Field<'_>]) {
        self.log(Level::Info, event, fields);
    }

    pub(crate) fn debug(&self, event: &str, fields: &[Field<'_>]) {
        self.log(Level::Debug, event, fields);
    }

    pub(crate) fn warn_schema(&self, schema: LogEventSchema, fields: &[Field<'_>]) {
        self.log_schema(Level::Warn, schema, fields);
    }

    pub(crate) fn info_schema(&self, schema: LogEventSchema, fields: &[Field<'_>]) {
        self.log_schema(Level::Info, schema, fields);
    }

    pub(crate) fn debug_schema(&self, schema: LogEventSchema, fields: &[Field<'_>]) {
        self.log_schema(Level::Debug, schema, fields);
    }

    pub(crate) fn emit_rule_batch(&self, event: RuleBatchEvent) {
        self.info_schema(
            schema::RULE_BATCH,
            &[
                ("batch_id", FieldValue::U64(event.batch_id)),
                ("count_input", FieldValue::Usize(event.count_input)),
                ("count_add", FieldValue::Usize(event.count_add)),
                ("count_del", FieldValue::Usize(event.count_del)),
                ("count_noop", FieldValue::Usize(event.count_noop)),
                ("count_failed", FieldValue::Usize(event.count_failed)),
                ("duration_ms", FieldValue::U128(event.duration_ms)),
            ],
        );
    }

    pub(crate) fn emit_rule_ack_failed(&self, event: RuleAckFailedEvent<'_>) {
        let mut fields = [("", FieldValue::U32(0)); 7];
        fields[0] = ("batch_id", FieldValue::U64(event.batch_id));
        fields[1] = ("seq", FieldValue::U32(event.seq));
        fields[2] = ("errno", FieldValue::I32(event.errno));
        fields[3] = ("op_action", FieldValue::Str(event.op_action));
        fields[4] = ("op_addr", FieldValue::display(event.op_addr));
        let mut len = 5usize;

        if let Some(ext_msg) = event.ext_msg {
            fields[len] = ("ext_msg", FieldValue::Str(ext_msg));
            len += 1;
        }
        if let Some(ext_offset) = event.ext_offset {
            fields[len] = ("ext_offset", FieldValue::U32(ext_offset));
            len += 1;
        }
        self.warn_schema(schema::RULE_ACK_FAILED, &fields[..len]);
    }

    pub(crate) fn emit_netlink_addr_event(&self, event: NetlinkAddrEvent<'_>) {
        self.debug_schema(
            schema::NETLINK_ADDR_EVENT,
            &[
                ("nlmsg_type", FieldValue::U32(event.nlmsg_type)),
                ("nlmsg_seq", FieldValue::U32(event.nlmsg_seq)),
                ("family", FieldValue::U32(event.family)),
                ("ifindex", FieldValue::I32(event.ifindex)),
                ("addr", FieldValue::display(event.addr)),
                ("flags", FieldValue::U32(event.flags)),
                ("op_action", FieldValue::Str(event.op_action)),
            ],
        );
    }

    pub(crate) fn debug_every(
        &self,
        key: &'static str,
        interval: Duration,
        event: &str,
        fields: &[Field<'_>],
    ) {
        if self.should_log_now(key, interval) {
            self.debug(event, fields);
        }
    }

    pub(crate) fn info_every(
        &self,
        key: &'static str,
        interval: Duration,
        event: &str,
        fields: &[Field<'_>],
    ) {
        if self.should_log_now(key, interval) {
            self.info(event, fields);
        }
    }

    fn log_schema(&self, level: Level, schema: LogEventSchema, fields: &[Field<'_>]) {
        #[cfg(debug_assertions)]
        {
            let missing = collect_missing_required_fields(schema.required_fields, fields);
            if !missing.is_empty() {
                let missing_text = missing.join(",");
                self.log(
                    Level::Warn,
                    "logger.schema_violation",
                    &[
                        ("event", FieldValue::Str(schema.event)),
                        ("missing", FieldValue::display(&missing_text)),
                    ],
                );
            }
        }
        self.log(level, schema.event, fields);
    }

    fn should_log_now(&self, key: &'static str, interval: Duration) -> bool {
        if key.is_empty() || interval.is_zero() {
            return true;
        }
        let now = Instant::now();
        let mut rate = self.inner.rate.borrow_mut();
        rate.should_log(key, interval, now)
    }

    fn log(&self, level: Level, event: &str, fields: &[Field<'_>]) {
        if !self.enabled(level) {
            return;
        }

        let mut buf = self.inner.line_buf.borrow_mut();
        buf.clear();
        self.build_line_into(&mut buf, level, event, fields);
        let line_len = buf.len();

        let mut writer = self.inner.writer.borrow_mut();
        if let Err(err) = writer.write_all(buf.as_bytes()) {
            eprintln!("addrsyncd logger write failed: {err}");
            return;
        }
        let should_flush = level <= Level::Warn
            || self.inner.level == Level::Debug
            || self.should_soft_flush(line_len);
        if should_flush {
            if let Err(err) = writer.flush() {
                eprintln!("addrsyncd logger flush failed: {err}");
            } else {
                self.mark_flushed();
            }
        }
    }

    fn should_soft_flush(&self, appended_bytes: usize) -> bool {
        let mut state = self.inner.flush_state.borrow_mut();
        state.buffered_bytes = state.buffered_bytes.saturating_add(appended_bytes);
        let now = Instant::now();
        state.buffered_bytes >= SOFT_FLUSH_BYTES
            || now.duration_since(state.last_flush_at) >= SOFT_FLUSH_INTERVAL
    }

    fn mark_flushed(&self) {
        let mut state = self.inner.flush_state.borrow_mut();
        state.buffered_bytes = 0;
        state.last_flush_at = Instant::now();
    }

    fn build_line_into(&self, line: &mut String, level: Level, event: &str, fields: &[Field<'_>]) {
        line.push('[');
        {
            let mut cache = self.inner.timestamp_cache.borrow_mut();
            format_timestamp_into(line, &mut cache);
        }
        let _ = write!(line, "] [{}] ", level.tag());
        if event.is_empty() {
            line.push_str("log");
        } else {
            line.push_str(event);
        }

        for (key, value) in fields {
            line.push_str(" | ");
            if !append_key(line, key) {
                line.truncate(line.len().saturating_sub(3));
                continue;
            }
            line.push('=');
            append_value(line, *value);
        }
        line.push('\n');
    }
}

#[cfg(debug_assertions)]
fn collect_missing_required_fields<'a>(
    required: &'a [&'a str],
    fields: &[Field<'_>],
) -> Vec<&'a str> {
    let mut out = Vec::new();
    for required_key in required {
        if fields.iter().any(|(key, _)| key == required_key) {
            continue;
        }
        out.push(*required_key);
    }
    out
}

fn append_value(out: &mut String, value: FieldValue<'_>) {
    match value {
        FieldValue::Str(value) => append_quoted_text(out, value),
        FieldValue::Bool(value) => {
            out.push_str(if value { "true" } else { "false" });
        }
        FieldValue::Usize(value) => {
            let _ = write!(out, "{value}");
        }
        FieldValue::U64(value) => {
            let _ = write!(out, "{value}");
        }
        FieldValue::U32(value) => {
            let _ = write!(out, "{value}");
        }
        FieldValue::I32(value) => {
            let _ = write!(out, "{value}");
        }
        FieldValue::U128(value) => {
            let _ = write!(out, "{value}");
        }
        FieldValue::Display(value) => {
            let _ = write!(out, "{value}");
        }
    }
}

fn append_quoted_text(out: &mut String, value: &str) {
    if needs_quote(value) {
        out.push('"');
        let bytes = value.as_bytes();
        let mut last = 0usize;
        for (idx, &b) in bytes.iter().enumerate() {
            let escaped = match b {
                b'"' => Some("\\\""),
                b'\\' => Some("\\\\"),
                b'\n' => Some("\\n"),
                b'\r' => Some("\\r"),
                b'\t' => Some("\\t"),
                _ => None,
            };
            if let Some(escaped) = escaped {
                out.push_str(&value[last..idx]);
                out.push_str(escaped);
                last = idx + 1;
            }
        }
        out.push_str(&value[last..]);
        out.push('"');
    } else {
        out.push_str(value);
    }
}

fn needs_quote(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    value
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b == b'"' || b == b'\\')
}

fn append_key(out: &mut String, key: &str) -> bool {
    let mut wrote_any = false;
    for b in key.bytes() {
        wrote_any = true;
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' {
            out.push(char::from(b));
        } else {
            out.push('_');
        }
    }
    wrote_any
}

fn format_timestamp_into(out: &mut String, cache: &mut TimestampCache) {
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    if unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) } != 0 {
        out.push_str("1970-01-01 00:00:00.000");
        return;
    }

    let sec = tv.tv_sec as libc::time_t;
    let millis = tv.tv_usec / 1000;

    if cache.sec != sec || cache.prefix.is_empty() {
        let mut tm = MaybeUninit::<libc::tm>::uninit();
        if unsafe { libc::localtime_r(&sec, tm.as_mut_ptr()) }.is_null() {
            out.push_str("1970-01-01 00:00:00.000");
            return;
        }
        let tm = unsafe { tm.assume_init() };
        cache.prefix.clear();
        let _ = write!(
            &mut cache.prefix,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        );
        cache.sec = sec;
    }

    out.push_str(&cache.prefix);
    let _ = write!(out, ".{:03}", millis);
}

#[cfg(test)]
mod tests {
    use super::Level;

    #[test]
    fn parse_level_exact_values() {
        assert!(matches!(Level::parse("error"), Ok(Level::Error)));
        assert!(matches!(Level::parse("warn"), Ok(Level::Warn)));
        assert!(matches!(Level::parse("info"), Ok(Level::Info)));
        assert!(matches!(Level::parse("debug"), Ok(Level::Debug)));
    }

    #[test]
    fn parse_level_rejects_aliases() {
        assert!(Level::parse("err").is_err());
        assert!(Level::parse("warning").is_err());
        assert!(Level::parse("d").is_err());
        assert!(Level::parse("INFO").is_err());
    }
}
