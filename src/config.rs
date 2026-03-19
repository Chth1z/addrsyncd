use std::fs;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::error::AppError;
use crate::logger::Level;
use crate::netlink::codec::{
    IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_MANAGETEMPADDR, IFA_F_OPTIMISTIC,
    IFA_F_STABLE_PRIVACY, IFA_F_TEMPORARY, IFA_F_TENTATIVE,
};

const KNOWN_SECTIONS: &[&str] = &["daemon", "log", "rule", "filters"];

#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub(crate) work_dir: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) log_level: Level,
    pub(crate) ipv6: bool,
    pub(crate) debounce: Duration,
    pub(crate) debounce_max: Duration,
    pub(crate) batch_max: usize,
    pub(crate) log_file: PathBuf,
    pub(crate) pref: NonZeroU32,
    pub(crate) table_id: NonZeroU32,
    pub(crate) ignore_addr_flag_mask: u32,
    pub(crate) ignore_ips: Vec<IpAddr>,
    pub(crate) ignore_cidrs: Vec<(IpAddr, u8)>,
}

// ---------------------------------------------------------------------------
// Minimal TOML subset parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum TomlValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<String>),
}

/// Flat representation: section -> key -> value
type TomlTable = FxHashMap<String, FxHashMap<String, TomlValue>>;

fn parse_toml(text: &str) -> Result<TomlTable, AppError> {
    let mut table = TomlTable::default();
    let mut current_section: Option<String> = None;

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = strip_comment(raw_line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Section header
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(parse_err(line_no, "malformed section header"));
            }
            let name = line[1..line.len() - 1].trim();
            if name.is_empty() {
                return Err(parse_err(line_no, "empty section name"));
            }
            if !table.contains_key(name) {
                table.insert(name.to_string(), FxHashMap::default());
            }
            if current_section.as_deref() != Some(name) {
                current_section = Some(name.to_string());
            }
            continue;
        }

        // Key = Value
        let Some((key, val_str)) = line.split_once('=') else {
            return Err(parse_err(line_no, "expected key = value"));
        };
        let key = key.trim();
        let val_str = val_str.trim();
        if key.is_empty() {
            return Err(parse_err(line_no, "empty key"));
        }
        let section_name = current_section
            .as_deref()
            .ok_or_else(|| parse_err(line_no, "key outside of section"))?;
        if section_name.is_empty() {
            return Err(parse_err(line_no, "key outside of section"));
        }

        let value = parse_value(val_str, line_no)?;
        let Some(section) = table.get_mut(section_name) else {
            return Err(parse_err(line_no, "section not initialized"));
        };
        if section.contains_key(key) {
            return Err(parse_err(
                line_no,
                &format!("duplicate key '{key}' in [{section_name}]"),
            ));
        }
        section.insert(key.to_string(), value);
    }
    Ok(table)
}

fn strip_comment(line: &str) -> &str {
    // Strip '#' only when not inside quoted strings.
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, ch) in line.char_indices() {
        match quote {
            Some('"') => {
                if escaped {
                    escaped = false;
                    continue;
                }
                match ch {
                    '\\' => escaped = true,
                    '"' => quote = None,
                    _ => {}
                }
            }
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                }
            }
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '#' => return &line[..i],
                _ => {}
            },
            _ => {}
        }
    }
    line
}

fn parse_value(s: &str, line_no: usize) -> Result<TomlValue, AppError> {
    if s.is_empty() {
        return Err(parse_err(line_no, "empty value"));
    }

    // Boolean
    if s == "true" {
        return Ok(TomlValue::Bool(true));
    }
    if s == "false" {
        return Ok(TomlValue::Bool(false));
    }

    // Quoted string
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        if s.len() < 2 {
            return Err(parse_err(line_no, "malformed string"));
        }
        return Ok(TomlValue::Str(unescape_string(&s[1..s.len() - 1])));
    }

    // Array
    if s.starts_with('[') {
        return parse_array(s, line_no);
    }

    // Integer
    if let Ok(n) = s.parse::<i64>() {
        return Ok(TomlValue::Int(n));
    }

    Err(parse_err(line_no, &format!("cannot parse value: {s}")))
}

fn parse_array(s: &str, line_no: usize) -> Result<TomlValue, AppError> {
    if !s.ends_with(']') {
        return Err(parse_err(line_no, "unterminated array"));
    }
    let inner = s[1..s.len() - 1].trim();
    if inner.is_empty() {
        return Ok(TomlValue::Array(Vec::new()));
    }

    let mut items = Vec::new();
    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue; // trailing comma
        }
        if (part.starts_with('"') && part.ends_with('"'))
            || (part.starts_with('\'') && part.ends_with('\''))
        {
            items.push(unescape_string(&part[1..part.len() - 1]));
        } else {
            return Err(parse_err(line_no, "array elements must be quoted strings"));
        }
    }
    Ok(TomlValue::Array(items))
}

fn unescape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn parse_err(line_no: usize, msg: &str) -> AppError {
    AppError::config(format!("line {}: {msg}", line_no + 1))
}

// ---------------------------------------------------------------------------
// Config loading helpers (extract typed values from TomlTable)
// ---------------------------------------------------------------------------

fn take_str(
    section: &mut FxHashMap<String, TomlValue>,
    key: &str,
    section_name: &str,
) -> Result<String, AppError> {
    match section.remove(key) {
        Some(TomlValue::Str(s)) => Ok(s),
        Some(_) => Err(AppError::config(format!(
            "{section_name}.{key} must be a string"
        ))),
        None => Err(AppError::config(format!(
            "missing required key {section_name}.{key}"
        ))),
    }
}

fn take_u64(
    section: &mut FxHashMap<String, TomlValue>,
    key: &str,
    section_name: &str,
) -> Result<u64, AppError> {
    match section.remove(key) {
        Some(TomlValue::Int(n)) if n >= 0 => Ok(n as u64),
        Some(TomlValue::Int(_)) => Err(AppError::config(format!(
            "{section_name}.{key} must be non-negative"
        ))),
        Some(_) => Err(AppError::config(format!(
            "{section_name}.{key} must be an integer"
        ))),
        None => Err(AppError::config(format!(
            "missing required key {section_name}.{key}"
        ))),
    }
}

fn take_bool(
    section: &mut FxHashMap<String, TomlValue>,
    key: &str,
    section_name: &str,
) -> Result<bool, AppError> {
    match section.remove(key) {
        Some(TomlValue::Bool(b)) => Ok(b),
        Some(_) => Err(AppError::config(format!(
            "{section_name}.{key} must be a boolean"
        ))),
        None => Err(AppError::config(format!(
            "missing required key {section_name}.{key}"
        ))),
    }
}

fn take_array_or_default(
    section: &mut FxHashMap<String, TomlValue>,
    key: &str,
    section_name: &str,
) -> Result<Vec<String>, AppError> {
    match section.remove(key) {
        Some(TomlValue::Array(arr)) => Ok(arr),
        Some(_) => Err(AppError::config(format!(
            "{section_name}.{key} must be an array"
        ))),
        None => Ok(Vec::new()),
    }
}

fn reject_unknown_keys(
    section: &FxHashMap<String, TomlValue>,
    section_name: &str,
) -> Result<(), AppError> {
    if let Some(key) = section.keys().next() {
        return Err(AppError::config(format!(
            "unknown field `{key}` in [{section_name}]"
        )));
    }
    Ok(())
}

fn reject_unknown_keys_with_allowlist(
    section: &FxHashMap<String, TomlValue>,
    section_name: &str,
    allowlist: &[&str],
) -> Result<(), AppError> {
    if let Some(key) = section
        .keys()
        .find(|key| !allowlist.contains(&key.as_str()))
    {
        return Err(AppError::config(format!(
            "unknown field `{key}` in [{section_name}]"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Options loading
// ---------------------------------------------------------------------------

impl Options {
    pub(crate) fn load(config_path: &Path, work_dir: &Path) -> Result<Self, AppError> {
        let work_dir = sanitize_work_dir(work_dir)?;
        let resolved_cfg = resolve_relative_path(config_path, &work_dir, "config path")?;
        let text = fs::read_to_string(&resolved_cfg).map_err(|err| {
            AppError::config(format!(
                "read config failed ({}): {err}",
                resolved_cfg.display()
            ))
        })?;

        let mut table = parse_toml(&text).map_err(|err| {
            AppError::config(format!(
                "parse config failed ({}): {err}",
                resolved_cfg.display()
            ))
        })?;

        // Check for unknown sections
        for section_name in table.keys() {
            if !KNOWN_SECTIONS.contains(&section_name.as_str()) {
                return Err(AppError::config(format!(
                    "parse config failed ({}): unknown section [{section_name}]",
                    resolved_cfg.display()
                )));
            }
        }

        // [daemon]
        let mut daemon = table.remove("daemon").ok_or_else(|| {
            AppError::config(format!(
                "parse config failed ({}): missing [daemon] section",
                resolved_cfg.display()
            ))
        })?;
        reject_unknown_keys_with_allowlist(
            &daemon,
            "daemon",
            &["ipv6", "debounce_ms", "debounce_max_ms", "batch_max"],
        )?;
        let ipv6 = take_bool(&mut daemon, "ipv6", "daemon")?;
        let debounce_ms = take_u64(&mut daemon, "debounce_ms", "daemon")?;
        let debounce_max_ms = take_u64(&mut daemon, "debounce_max_ms", "daemon")?;
        let batch_max = take_u64(&mut daemon, "batch_max", "daemon")? as usize;
        reject_unknown_keys(&daemon, "daemon")?;

        // [log]
        let mut log_sec = table.remove("log").ok_or_else(|| {
            AppError::config(format!(
                "parse config failed ({}): missing [log] section",
                resolved_cfg.display()
            ))
        })?;
        reject_unknown_keys_with_allowlist(&log_sec, "log", &["level", "file"])?;
        let log_level_str = take_str(&mut log_sec, "level", "log")?;
        let log_file_str = take_str(&mut log_sec, "file", "log")?;
        reject_unknown_keys(&log_sec, "log")?;

        // [rule]
        let mut rule = table.remove("rule").ok_or_else(|| {
            AppError::config(format!(
                "parse config failed ({}): missing [rule] section",
                resolved_cfg.display()
            ))
        })?;
        reject_unknown_keys_with_allowlist(&rule, "rule", &["pref", "table_id"])?;
        let pref_raw = take_u64(&mut rule, "pref", "rule")? as u32;
        let table_id_raw = take_u64(&mut rule, "table_id", "rule")? as u32;
        reject_unknown_keys(&rule, "rule")?;

        // [filters]
        let mut filters = table.remove("filters").ok_or_else(|| {
            AppError::config(format!(
                "parse config failed ({}): missing [filters] section",
                resolved_cfg.display()
            ))
        })?;
        reject_unknown_keys_with_allowlist(
            &filters,
            "filters",
            &["ignore_addr_flags", "ignore_ips", "ignore_cidrs"],
        )?;
        let ignore_addr_flags_raw =
            take_array_or_default(&mut filters, "ignore_addr_flags", "filters")?;
        let ignore_ips_raw = take_array_or_default(&mut filters, "ignore_ips", "filters")?;
        let ignore_cidrs_raw = take_array_or_default(&mut filters, "ignore_cidrs", "filters")?;
        reject_unknown_keys(&filters, "filters")?;

        // Validate
        validate_positive(debounce_ms, "daemon.debounce_ms")?;
        validate_positive(debounce_max_ms, "daemon.debounce_max_ms")?;
        if batch_max == 0 {
            return Err(AppError::config("daemon.batch_max must be positive"));
        }

        let pref = NonZeroU32::new(pref_raw)
            .ok_or_else(|| AppError::config("rule.pref must be positive"))?;
        let table_id = NonZeroU32::new(table_id_raw)
            .ok_or_else(|| AppError::config("rule.table_id must be positive"))?;

        let log_level = Level::parse(&log_level_str)
            .map_err(|err| AppError::config(format!("log.level {err}")))?;

        let debounce = Duration::from_millis(debounce_ms);
        let debounce_max = Duration::from_millis(debounce_max_ms.max(debounce_ms));
        let log_file = resolve_relative_path(Path::new(&log_file_str), &work_dir, "log.file")?;

        let ignore_addr_flag_mask = parse_ignore_flag_mask(ignore_addr_flags_raw)?;
        let ignore_ips = parse_ip_list(ignore_ips_raw)?;
        let ignore_cidrs = parse_cidr_list(ignore_cidrs_raw)?;

        Ok(Self {
            work_dir,
            config_path: resolved_cfg,
            log_level,
            ipv6,
            debounce,
            debounce_max,
            batch_max,
            log_file,
            pref,
            table_id,
            ignore_addr_flag_mask,
            ignore_ips,
            ignore_cidrs,
        })
    }
}

fn sanitize_work_dir(path: &Path) -> Result<PathBuf, AppError> {
    if path.as_os_str().is_empty() {
        return Err(AppError::config("work_dir must not be empty"));
    }
    Ok(path.to_path_buf())
}

fn resolve_relative_path(path: &Path, base: &Path, context: &str) -> Result<PathBuf, AppError> {
    if path.as_os_str().is_empty() {
        return Err(AppError::config(format!("{context} must not be empty")));
    }
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(base.join(path))
}

fn validate_positive(value: u64, key: &str) -> Result<(), AppError> {
    if value == 0 {
        return Err(AppError::config(format!("{key} must be positive")));
    }
    Ok(())
}

fn parse_ignore_flag_mask(values: Vec<String>) -> Result<u32, AppError> {
    let mut mask = 0u32;
    let mut seen = FxHashSet::default();
    for raw in values {
        if raw.is_empty() {
            return Err(AppError::config(
                "filters.ignore_addr_flags must not contain empty value",
            ));
        }
        let bit = match raw.as_str() {
            "temporary" => IFA_F_TEMPORARY,
            "optimistic" => IFA_F_OPTIMISTIC,
            "deprecated" => IFA_F_DEPRECATED,
            "tentative" => IFA_F_TENTATIVE,
            "dadfailed" => IFA_F_DADFAILED,
            "stable_privacy" => IFA_F_STABLE_PRIVACY,
            "managetempaddr" => IFA_F_MANAGETEMPADDR,
            _ => {
                return Err(AppError::config(format!(
                    "filters.ignore_addr_flags invalid value: {raw}; must be one of temporary|optimistic|deprecated|tentative|dadfailed|stable_privacy|managetempaddr"
                )));
            }
        };
        if !seen.insert(raw.clone()) {
            return Err(AppError::config(format!(
                "filters.ignore_addr_flags duplicate value: {raw}"
            )));
        }
        mask |= bit;
    }
    Ok(mask)
}

fn parse_ip_list(values: Vec<String>) -> Result<Vec<IpAddr>, AppError> {
    let mut out = Vec::with_capacity(values.len());
    let mut seen = FxHashSet::default();
    for raw in values {
        if raw.is_empty() {
            return Err(AppError::config(
                "filters.ignore_ips must not contain empty value",
            ));
        }
        let parsed: IpAddr = raw
            .parse()
            .map_err(|_| AppError::config(format!("filters.ignore_ips invalid ip: {raw}")))?;
        if !seen.insert(parsed) {
            return Err(AppError::config(format!(
                "filters.ignore_ips duplicate ip: {raw}"
            )));
        }
        out.push(parsed);
    }
    Ok(out)
}

fn parse_cidr_list(values: Vec<String>) -> Result<Vec<(IpAddr, u8)>, AppError> {
    let mut out = Vec::with_capacity(values.len());
    let mut seen = FxHashSet::default();
    for raw in values {
        if raw.is_empty() {
            return Err(AppError::config(
                "filters.ignore_cidrs must not contain empty value",
            ));
        }
        let (addr_str, prefix_str) = raw
            .split_once('/')
            .ok_or_else(|| AppError::config(format!("filters.ignore_cidrs invalid cidr: {raw}")))?;
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|_| AppError::config(format!("filters.ignore_cidrs invalid cidr: {raw}")))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| AppError::config(format!("filters.ignore_cidrs invalid cidr: {raw}")))?;
        let max_prefix = if addr.is_ipv4() { 32u8 } else { 128u8 };
        if prefix > max_prefix {
            return Err(AppError::config(format!(
                "filters.ignore_cidrs invalid cidr: {raw}"
            )));
        }
        if !seen.insert((addr, prefix)) {
            return Err(AppError::config(format!(
                "filters.ignore_cidrs duplicate cidr: {raw}"
            )));
        }
        out.push((addr, prefix));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::tempdir;

    fn base_config() -> String {
        r#"
[daemon]
ipv6 = true
debounce_ms = 500
debounce_max_ms = 5000
batch_max = 128

[log]
level = "info"
file = "logs/addrsyncd.log"

[rule]
pref = 1900
table_id = 254

[filters]
ignore_addr_flags = ["temporary"]
ignore_ips = ["10.0.0.9"]
ignore_cidrs = ["10.0.0.0/8"]
"#
        .to_string()
    }

    #[test]
    fn load_options_success() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        fs::write(&config_path, base_config()).expect("write config");

        let opts = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect("load config");

        assert_eq!(opts.pref.get(), 1900);
        assert_eq!(opts.table_id.get(), 254);
        assert_eq!(opts.batch_max, 128);
        assert_eq!(opts.ignore_ips.len(), 1);
        assert_eq!(opts.ignore_cidrs.len(), 1);
        assert_eq!(opts.log_file, dir.path().join("logs").join("addrsyncd.log"));
    }

    #[test]
    fn load_options_supports_absolute_log_path() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let absolute_log = dir.path().join("abs.log");
        let config = base_config().replace(
            r#"file = "logs/addrsyncd.log""#,
            &format!("file = '{}'", absolute_log.display()),
        );
        fs::write(&config_path, config).expect("write config");

        let opts = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect("load config");
        assert_eq!(opts.log_file, absolute_log);
    }

    #[test]
    fn load_options_rejects_empty_log_file() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let broken = base_config().replace("file = \"logs/addrsyncd.log\"", "file = \"\"");
        fs::write(&config_path, broken).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("log.file must not be empty"));
    }

    #[test]
    fn load_options_rejects_non_cidr_in_ignore_cidrs() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let broken = base_config().replace("10.0.0.0/8", "10.0.0.9");
        fs::write(&config_path, broken).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("invalid cidr"));
    }

    #[test]
    fn load_options_missing_required_key() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let broken = base_config().replace("table_id = 254\n", "");
        fs::write(&config_path, broken).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("missing required key"));
    }

    #[test]
    fn load_options_invalid_values() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let broken = base_config().replace("debounce_ms = 500", "debounce_ms = 0");
        fs::write(&config_path, broken).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("debounce_ms must be positive"));
    }

    #[test]
    fn load_options_rejects_unknown_keys() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let mut config = base_config();
        config.push_str("\n[unknown]\nfoo = 1\n");
        fs::write(&config_path, config).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("parse config failed"));
    }

    #[test]
    fn load_options_rejects_legacy_daemon_log_fields() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let mut config = base_config();
        config = config.replace("[daemon]\n", "[daemon]\nlog_level = \"info\"\n");
        fs::write(&config_path, config).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn load_options_rejects_log_level_aliases() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let config = base_config().replace("level = \"info\"", "level = \"d\"");
        fs::write(&config_path, config).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("log.level"));
    }

    #[test]
    fn load_options_rejects_ignore_flag_aliases() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let config = base_config().replace(
            "ignore_addr_flags = [\"temporary\"]",
            "ignore_addr_flags = [\"stable-privacy\"]",
        );
        fs::write(&config_path, config).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(
            err.to_string()
                .contains("filters.ignore_addr_flags invalid value")
        );
    }

    #[test]
    fn load_options_rejects_empty_filter_values() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let config = base_config().replace(
            "ignore_addr_flags = [\"temporary\"]",
            "ignore_addr_flags = [\"\"]",
        );
        fs::write(&config_path, config).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("must not contain empty value"));
    }

    #[test]
    fn load_options_rejects_duplicate_filter_values() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let config = base_config().replace(
            "ignore_ips = [\"10.0.0.9\"]",
            "ignore_ips = [\"10.0.0.9\", \"10.0.0.9\"]",
        );
        fs::write(&config_path, config).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("duplicate ip"));
    }

    #[test]
    fn load_options_rejects_duplicate_cidr_values() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let config = base_config().replace(
            "ignore_cidrs = [\"10.0.0.0/8\"]",
            "ignore_cidrs = [\"10.0.0.0/8\", \"10.0.0.0/8\"]",
        );
        fs::write(&config_path, config).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("duplicate cidr"));
    }

    #[test]
    fn load_options_rejects_legacy_rule_table_name() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("addrsyncd.toml");
        let config = base_config().replace("table_id = 254", "table = \"main\"");
        fs::write(&config_path, config).expect("write config");

        let err = Options::load(Path::new("addrsyncd.toml"), dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("unknown field"));
        assert!(err.to_string().contains("table"));
    }

    #[test]
    fn strip_comment_keeps_hash_inside_quotes() {
        let line = r#"key = "a#b" # tail"#;
        assert_eq!(strip_comment(line).trim_end(), r#"key = "a#b""#);
    }

    #[test]
    fn strip_comment_handles_escaped_quote_in_double_quotes() {
        let line = r##"key = "a\"#b" # tail"##;
        assert_eq!(strip_comment(line).trim_end(), r##"key = "a\"#b""##);
    }
}
