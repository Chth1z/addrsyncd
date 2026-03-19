use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::Options;
use crate::error::AppError;

const START_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_POLL_INITIAL: Duration = Duration::from_millis(20);
const STOP_POLL_MAX: Duration = Duration::from_millis(250);

const READY_SIGNAL_ENV: &str = "ADDRSYNCD_READY_FD";
const READY_SIGNAL_BYTE: u8 = 1;

const RESYNC_SIGNAL: libc::c_int = libc::SIGUSR1;
const STOP_SIGNAL: libc::c_int = libc::SIGTERM;

#[derive(Clone, Copy, Debug)]
struct DaemonProcess {
    pid: i32,
    start_ticks: Option<u64>,
}

pub(crate) fn take_ready_fd_from_env() -> Option<libc::c_int> {
    let Ok(raw) = std::env::var(READY_SIGNAL_ENV) else {
        return None;
    };
    unsafe {
        std::env::remove_var(READY_SIGNAL_ENV);
    }
    let Ok(fd) = raw.parse::<libc::c_int>() else {
        return None;
    };
    if fd < 0 {
        return None;
    }
    Some(fd)
}

pub(crate) fn notify_ready_fd(fd: libc::c_int) -> Result<(), AppError> {
    let mut byte = READY_SIGNAL_BYTE;
    let rc = unsafe { libc::write(fd, (&mut byte as *mut u8).cast::<libc::c_void>(), 1) };
    let close_rc = unsafe { libc::close(fd) };
    if rc != 1 {
        return Err(AppError::Io(io::Error::last_os_error()));
    }
    if close_rc < 0 {
        return Err(AppError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

pub(crate) fn start_background(opts: &Options) -> Result<(), AppError> {
    let work_dir = normalize_work_dir(&opts.work_dir)?;
    if let Some(proc) = find_running_daemon_normalized(&work_dir)? {
        println!("addrsyncd already running pid={}", proc.pid);
        return Ok(());
    }

    if let Some(parent) = opts.log_file.parent() {
        fs::create_dir_all(parent)?;
    }

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&opts.log_file)?;
    let stderr = stdout.try_clone()?;

    let (ready_read_fd, ready_write_fd) = create_ready_pipe()?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("-c")
        .arg(&opts.config_path)
        .arg("-d")
        .arg(&work_dir)
        .arg("run")
        .env(READY_SIGNAL_ENV, ready_write_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            close_fd_quietly(ready_read_fd);
            close_fd_quietly(ready_write_fd);
            return Err(AppError::Io(err));
        }
    };
    close_fd_quietly(ready_write_fd);

    let ready_result = wait_child_ready_signal(&mut child, ready_read_fd, START_WAIT_TIMEOUT);
    close_fd_quietly(ready_read_fd);
    ready_result?;

    println!("addrsyncd started pid={}", child.id());
    Ok(())
}

pub(crate) fn stop_background(work_dir: &Path) -> Result<(), AppError> {
    let relative_hint = !work_dir.is_absolute();
    let work_dir = normalize_work_dir(work_dir)?;
    let Some(proc) = find_running_daemon_normalized(&work_dir)? else {
        print_not_running_message(relative_hint);
        return Ok(());
    };

    if let Err(err) = send_signal(proc.pid, STOP_SIGNAL) {
        if is_not_running_error(&err) {
            println!("addrsyncd stopped pid={}", proc.pid);
            return Ok(());
        }
        return Err(err);
    }

    let deadline = Instant::now() + STOP_WAIT_TIMEOUT;
    let mut poll_interval = STOP_POLL_INITIAL;
    while Instant::now() < deadline {
        if !is_same_process_alive(proc.pid, proc.start_ticks) {
            println!("addrsyncd stopped pid={}", proc.pid);
            return Ok(());
        }
        std::thread::sleep(poll_interval);
        poll_interval = std::cmp::min(poll_interval.saturating_mul(2), STOP_POLL_MAX);
    }

    Err(AppError::message("stop timeout"))
}

pub(crate) fn signal_resync(work_dir: &Path) -> Result<(), AppError> {
    let relative_hint = !work_dir.is_absolute();
    let work_dir = normalize_work_dir(work_dir)?;
    let Some(proc) = find_running_daemon_normalized(&work_dir)? else {
        return Err(AppError::message(not_running_message(relative_hint)));
    };

    send_signal(proc.pid, RESYNC_SIGNAL)?;
    println!("resync signal sent pid={}", proc.pid);
    Ok(())
}

pub(crate) fn print_status(config: &Path, work_dir: &Path) -> Result<(), AppError> {
    let opts = match Options::load(config, work_dir) {
        Ok(opts) => opts,
        Err(err) => {
            println!("stopped(config invalid: {err})");
            return Ok(());
        }
    };

    let work_dir = normalize_work_dir(&opts.work_dir)?;
    match find_running_daemon_normalized(&work_dir)? {
        Some(proc) => println!("running pid={}", proc.pid),
        None => println!("stopped"),
    }
    Ok(())
}

fn find_running_daemon_normalized(
    target_work_dir: &Path,
) -> Result<Option<DaemonProcess>, AppError> {
    let self_pid = unsafe { libc::getpid() };
    let proc_iter = fs::read_dir("/proc").map_err(AppError::Io)?;

    for entry in proc_iter {
        let Ok(entry) = entry else {
            continue;
        };
        let file_name = entry.file_name();
        let Some(raw_pid) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = raw_pid.parse::<i32>() else {
            continue;
        };
        if pid <= 1 || pid == self_pid {
            continue;
        }

        let Some(args) = read_cmdline_args(pid) else {
            continue;
        };
        let Some(argv0) = args.first() else {
            continue;
        };
        if !is_addrsyncd_argv0(argv0) {
            continue;
        }
        let Some(candidate_work_dir) = parse_run_work_dir(pid, &args) else {
            continue;
        };
        if candidate_work_dir != target_work_dir {
            continue;
        }
        return Ok(Some(DaemonProcess {
            pid,
            start_ticks: process_start_ticks(pid),
        }));
    }

    Ok(None)
}

fn read_cmdline_args(pid: i32) -> Option<Vec<String>> {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if cmdline.is_empty() {
        return None;
    }
    let mut args = Vec::new();
    for part in cmdline.split(|b| *b == 0) {
        if part.is_empty() {
            continue;
        }
        args.push(String::from_utf8_lossy(part).into_owned());
    }
    if args.is_empty() { None } else { Some(args) }
}

fn parse_run_work_dir(pid: i32, args: &[String]) -> Option<PathBuf> {
    let mut idx = 1usize; // skip argv[0]
    let mut work_dir = PathBuf::from(".");
    let mut saw_run = false;
    while idx < args.len() {
        match args[idx].as_str() {
            "-d" | "--work-dir" => {
                idx += 1;
                if idx >= args.len() {
                    return None;
                }
                work_dir = PathBuf::from(&args[idx]);
            }
            "-c" | "--config" => {
                idx += 1;
                if idx >= args.len() {
                    return None;
                }
            }
            "run" => {
                saw_run = true;
                break;
            }
            _ => return None,
        }
        idx += 1;
    }
    if !saw_run {
        return None;
    }
    idx += 1;
    while idx < args.len() {
        // keep parser strict: only known run flags are accepted.
        match args[idx].as_str() {
            "--daemon" => {}
            _ => return None,
        }
        idx += 1;
    }
    resolve_daemon_work_dir(pid, &work_dir)
}

fn is_addrsyncd_argv0(argv0: &str) -> bool {
    let path = Path::new(argv0);
    let Some(name) = path.file_name().and_then(|part| part.to_str()) else {
        return false;
    };
    name == "addrsyncd" || name.starts_with("addrsyncd-")
}

fn resolve_daemon_work_dir(pid: i32, raw: &Path) -> Option<PathBuf> {
    if raw.is_absolute() {
        return Some(normalize_path(raw));
    }
    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).ok()?;
    Some(normalize_path(&cwd.join(raw)))
}

fn normalize_work_dir(path: &Path) -> Result<PathBuf, AppError> {
    if path.as_os_str().is_empty() {
        return Err(AppError::config("work_dir must not be empty"));
    }

    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let canonical = fs::canonicalize(&resolved).unwrap_or(resolved);
    Ok(normalize_path(&canonical))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

fn process_start_ticks(pid: i32) -> Option<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let raw = fs::read_to_string(stat_path).ok()?;
    parse_proc_stat_start_ticks(&raw)
}

fn is_same_process_alive(pid: i32, expected_start_ticks: Option<u64>) -> bool {
    let Some(current_ticks) = process_start_ticks(pid) else {
        return false;
    };
    match expected_start_ticks {
        Some(expected) => current_ticks == expected,
        None => true,
    }
}

fn send_signal(pid: i32, signal: libc::c_int) -> Result<(), AppError> {
    let rc = unsafe { libc::kill(pid, signal) };
    if rc == 0 {
        return Ok(());
    }
    Err(AppError::Io(io::Error::last_os_error()))
}

fn is_not_running_error(err: &AppError) -> bool {
    match err {
        AppError::Io(ioe) => matches!(ioe.raw_os_error(), Some(code) if code == libc::ESRCH),
        _ => false,
    }
}

fn create_ready_pipe() -> Result<(libc::c_int, libc::c_int), AppError> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(AppError::Io(io::Error::last_os_error()));
    }
    if let Err(err) = set_cloexec(fds[0], true) {
        close_fd_quietly(fds[0]);
        close_fd_quietly(fds[1]);
        return Err(err);
    }
    if let Err(err) = set_cloexec(fds[1], false) {
        close_fd_quietly(fds[0]);
        close_fd_quietly(fds[1]);
        return Err(err);
    }
    Ok((fds[0], fds[1]))
}

fn set_cloexec(fd: libc::c_int, enabled: bool) -> Result<(), AppError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(AppError::Io(io::Error::last_os_error()));
    }
    let mut next = flags;
    if enabled {
        next |= libc::FD_CLOEXEC;
    } else {
        next &= !libc::FD_CLOEXEC;
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
        return Err(AppError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn wait_child_ready_signal(
    child: &mut std::process::Child,
    ready_read_fd: libc::c_int,
    timeout: Duration,
) -> Result<(), AppError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(AppError::message(format!(
                "daemon exited early while starting: {status}"
            )));
        }
        if !crate::kernel::wait_readable(ready_read_fd, deadline)? {
            return Err(AppError::message("start timeout"));
        }

        let mut byte = 0u8;
        let rc = unsafe { libc::read(ready_read_fd, (&mut byte as *mut u8).cast(), 1) };
        if rc == 1 {
            if byte == READY_SIGNAL_BYTE {
                return Ok(());
            }
            return Err(AppError::message(format!(
                "invalid ready signal byte: {byte}"
            )));
        }
        if rc == 0 {
            return Err(AppError::message(
                "ready pipe closed before daemon signaled ready",
            ));
        }
        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(code) if code == libc::EINTR || code == libc::EAGAIN || code == libc::EWOULDBLOCK)
        {
            continue;
        }
        return Err(AppError::Io(err));
    }
}

fn close_fd_quietly(fd: libc::c_int) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn print_not_running_message(relative_hint: bool) {
    println!("{}", not_running_message(relative_hint));
}

fn not_running_message(relative_hint: bool) -> String {
    if relative_hint {
        "addrsyncd not running (tip: use absolute --work-dir)".to_string()
    } else {
        "addrsyncd not running".to_string()
    }
}

fn parse_proc_stat_start_ticks(raw: &str) -> Option<u64> {
    // /proc/<pid>/stat field #2 (comm) is inside parentheses and may contain spaces.
    // We parse fields after ") ", where index 0 is field #3 (state).
    let after_comm = raw.rsplit_once(") ")?.1;
    let mut fields = after_comm.split_whitespace();
    // starttime is field #22, i.e. index 19 from field #3.
    fields.nth(19)?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_stat_start_ticks_handles_spaces_in_comm() {
        // field #2 contains spaces: "(a b)"
        // field #22(starttime)=123456789
        let stat = "123 (a b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456789 20";
        assert_eq!(parse_proc_stat_start_ticks(stat), Some(123456789));
    }

    #[test]
    fn parse_run_work_dir_extracts_global_d() {
        let pid = unsafe { libc::getpid() };
        let args = vec![
            "/proc/self/exe".to_string(),
            "-c".to_string(),
            "/tmp/a.toml".to_string(),
            "-d".to_string(),
            "/work".to_string(),
            "run".to_string(),
        ];
        let parsed = parse_run_work_dir(pid, &args).expect("work dir");
        assert_eq!(parsed, PathBuf::from("/work"));
    }

    #[test]
    fn parse_run_work_dir_rejects_unknown_global_option() {
        let pid = unsafe { libc::getpid() };
        let args = vec![
            "/tmp/addrsyncd".to_string(),
            "--foo".to_string(),
            "run".to_string(),
        ];
        assert!(parse_run_work_dir(pid, &args).is_none());
    }

    #[test]
    fn detect_addrsyncd_argv0() {
        assert!(is_addrsyncd_argv0("/data/adb/flux/addrsyncd"));
        assert!(is_addrsyncd_argv0("/tmp/addrsyncd-debug"));
        assert!(!is_addrsyncd_argv0("/system/bin/sh"));
    }
}
