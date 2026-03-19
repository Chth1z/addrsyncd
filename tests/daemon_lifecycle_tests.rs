use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_addrsyncd")
}

fn run_cmd(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("spawn")
}

fn write_config(config_path: &Path) {
    let content = r#"
[daemon]
ipv6 = true
debounce_ms = 50
debounce_max_ms = 500
batch_max = 64

[log]
level = "debug"
file = "addrsyncd.log"

[rule]
pref = 1900
table_id = 254

[filters]
ignore_addr_flags = []
ignore_ips = []
ignore_cidrs = []
"#;
    std::fs::write(config_path, content).expect("write config");
}

fn wait_status(config: &Path, work_dir: &Path, want_prefix: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let output = Command::new(bin())
            .arg("-c")
            .arg(config)
            .arg("-d")
            .arg(work_dir)
            .arg("status")
            .output()
            .expect("spawn status");
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.starts_with(want_prefix) {
            return stdout;
        }
        if Instant::now() >= deadline {
            return stdout;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
#[ignore = "requires Android/Linux root + NETLINK_ROUTE; run with ADDRSYNCD_E2E=1 cargo test -- --ignored"]
fn daemon_lifecycle_run_status_resync_stop_cleanup() {
    assert_eq!(
        std::env::var("ADDRSYNCD_E2E").ok().as_deref(),
        Some("1"),
        "set ADDRSYNCD_E2E=1 to run lifecycle e2e test"
    );
    assert_eq!(unsafe { libc::geteuid() }, 0, "lifecycle e2e requires root");

    let dir = tempdir().expect("tempdir");
    let work_dir = dir.path();
    let config_path = work_dir.join("addrsyncd.toml");
    write_config(&config_path);

    let start = run_cmd(&[
        "-c",
        config_path.to_str().expect("config path"),
        "-d",
        work_dir.to_str().expect("work dir"),
        "run",
        "--daemon",
    ]);
    assert!(
        start.status.success(),
        "start failed: stdout={} stderr={}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr)
    );

    let running = wait_status(
        &config_path,
        work_dir,
        "running pid=",
        Duration::from_secs(10),
    );
    assert!(
        running.starts_with("running pid="),
        "daemon did not enter running state, status={running}"
    );

    let resync = run_cmd(&[
        "-c",
        config_path.to_str().expect("config path"),
        "-d",
        work_dir.to_str().expect("work dir"),
        "resync",
    ]);
    assert!(
        resync.status.success(),
        "resync failed: stdout={} stderr={}",
        String::from_utf8_lossy(&resync.stdout),
        String::from_utf8_lossy(&resync.stderr)
    );

    let stop = run_cmd(&[
        "-c",
        config_path.to_str().expect("config path"),
        "-d",
        work_dir.to_str().expect("work dir"),
        "stop",
    ]);
    assert!(
        stop.status.success(),
        "stop failed: stdout={} stderr={}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );

    let stopped = wait_status(&config_path, work_dir, "stopped", Duration::from_secs(10));
    assert!(
        stopped.starts_with("stopped"),
        "daemon did not stop cleanly, status={stopped}"
    );

    let cleanup_tracked = run_cmd(&[
        "-c",
        config_path.to_str().expect("config path"),
        "-d",
        work_dir.to_str().expect("work dir"),
        "cleanup",
        "--mode",
        "tracked",
    ]);
    assert!(
        cleanup_tracked.status.success(),
        "cleanup tracked failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cleanup_tracked.stdout),
        String::from_utf8_lossy(&cleanup_tracked.stderr)
    );

    let cleanup_dump = run_cmd(&[
        "-c",
        config_path.to_str().expect("config path"),
        "-d",
        work_dir.to_str().expect("work dir"),
        "cleanup",
        "--mode",
        "dump",
    ]);
    assert!(
        cleanup_dump.status.success(),
        "cleanup dump failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cleanup_dump.stdout),
        String::from_utf8_lossy(&cleanup_dump.stderr)
    );
}
