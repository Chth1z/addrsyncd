use std::process::Command;

use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_addrsyncd")
}

#[test]
fn cli_rejects_removed_start_subcommand() {
    let output = Command::new(bin()).arg("start").output().expect("spawn");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown subcommand"));
    assert!(stderr.contains("start"));
}

#[test]
fn cli_help_contains_run_and_cleanup_modes() {
    let output = Command::new(bin()).arg("--help").output().expect("spawn");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("run"));
    assert!(stdout.contains("cleanup"));
    assert!(stdout.contains("pbr"));
    assert!(stdout.contains("-c"));
    assert!(stdout.contains("-d"));
}

#[test]
fn run_help_contains_daemon_flag() {
    let output = Command::new(bin())
        .arg("run")
        .arg("--help")
        .output()
        .expect("spawn");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--daemon"));
}

#[test]
fn cleanup_help_contains_mode_values() {
    let output = Command::new(bin())
        .arg("cleanup")
        .arg("--help")
        .output()
        .expect("spawn");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tracked"));
    assert!(stdout.contains("dump"));
}

#[test]
fn pbr_help_contains_mark_mask_options() {
    let output = Command::new(bin())
        .arg("pbr")
        .arg("--help")
        .output()
        .expect("spawn");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--mark"));
    assert!(stdout.contains("--mask"));
    assert!(stdout.contains("--table"));
    assert!(stdout.contains("--pref"));
}

#[test]
fn status_works_without_existing_config() {
    let dir = tempdir().expect("tempdir");
    let missing_cfg = dir.path().join("missing.toml");
    let output = Command::new(bin())
        .arg("-c")
        .arg(&missing_cfg)
        .arg("-d")
        .arg(dir.path())
        .arg("status")
        .output()
        .expect("spawn");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stopped"));
}

#[test]
fn status_reports_invalid_config_reason() {
    let dir = tempdir().expect("tempdir");
    let config = dir.path().join("bad.toml");
    std::fs::write(&config, "[daemon]\n").expect("write config");
    let output = Command::new(bin())
        .arg("-c")
        .arg(&config)
        .arg("-d")
        .arg(dir.path())
        .arg("status")
        .output()
        .expect("spawn");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("config invalid"));
}
