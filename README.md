# addrsyncd-rs

`addrsyncd-rs` is a Linux/Android address-to-rule sync daemon (optimized for Android arm64).

## Scope

- Platform: Linux / Android only
- Kernel contract: `>= 5.10`
- Runtime: single reactor (`epoll + timerfd + signalfd + netlink`)
- Control plane: signal-based (`SIGUSR1=resync`, `SIGTERM=stop`) + ready-pipe startup handshake
- No pid file management
- No unix control socket

Operational requirement:

- `run` / `cleanup` require netlink privileges (typically root / CAP_NET_ADMIN)

## Toolchain

- Toolchain pin: `rust-toolchain.toml` (`stable`, with `rustfmt` and `clippy`)
- Minimum Rust version: `rust-version = 1.93` (see `Cargo.toml`)

```bash
rustup update stable
rustc --version
```

## Build

Android cross build requires Android NDK clang linker in `PATH`:

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
```

```bash
rustup target add aarch64-linux-android
cargo build --release --target aarch64-linux-android
```

Checks:

```bash
cargo check --target aarch64-linux-android --all-targets
cargo clippy --target aarch64-linux-android --all-targets -- -D warnings
cargo test --target aarch64-linux-android --no-run
```

## CLI

```bash
addrsyncd [-c <config>] [-d <work-dir>] run [--daemon]
addrsyncd [-d <work-dir>] stop
addrsyncd [-d <work-dir>] resync
addrsyncd [-c <config>] [-d <work-dir>] cleanup [--mode tracked|dump]
addrsyncd [-d <work-dir>] status
```

Defaults:

- `-c/--config`: `addrsyncd.toml`
- `-d/--work-dir`: `.`
- `cleanup --mode`: `dump`

Semantics:

- `stop`: triggers tracked cleanup
- `cleanup --mode tracked`: cleanup by in-memory tracked set
- `cleanup --mode dump`: cleanup by kernel dump scan
- `status` output is one of:
  - `running pid=...`
  - `stopped`
  - `stopped(config invalid: ...)`

Notes:

- `start` subcommand is removed
- `resync/stop/status` target discovery scans `/proc`, strictly matches `addrsyncd*` in `run` mode, and validates `pid + /proc/<pid>/stat start_ticks` to reduce PID reuse mis-targeting

## Config

Reference template: `addrsyncd.toml`.

Supported sections:

- `[log]`: `level`, `file`
- `[daemon]`: `ipv6`, `debounce_ms`, `debounce_max_ms`, `batch_max`
- `[rule]`: `pref`, `table_id`
- `[filters]`: `ignore_addr_flags`, `ignore_ips`, `ignore_cidrs`

Strict schema behavior:

- unknown section/key => error
- no alias / abbreviation compatibility
- `log.level` must be exactly `error|warn|info|debug`
- `ignore_cidrs` must be CIDR (plain IP is invalid)
- `ignore_*` lists reject empty and duplicate values

Path behavior:

- `log.file` absolute path: used as-is
- `log.file` relative path: resolved against `--work-dir`
- `--work-dir` relative path is resolved from the caller current directory; for stable lifecycle control, prefer absolute `--work-dir`

## Logging

Text-only:

```text
[YYYY-MM-DD HH:MM:SS.mmm] [E|W|I|D] event | key=value | ...
```

Level policy:

- `E`: unrecoverable failures
- `W`: recoverable failures / degraded path
- `I`: lifecycle and summaries
- `D`: diagnostics

Flush policy (realtime / power balance):

- `warn/error`: immediate flush
- decision follows configured `log.level`
- `log.level=debug`: every log line flushes immediately
- `log.level=info`: `info` lines use soft flush trigger (`~500ms` or `~2KB`)

Common diagnostic events:

- `rule.op`
- `rule.ack_failed`
- `netlink.addr_event`

## Android Scripts

`bench_android.sh` captures resource deltas and enforces thresholds:

```bash
ADDRSYNCD_BIN=/data/local/tmp/addrsyncd \
WORK_DIR=/data/local/tmp \
CONFIG_FILE=/data/local/tmp/addrsyncd.toml \
sh ./bench_android.sh
```

The benchmark expects daemon status `running` before sampling.

Default thresholds come from `docs/baseline-android.env`.
If `BASELINE_CAPTURED_AT=UNSET`, the benchmark gate fails fast.

Record baseline on device:

```bash
RECORD_BASELINE=1 sh ./bench_android.sh
```

## E2E Test (Ignored by Default)

```bash
ADDRSYNCD_E2E=1 cargo test --target aarch64-linux-android --test daemon_lifecycle_tests -- --ignored
```

Requires Linux/Android runtime with root/netlink permissions.
