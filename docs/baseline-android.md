# Android Baseline (aarch64-linux-android)

Baseline and gate source for Android real-device runs.

## Environment

- target: `aarch64-linux-android`
- kernel contract: `>= 5.10`
- baseline env file: `docs/baseline-android.env`

## Current Gate Defaults

- MAX_CPU_TICKS_DELTA: `1000000`
- MAX_EVENT_DROP: `0`
- MAX_COMPENSATE_RESYNC: `0`

`bench_android.sh` now treats `BASELINE_CAPTURED_AT=UNSET` as placeholder and fails gate runs
until a real-device baseline is captured.

## Capture Real-Device Baseline

Run on Android target machine:

```sh
RECORD_BASELINE=1 sh ./bench_android.sh
```

This will regenerate:
- `docs/baseline-android.env`
- `docs/baseline-android.md`

## Enforced Bench Run

After baseline capture:

```sh
sh ./bench_android.sh
```

The script will load thresholds from `docs/baseline-android.env` unless overridden by env vars.
