#!/system/bin/sh

set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ADDRSYNCD_BIN="${ADDRSYNCD_BIN:-${SCRIPT_DIR}/addrsyncd}"
WORK_DIR="${WORK_DIR:-${SCRIPT_DIR}}"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/addrsyncd.toml}"
LOG_FILE="${LOG_FILE:-${WORK_DIR}/addrsyncd.log}"
START_TIMEOUT_SEC="${START_TIMEOUT_SEC:-10}"
STOP_TIMEOUT_SEC="${STOP_TIMEOUT_SEC:-10}"
RESET_LOG="${RESET_LOG:-1}"

fail() {
    echo "test_failed: $*" >&2
    exit 1
}

run_cmd() {
    echo ">> $*"
    "$@"
}

require_runtime() {
    [ -x "${ADDRSYNCD_BIN}" ] || fail "binary not executable: ${ADDRSYNCD_BIN}"
    [ -f "${CONFIG_FILE}" ] || fail "config not found: ${CONFIG_FILE}"
    mkdir -p "${WORK_DIR}" 2>/dev/null || true
}

print_binary_meta() {
    version="$("${ADDRSYNCD_BIN}" --version 2>/dev/null || true)"
    if command -v sha256sum >/dev/null 2>&1; then
        digest="$(sha256sum "${ADDRSYNCD_BIN}" | awk '{print $1}')"
    else
        digest="unknown"
    fi
    echo "binary_meta version=${version:-unknown} sha256=${digest}"
}

status_text() {
    "${ADDRSYNCD_BIN}" -c "${CONFIG_FILE}" -d "${WORK_DIR}" status 2>&1 || true
}

wait_running() {
    timeout="${1}"
    i=0
    while [ "${i}" -lt "${timeout}" ]; do
        s="$(status_text)"
        echo "status=${s}"
        echo "${s}" | grep -q '^running pid=' && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

wait_stopped() {
    timeout="${1}"
    i=0
    while [ "${i}" -lt "${timeout}" ]; do
        s="$(status_text)"
        echo "status=${s}"
        echo "${s}" | grep -q '^stopped$' && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

assert_log_contains() {
    needle="$1"
    [ -f "${LOG_FILE}" ] || fail "log file not found: ${LOG_FILE}"
    if ! grep -q "${needle}" "${LOG_FILE}"; then
        fail "log missing pattern: ${needle}"
    fi
}

main() {
    require_runtime
    print_binary_meta

    if [ "${RESET_LOG}" = "1" ]; then
        rm -f "${LOG_FILE}" 2>/dev/null || true
    fi

    run_cmd "${ADDRSYNCD_BIN}" -c "${CONFIG_FILE}" -d "${WORK_DIR}" stop >/dev/null 2>&1 || true
    run_cmd "${ADDRSYNCD_BIN}" -c "${CONFIG_FILE}" -d "${WORK_DIR}" cleanup --mode dump >/dev/null 2>&1 || true

    run_cmd "${ADDRSYNCD_BIN}" -c "${CONFIG_FILE}" -d "${WORK_DIR}" run --daemon
    wait_running "${START_TIMEOUT_SEC}" || fail "start timeout"

    run_cmd "${ADDRSYNCD_BIN}" -c "${CONFIG_FILE}" -d "${WORK_DIR}" resync
    sleep 1
    wait_running 2 || fail "daemon is not running after resync"

    run_cmd "${ADDRSYNCD_BIN}" -c "${CONFIG_FILE}" -d "${WORK_DIR}" stop
    wait_stopped "${STOP_TIMEOUT_SEC}" || fail "stop timeout"

    run_cmd "${ADDRSYNCD_BIN}" -c "${CONFIG_FILE}" -d "${WORK_DIR}" cleanup --mode tracked
    run_cmd "${ADDRSYNCD_BIN}" -c "${CONFIG_FILE}" -d "${WORK_DIR}" cleanup --mode dump

    assert_log_contains "daemon.started"
    assert_log_contains "daemon.resync"
    assert_log_contains "daemon.stopped"
    assert_log_contains "cleanup.result"

    echo "test_passed: lifecycle + cleanup + log assertions"
}

main "$@"
