#!/usr/bin/env bash
# =============================================================================
# integration_test.sh — Full pipeline integration test using mock Hub
#
# Starts mock_hub.py, runs policy_gate.py against it in each scenario,
# and asserts correct exit codes. No real Black Duck Hub required.
#
# Usage:
#   bash tests/integration_test.sh
#   bash tests/integration_test.sh --keep-server   # leave mock running
#
# Prerequisites:
#   pip install requests
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCRIPTS="${ROOT}/scripts"
MOCK_PORT="${BD_MOCK_PORT:-8889}"
BD_URL="http://localhost:${MOCK_PORT}"
BD_TOKEN="mock-token-integration-test"
MOCK_PID=""
KEEP_SERVER="${1:-}"

pass=0
fail=0

# ---------------------------------------------------------------------------
log()  { echo "[$(date -u '+%H:%M:%S')] $*"; }
ok()   { echo "  ✓ $*"; ((pass++)); }
fail() { echo "  ✗ $*"; ((fail++)); }

cleanup() {
  if [[ -n "${MOCK_PID}" && "${KEEP_SERVER}" != "--keep-server" ]]; then
    log "Stopping mock Hub (PID ${MOCK_PID})..."
    kill "${MOCK_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
start_mock() {
  local scenario="$1"
  [[ -n "${MOCK_PID}" ]] && kill "${MOCK_PID}" 2>/dev/null || true
  sleep 0.3

  BD_MOCK_SCENARIO="${scenario}" BD_MOCK_PORT="${MOCK_PORT}" \
    python3 "${SCRIPT_DIR}/mock_hub.py" &>/tmp/mock_hub.log &
  MOCK_PID=$!

  # Wait for server to be ready
  local tries=0
  until curl -sf "${BD_URL}/api/current-version" > /dev/null 2>&1; do
    sleep 0.5
    ((tries++))
    [[ ${tries} -gt 20 ]] && { log "Mock Hub failed to start"; exit 1; }
  done
  log "Mock Hub started (scenario=${scenario}, PID=${MOCK_PID})"
}

run_gate() {
  python3 "${SCRIPTS}/policy_gate.py" \
    --bd-url "${BD_URL}" \
    --bd-token "${BD_TOKEN}" \
    --project "mock-project" \
    --version "1.0.0" \
    "$@"
}

assert_exit() {
  local expected="$1"; shift
  local description="$1"; shift
  local actual=0
  run_gate "$@" > /dev/null 2>&1 || actual=$?
  if [[ "${actual}" -eq "${expected}" ]]; then
    ok "${description} (exit ${actual})"
  else
    fail "${description} — expected exit ${expected}, got ${actual}"
  fi
}

# ---------------------------------------------------------------------------
log "=== Integration Tests: policy_gate.py ==="
echo

log "--- Scenario: clean (no vulnerabilities) ---"
start_mock "clean"
assert_exit 0 "Clean scan passes on CRITICAL threshold" \
  --fail-on-severities "CRITICAL"
assert_exit 0 "Clean scan passes on CRITICAL,HIGH threshold" \
  --fail-on-severities "CRITICAL,HIGH"
assert_exit 0 "Clean scan passes with CVSS threshold" \
  --fail-on-severities "CRITICAL" --max-cvss "8.5"

echo
log "--- Scenario: violations (CRITICAL + HIGH findings) ---"
start_mock "violations"
assert_exit 1 "violations fail on CRITICAL threshold" \
  --fail-on-severities "CRITICAL"
assert_exit 1 "violations fail on CRITICAL,HIGH threshold" \
  --fail-on-severities "CRITICAL,HIGH"
assert_exit 0 "violations pass when only LOW blocked" \
  --fail-on-severities "LOW"   # Nope — violations has CRITICAL/HIGH which aren't LOW
# Actually LOW wouldn't block here because fail_on checks only listed severities
# Correct: CRITICAL findings exist but the gate is checking for LOW, not CRITICAL
# so the gate loops fail_on=["LOW"] → counts["LOW"]=0 → pass

echo
log "--- Scenario: cvss_high (CVSS 9.8, severity=HIGH) ---"
start_mock "cvss_high"
assert_exit 0 "cvss_high passes on CRITICAL-only threshold (no CRITICAL findings)" \
  --fail-on-severities "CRITICAL"
assert_exit 1 "cvss_high fails on CRITICAL,HIGH threshold" \
  --fail-on-severities "CRITICAL,HIGH"
assert_exit 1 "cvss_high fails with max-cvss=8.5" \
  --fail-on-severities "CRITICAL" --max-cvss "8.5"
assert_exit 0 "cvss_high passes with max-cvss=10.0 (score is 9.8)" \
  --fail-on-severities "CRITICAL" --max-cvss "10.0"

echo
log "--- Scenario: empty BOM ---"
start_mock "empty"
assert_exit 0 "Empty BOM passes all thresholds" \
  --fail-on-severities "CRITICAL,HIGH,MEDIUM,LOW"

# ---------------------------------------------------------------------------
echo
log "=== Results ==="
log "  Passed: ${pass}"
log "  Failed: ${fail}"
echo

if [[ ${fail} -gt 0 ]]; then
  log "INTEGRATION TESTS FAILED"
  exit 1
else
  log "ALL INTEGRATION TESTS PASSED"
  exit 0
fi
