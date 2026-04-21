#!/usr/bin/env bash
# =============================================================================
# entrypoint.sh — Black Duck Detect orchestrator
#
# Stages:
#   1. Pre-flight validation
#   2. Detect execution
#   3. Policy gate
#   4. SBOM export
#   5. Notifications
# =============================================================================
set -euo pipefail

SCRIPTS_DIR="/opt/blackduck/scripts"
DETECT_SH="/opt/blackduck/detect/detect.sh"
REPORT_DIR="${DETECT_OUTPUT_PATH}/runs"

# --------------------------------------------------------------------------
# Logging helpers
# --------------------------------------------------------------------------
log()  { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [INFO]  $*"; }
warn() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [WARN]  $*" >&2; }
die()  { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [ERROR] $*" >&2; exit 1; }

# --------------------------------------------------------------------------
# 1. Pre-flight validation
# --------------------------------------------------------------------------
log "=== PRE-FLIGHT ==="

[[ -z "${BD_URL:-}"   ]] && die "BD_URL is required"
[[ -z "${BD_TOKEN:-}" ]] && die "BD_TOKEN is required (masked CI/CD variable)"
[[ -z "${BD_PROJECT_NAME:-}" ]] && die "BD_PROJECT_NAME is required"
[[ -z "${BD_PROJECT_VERSION:-}" ]] && BD_PROJECT_VERSION="unspecified"

log "Hub URL          : ${BD_URL}"
log "Project          : ${BD_PROJECT_NAME}"
log "Version          : ${BD_PROJECT_VERSION}"
log "Detect version   : ${DETECT_VERSION}"
log "Fail severities  : ${BD_POLICY_FAIL_ON_SEVERITIES:-CRITICAL}"

# Connectivity check
log "Pinging Black Duck Hub..."
HTTP_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: token ${BD_TOKEN}" \
  "${BD_URL}/api/current-version" || echo "000")

if [[ "${HTTP_STATUS}" != "200" ]]; then
  die "Cannot reach Black Duck Hub at ${BD_URL} (HTTP ${HTTP_STATUS}). Check BD_URL and BD_TOKEN."
fi
log "Hub reachable (HTTP 200)."

# --------------------------------------------------------------------------
# 2. Detect execution
# --------------------------------------------------------------------------
log "=== DETECT SCAN ==="

DETECT_ARGS=(
  "--blackduck.url=${BD_URL}"
  "--blackduck.api.token=${BD_TOKEN}"
  "--blackduck.trust.cert=${BD_TRUST_CERT:-false}"
  "--detect.project.name=${BD_PROJECT_NAME}"
  "--detect.project.version.name=${BD_PROJECT_VERSION}"
  "--detect.output.path=${DETECT_OUTPUT_PATH}"
  "--detect.scan.output.path=${DETECT_SCAN_OUTPUT_PATH}"
  "--detect.risk.report.pdf=true"
  "--detect.notices.report=true"
  "--detect.cleanup=false"
)

# Optional: SBOM generation via Detect
if [[ "${BD_GENERATE_SBOM:-true}" == "true" ]]; then
  DETECT_ARGS+=("--detect.blackduck.signature.scanner.arguments=--generate-bdio")
fi

# Optional: snippet matching (slower, more thorough)
if [[ "${BD_SNIPPET_MATCHING:-false}" == "true" ]]; then
  DETECT_ARGS+=("--detect.blackduck.signature.scanner.snippet.matching=true")
fi

# Optional: detectors override
if [[ -n "${BD_DETECTORS:-}" ]]; then
  DETECT_ARGS+=("--detect.included.detector.types=${BD_DETECTORS}")
fi

# Optional: source path override (default = current WORKDIR)
DETECT_ARGS+=("--detect.source.path=${BD_SOURCE_PATH:-/workspace}")

log "Running: ${DETECT_SH} ${DETECT_ARGS[*]//${BD_TOKEN}/***}"

SCAN_EXIT=0
bash "${DETECT_SH}" "${DETECT_ARGS[@]}" || SCAN_EXIT=$?

if [[ ${SCAN_EXIT} -eq 3 ]]; then
  warn "Detect exit code 3 — policy violation detected by Detect itself."
elif [[ ${SCAN_EXIT} -ne 0 ]]; then
  die "Detect exited with code ${SCAN_EXIT}. Check scan logs above."
fi

log "Detect scan complete."

# --------------------------------------------------------------------------
# 3. Policy gate
# --------------------------------------------------------------------------
log "=== POLICY GATE ==="

GATE_ARGS=(
  "--bd-url" "${BD_URL}"
  "--bd-token" "${BD_TOKEN}"
  "--project" "${BD_PROJECT_NAME}"
  "--version" "${BD_PROJECT_VERSION}"
  "--fail-on-severities" "${BD_POLICY_FAIL_ON_SEVERITIES:-CRITICAL}"
)

[[ -n "${BD_MAX_CVSS:-}" ]] && GATE_ARGS+=("--max-cvss" "${BD_MAX_CVSS}")
[[ "${BD_TRUST_CERT:-false}" == "true" ]] && GATE_ARGS+=("--insecure")

GATE_EXIT=0
python3 "${SCRIPTS_DIR}/policy_gate.py" "${GATE_ARGS[@]}" || GATE_EXIT=$?

# --------------------------------------------------------------------------
# 4. SBOM export (always runs, even on gate failure)
# --------------------------------------------------------------------------
log "=== SBOM EXPORT ==="

python3 "${SCRIPTS_DIR}/sbom_export.py" \
  --bd-url "${BD_URL}" \
  --bd-token "${BD_TOKEN}" \
  --project "${BD_PROJECT_NAME}" \
  --version "${BD_PROJECT_VERSION}" \
  --output-dir "${DETECT_OUTPUT_PATH}/sbom" \
  ${BD_TRUST_CERT:+--insecure} || warn "SBOM export failed (non-fatal)"

# --------------------------------------------------------------------------
# 5. Notifications (only on policy violation)
# --------------------------------------------------------------------------
if [[ ${GATE_EXIT} -ne 0 ]]; then
  log "=== NOTIFICATIONS ==="

  if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    python3 "${SCRIPTS_DIR}/notify_slack.py" \
      --webhook-url "${SLACK_WEBHOOK_URL}" \
      --project "${BD_PROJECT_NAME}" \
      --version "${BD_PROJECT_VERSION}" \
      --bd-url "${BD_URL}" \
      --severities "${BD_POLICY_FAIL_ON_SEVERITIES:-CRITICAL}" || warn "Slack notification failed"
  fi

  if [[ -n "${JIRA_URL:-}" && -n "${JIRA_TOKEN:-}" && -n "${JIRA_PROJECT_KEY:-}" ]]; then
    python3 "${SCRIPTS_DIR}/create_jira_issue.py" \
      --jira-url "${JIRA_URL}" \
      --jira-token "${JIRA_TOKEN}" \
      --project-key "${JIRA_PROJECT_KEY}" \
      --bd-project "${BD_PROJECT_NAME}" \
      --bd-version "${BD_PROJECT_VERSION}" \
      --bd-url "${BD_URL}" || warn "JIRA issue creation failed"
  fi

  die "Policy gate FAILED for ${BD_PROJECT_NAME}@${BD_PROJECT_VERSION}. Review violations in Black Duck Hub."
fi

log "=== SCAN COMPLETE — all policies passed ==="
