#!/usr/bin/env bash
# ==============================================================================
# entrypoint.sh — BlackDuck SCA Container Orchestrator
# ==============================================================================
# Exit codes:
#   0  — Scan passed all policy gates
#   1  — Policy violation (vuln severity / CVSS threshold exceeded)
#   2  — Infrastructure / configuration error (not a scan result)
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

# ── Logging ────────────────────────────────────────────────────────────────────
log()  { echo "[$(date -u +%FT%TZ)] [INFO]  $*"; }
warn() { echo "[$(date -u +%FT%TZ)] [WARN]  $*" >&2; }
err()  { echo "[$(date -u +%FT%TZ)] [ERROR] $*" >&2; }
die()  { err "$*"; exit 2; }

# ── Required variable validation ───────────────────────────────────────────────
: "${BD_URL:?BD_URL is required (e.g. https://hub.example.com)}"
: "${BD_TOKEN:?BD_TOKEN is required — must be a valid Black Duck API token}"
: "${BD_PROJECT_NAME:?BD_PROJECT_NAME is required}"
: "${BD_PROJECT_VERSION:?BD_PROJECT_VERSION is required}"

# ── Defaults for optional variables ────────────────────────────────────────────
BD_TRUST_CERT="${BD_TRUST_CERT:-false}"
BD_POLICY_FAIL_ON_SEVERITIES="${BD_POLICY_FAIL_ON_SEVERITIES:-CRITICAL,HIGH}"
BD_MAX_CVSS="${BD_MAX_CVSS:-}"
BD_DETECT_ADDITIONAL_ARGS="${BD_DETECT_ADDITIONAL_ARGS:-}"
REPORT_DIR="${REPORT_DIR:-/tmp/blackduck/reports}"
SBOM_OUTPUT_DIR="${SBOM_OUTPUT_DIR:-/tmp/blackduck/sbom}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
JIRA_URL="${JIRA_URL:-}"
JIRA_TOKEN="${JIRA_TOKEN:-}"
JIRA_PROJECT_KEY="${JIRA_PROJECT_KEY:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts"
VIOLATIONS_FILE="${REPORT_DIR}/violations.json"

# ── Step 0: Pre-flight checks ──────────────────────────────────────────────────
log "============================================================"
log "  BlackDuck SCA — Starting pipeline scan"
log "  Project : ${BD_PROJECT_NAME}"
log "  Version : ${BD_PROJECT_VERSION}"
log "  Hub URL : ${BD_URL}"
log "============================================================"

log "Verifying Black Duck Hub connectivity..."
HTTP_STATUS=$(curl \
  --silent \
  --output /dev/null \
  --write-out "%{http_code}" \
  --max-time 15 \
  --header "Authorization: Bearer ${BD_TOKEN}" \
  "${BD_URL}/api/current-version" || true)

if [[ "${HTTP_STATUS}" != "200" ]]; then
  die "Cannot reach Black Duck Hub at ${BD_URL} (HTTP ${HTTP_STATUS}). Check BD_URL and BD_TOKEN."
fi
log "Hub connectivity confirmed (HTTP 200)."

mkdir -p "${REPORT_DIR}" "${SBOM_OUTPUT_DIR}"

# ── Step 1: Run Synopsys Detect ────────────────────────────────────────────────
log "------------------------------------------------------------"
log "Step 1/5: Running Synopsys Detect..."
log "------------------------------------------------------------"

TRUST_CERT_FLAG=""
if [[ "${BD_TRUST_CERT}" == "true" ]]; then
  TRUST_CERT_FLAG="--blackduck.trust.cert=true"
  warn "Certificate verification is disabled (BD_TRUST_CERT=true). Not recommended for production."
fi

# shellcheck disable=SC2086
bash /opt/detect/detect.sh \
  --blackduck.url="${BD_URL}" \
  --blackduck.api.token="${BD_TOKEN}" \
  --detect.project.name="${BD_PROJECT_NAME}" \
  --detect.project.version.name="${BD_PROJECT_VERSION}" \
  --detect.output.path="${REPORT_DIR}" \
  --detect.risk.report.pdf=false \
  --detect.notices.report=false \
  ${TRUST_CERT_FLAG} \
  ${BD_DETECT_ADDITIONAL_ARGS} \
|| {
  DETECT_EXIT=$?
  # Detect exits 3 for policy violations — we handle those ourselves below
  if [[ ${DETECT_EXIT} -ne 3 ]]; then
    die "Synopsys Detect failed with exit code ${DETECT_EXIT} (infrastructure/config error)."
  fi
  log "Detect exited with code 3 (policy violation) — continuing to policy gate evaluation."
}

log "Detect execution complete."

# ── Step 2: Policy Gate ────────────────────────────────────────────────────────
log "------------------------------------------------------------"
log "Step 2/5: Evaluating policy gate..."
log "------------------------------------------------------------"

POLICY_ARGS=(
  "--report-dir"       "${REPORT_DIR}"
  "--fail-on-severities" "${BD_POLICY_FAIL_ON_SEVERITIES}"
  "--violations-out"   "${VIOLATIONS_FILE}"
)
[[ -n "${BD_MAX_CVSS}" ]] && POLICY_ARGS+=("--max-cvss" "${BD_MAX_CVSS}")

POLICY_EXIT=0
python3 "${SCRIPT_DIR}/policy_gate.py" "${POLICY_ARGS[@]}" || POLICY_EXIT=$?

if [[ ${POLICY_EXIT} -eq 2 ]]; then
  die "Policy gate script encountered an infrastructure error (exit 2). Check report directory."
fi

# ── Step 3: SBOM Export ────────────────────────────────────────────────────────
log "------------------------------------------------------------"
log "Step 3/5: Exporting SBOMs..."
log "------------------------------------------------------------"

python3 "${SCRIPT_DIR}/sbom_export.py" \
  --bd-url        "${BD_URL}" \
  --bd-token      "${BD_TOKEN}" \
  --project-name  "${BD_PROJECT_NAME}" \
  --project-version "${BD_PROJECT_VERSION}" \
  --output-dir    "${SBOM_OUTPUT_DIR}" \
|| warn "SBOM export encountered an error — continuing pipeline."

log "SBOMs written to ${SBOM_OUTPUT_DIR}."

# ── Step 4: Alerts (only on policy violation) ──────────────────────────────────
if [[ ${POLICY_EXIT} -eq 1 ]]; then
  log "------------------------------------------------------------"
  log "Step 4/5: Sending violation alerts..."
  log "------------------------------------------------------------"

  if [[ -n "${SLACK_WEBHOOK_URL}" ]]; then
    log "Sending Slack notification..."
    python3 "${SCRIPT_DIR}/notify_slack.py" \
      --webhook-url     "${SLACK_WEBHOOK_URL}" \
      --violations-file "${VIOLATIONS_FILE}" \
      --project         "${BD_PROJECT_NAME}" \
      --version         "${BD_PROJECT_VERSION}" \
      --bd-url          "${BD_URL}" \
      --pipeline-url    "${CI_PIPELINE_URL:-}" \
    || warn "Slack notification failed — non-fatal."
  fi

  if [[ -n "${JIRA_URL}" && -n "${JIRA_TOKEN}" && -n "${JIRA_PROJECT_KEY}" ]]; then
    log "Creating JIRA issues..."
    python3 "${SCRIPT_DIR}/create_jira_issue.py" \
      --jira-url        "${JIRA_URL}" \
      --jira-token      "${JIRA_TOKEN}" \
      --project-key     "${JIRA_PROJECT_KEY}" \
      --violations-file "${VIOLATIONS_FILE}" \
      --project         "${BD_PROJECT_NAME}" \
      --version         "${BD_PROJECT_VERSION}" \
    || warn "JIRA issue creation failed — non-fatal."
  fi
else
  log "Step 4/5: No violations — skipping alerts."
fi

# ── Step 5: Summary ────────────────────────────────────────────────────────────
log "------------------------------------------------------------"
log "Step 5/5: Scan complete."
log "------------------------------------------------------------"

if [[ ${POLICY_EXIT} -eq 1 ]]; then
  err "RESULT: POLICY GATE FAILED — one or more vulnerabilities exceeded configured thresholds."
  err "Review ${VIOLATIONS_FILE} for details."
  exit 1
fi

log "RESULT: POLICY GATE PASSED — no violations found."
exit 0
