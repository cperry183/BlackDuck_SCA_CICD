# CI/CD Variables Reference

All variables can be set at the GitLab **Group**, **Project**, or **Job** level.
Variables marked **Required** must be set for the scan to run.

## Core Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `BD_URL` | ✅ | — | Black Duck Hub base URL (e.g., `https://hub.example.com`) |
| `BD_TOKEN` | ✅ | — | Black Duck API token. **Mask this variable.** |
| `BD_DETECT_IMAGE` | ✅ | — | Full image reference of the built scanner image |
| `BD_PROJECT_NAME` | ✅ | `$CI_PROJECT_NAME` | Black Duck project name |
| `BD_PROJECT_VERSION` | — | `$CI_COMMIT_REF_SLUG` | Black Duck project version string |
| `BD_TRUST_CERT` | — | `false` | Set `true` to skip TLS certificate verification |

## Policy Gate Variables

| Variable | Default | Description |
|---|---|---|
| `BD_POLICY_FAIL_ON_SEVERITIES` | `CRITICAL` | Comma-separated severities that fail the gate (`CRITICAL,HIGH,MEDIUM,LOW`) |
| `BD_MAX_CVSS` | *(unset)* | Fail if any vulnerability has CVSS ≥ this value (e.g., `8.5`) |

## Scanner Behavior Variables

| Variable | Default | Description |
|---|---|---|
| `BD_SNIPPET_MATCHING` | `false` | Enable snippet-level matching (slower, more thorough) |
| `BD_GENERATE_SBOM` | `true` | Generate SBOM output (CycloneDX + SPDX) |
| `BD_DETECTORS` | *(auto)* | Comma-separated Detect detector types to include (e.g., `GRADLE,NPM`) |
| `BD_SOURCE_PATH` | `$CI_PROJECT_DIR` | Path to scan (defaults to checked-out repo) |

## Notification Variables (Optional)

| Variable | Description |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL. If set, violations post an alert. **Mask this.** |
| `JIRA_URL` | JIRA base URL (e.g., `https://jira.example.com`) |
| `JIRA_TOKEN` | JIRA API token (Bearer). **Mask this.** |
| `JIRA_PROJECT_KEY` | JIRA project key to create issues in (e.g., `SEC`) |

## Pipeline Control Variables

| Variable | Default | Description |
|---|---|---|
| `BD_FORCE_SCAN` | `false` | Set `true` to trigger scan on any branch |
| `BD_SKIP_SCAN` | `false` | Set `true` to skip scan entirely (use for hotfix branches, etc.) |
