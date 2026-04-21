# 🛡️ BlackDuck SCA — Containerized GitLab CI/CD Pipeline

> Containerized Black Duck Software Composition Analysis integrated into GitLab CI/CD with policy gates, SBOM export, and Slack/JIRA alerting.

---

## Overview

This project wraps the [Synopsys Black Duck](https://www.synopsys.com/software-integrity/security-testing/software-composition-analysis.html) SCA scanner in a reproducible Docker image and wires it into GitLab CI/CD as a reusable pipeline component. It is designed to support mature AppSec programs that need **shift-left SCA** without relying on the Detect plugin directly on runner hosts.

### Key Capabilities

| Feature | Details |
|---|---|
| **Container-first** | All scanner logic lives in a versioned Docker image — no host-level deps |
| **Policy gate** | Pipeline fails on configurable severity/CVSS thresholds |
| **SBOM export** | CycloneDX and SPDX output artifacts per build |
| **Incremental scans** | Snippet/signature detection only on changed components (optional) |
| **Multi-project** | Single image, parameterized per repo via CI/CD variables |
| **Notifications** | Slack webhook + JIRA issue creation on policy violations |

---

## Repository Structure

```
blackduck-cicd/
├── docker/
│   ├── Dockerfile                  # Black Duck Detect runner image
│   ├── entrypoint.sh               # Wrapper script with pre/post hooks
│   └── detect-config.yml           # Default Detect property overrides
├── gitlab/
│   ├── blackduck-scan.yml          # Reusable CI component (include:)
│   └── example-consumer.gitlab-ci.yml  # Consumer pipeline example
├── scripts/
│   ├── policy_gate.py              # Exit-code policy evaluator
│   ├── sbom_export.py              # CycloneDX/SPDX post-processor
│   ├── notify_slack.py             # Slack violation alerter
│   └── create_jira_issue.py        # JIRA issue creator
├── docs/
│   ├── SETUP.md                    # One-time BD Hub + GitLab setup
│   ├── VARIABLES.md                # All supported CI/CD variables
│   └── POLICY_GATE.md              # Policy gate logic reference
├── .github/
│   └── workflows/
│       └── lint.yml                # Dockerfile + script linting (GitHub Actions)
├── .gitlab-ci.yml                  # Dev/test pipeline for this repo itself
├── .hadolint.yaml                  # Hadolint config
└── README.md
```

---

## Quick Start

### 1. Build & push the scanner image

```bash
docker build -t your-registry.example.com/blackduck-detect:latest ./docker
docker push your-registry.example.com/blackduck-detect:latest
```

### 2. Configure GitLab CI/CD Variables

Set the following at the **Group** or **Project** level (masked):

| Variable | Description |
|---|---|
| `BD_URL` | Black Duck Hub URL (`https://hub.example.com`) |
| `BD_TOKEN` | Black Duck API token (masked, protected) |
| `BD_TRUST_CERT` | `true` if using self-signed cert |
| `BD_DETECT_IMAGE` | Full image ref of your built scanner image |
| `SLACK_WEBHOOK_URL` | Optional — Slack incoming webhook |
| `JIRA_URL` | Optional — JIRA base URL |
| `JIRA_TOKEN` | Optional — JIRA API token |
| `JIRA_PROJECT_KEY` | Optional — target JIRA project key |

### 3. Include the component in your pipeline

```yaml
# your-project/.gitlab-ci.yml
include:
  - project: 'security/blackduck-cicd'
    ref: main
    file: 'gitlab/blackduck-scan.yml'

stages:
  - build
  - test
  - scan
  - deploy

blackduck-sca:
  extends: .blackduck_scan
  variables:
    BD_PROJECT_NAME: "my-app"
    BD_PROJECT_VERSION: "$CI_COMMIT_REF_SLUG"
    BD_POLICY_FAIL_ON_SEVERITIES: "CRITICAL,HIGH"
```

---

## Docker Image

The image is based on `eclipse-temurin:17-jre-alpine` and bundles:

- **Synopsys Detect** (pinned version, configurable via `DETECT_VERSION` ARG)
- **Python 3** — for post-scan scripts
- `bash`, `curl`, `jq` — for shell hooks

The `entrypoint.sh` orchestrates:
1. Pre-scan validation (token ping, project name assertion)
2. `detect.sh` execution with mapped properties
3. Policy gate evaluation (`policy_gate.py`)
4. SBOM artifact export (`sbom_export.py`)
5. Conditional notifications (Slack / JIRA)

---

## Policy Gate

`scripts/policy_gate.py` reads the Black Duck risk report JSON and applies configurable thresholds:

```bash
# Exit 0 = pass, Exit 1 = policy violation
python3 policy_gate.py \
  --report-dir /tmp/blackduck/reports \
  --fail-on-severities CRITICAL,HIGH \
  --max-cvss 8.5
```

See [`docs/POLICY_GATE.md`](docs/POLICY_GATE.md) for full logic.

---

## SBOM Export

After a successful scan, `sbom_export.py` calls the Black Duck REST API to download:
- `sbom-cyclonedx.json` (CycloneDX 1.4)
- `sbom-spdx.json` (SPDX 2.3)

Both are published as GitLab job artifacts and optionally pushed to a configured artifact registry.

---

## Versioning & Tagging

| Tag | Meaning |
|---|---|
| `latest` | Tracks `main` — avoid in production |
| `vX.Y.Z` | Pinned release — use this in consumer pipelines |
| `detect-X.Y.Z` | Tied to a specific Detect release |

---

## Contributing

1. Branch off `main`
2. Run `make lint` before opening an MR
3. Update `docs/VARIABLES.md` for any new CI variable
4. Tag releases with semantic versioning

---

## License

MIT — see [LICENSE](LICENSE).
# BlackDuck_SCA_CICD
