<div align="center">
  <img src="https://img.shields.io/badge/Security-BlackDuck_SCA-blue?style=for-the-badge&logo=security" alt="BlackDuck SCA" />
  <img src="https://img.shields.io/badge/CI%2FCD-GitLab-orange?style=for-the-badge&logo=gitlab" alt="GitLab CI/CD" />
  <img src="https://img.shields.io/badge/Container-Docker-2496ED?style=for-the-badge&logo=docker" alt="Docker" />
  <img src="https://img.shields.io/badge/Language-Python_3-3776AB?style=for-the-badge&logo=python" alt="Python 3" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License" />
</div>

<h1 align="center">🛡️ BlackDuck SCA — Containerized GitLab CI/CD Pipeline</h1>

<p align="center">
  <strong>A robust, containerized Synopsys Black Duck Software Composition Analysis (SCA) integration for GitLab CI/CD, featuring policy gates, SBOM export, and automated Slack/JIRA alerting.</strong>
</p>

---

## 📖 Overview

This project wraps the **Synopsys Black Duck SCA scanner** in a reproducible Docker image and seamlessly integrates it into GitLab CI/CD as a reusable pipeline component. It is purposefully designed to support mature Application Security (AppSec) programs that require **shift-left SCA** without relying on installing the Detect plugin directly on runner hosts.

By containerizing the scanner and its post-processing scripts, this solution ensures consistent, reliable, and secure vulnerability scanning across all your organization's repositories.

### ✨ Key Capabilities

| Feature | Description |
| :--- | :--- |
| 🐳 **Container-First Architecture** | All scanner logic, dependencies, and scripts live within a versioned Docker image, eliminating host-level dependencies. |
| 🛑 **Automated Policy Gates** | The pipeline automatically fails based on highly configurable severity or CVSS score thresholds, preventing vulnerable code from progressing. |
| 📦 **SBOM Export & Generation** | Automatically generates and exports Software Bill of Materials (SBOM) in both **CycloneDX** and **SPDX** formats as pipeline artifacts for every build. |
| ⚡ **Incremental Scanning** | Supports snippet and signature detection exclusively on changed components, significantly reducing scan times (optional). |
| 🔄 **Multi-Project Scalability** | Utilize a single centralized image, parameterized per repository via GitLab CI/CD variables, making it trivial to roll out across hundreds of projects. |
| 🔔 **Integrated Notifications** | Automated Slack webhook notifications and automated JIRA issue creation upon policy violations to streamline developer triage. |

---

## 📂 Repository Structure

The repository is organized to separate the Docker runner environment, the CI/CD pipeline templates, and the post-processing automation scripts.

```text
blackduck-cicd/
├── docker/
│   ├── Dockerfile                  # Black Duck Detect runner image definition
│   ├── entrypoint.sh               # Primary wrapper script orchestrating pre/post hooks
│   └── detect-config.yml           # Default Synopsys Detect property overrides
├── gitlab/
│   ├── blackduck-scan.yml          # The reusable CI component (to be included by consumers)
│   └── example-consumer.gitlab-ci.yml  # Example pipeline demonstrating how to consume the scanner
├── scripts/
│   ├── policy_gate.py              # Evaluates scan results against thresholds and exits accordingly
│   ├── sbom_export.py              # Post-processor for CycloneDX and SPDX artifact generation
│   ├── notify_slack.py             # Sends formatted violation alerts to Slack
│   └── create_jira_issue.py        # Automatically generates JIRA tickets for vulnerabilities
├── docs/
│   ├── SETUP.md                    # One-time Black Duck Hub and GitLab integration setup guide
│   ├── VARIABLES.md                # Comprehensive reference for all supported CI/CD variables
│   └── POLICY_GATE.md              # Detailed explanation of the policy gate logic and configuration
├── tests/
│   ├── integration_test.sh         # Shell-based integration tests
│   ├── mock_hub.py                 # Mock Black Duck Hub server for testing
│   └── test_policy_gate.py         # Unit tests for the policy gate script
├── .github/
│   └── workflows/
│       └── lint.yml                # GitHub Actions workflow for Dockerfile and script linting
├── .gitlab-ci.yml                  # Development and testing pipeline for this repository itself
├── .hadolint.yaml                  # Configuration for Hadolint (Dockerfile linter)
├── Makefile                        # Build, test, and linting automation commands
└── README.md                       # This file
```

---

## 🚀 Quick Start Guide

### 1. Build and Push the Scanner Image

First, build the containerized scanner image and push it to your organization's container registry. You can utilize the provided `Makefile` for convenience.

```bash
# Using the Makefile
make build REGISTRY=your-registry.example.com
make push REGISTRY=your-registry.example.com

# Or using Docker directly
docker build -t your-registry.example.com/blackduck-detect:latest ./docker
docker push your-registry.example.com/blackduck-detect:latest
```

### 2. Configure GitLab CI/CD Variables

Configure the following variables in your GitLab instance at the **Group** or **Project** level. Ensure sensitive tokens are marked as **Masked** and **Protected**.

| Variable | Requirement | Description |
| :--- | :---: | :--- |
| `BD_URL` | **Required** | The URL to your Black Duck Hub instance (e.g., `https://hub.example.com`). |
| `BD_TOKEN` | **Required** | Your Black Duck API token. **Must be masked.** |
| `BD_DETECT_IMAGE` | **Required** | The full image reference of your built scanner image. |
| `BD_TRUST_CERT` | Optional | Set to `true` if your Black Duck Hub uses a self-signed certificate. |
| `SLACK_WEBHOOK_URL` | Optional | The incoming webhook URL for Slack notifications. |
| `JIRA_URL` | Optional | The base URL for your JIRA instance. |
| `JIRA_TOKEN` | Optional | Your JIRA API authentication token. |
| `JIRA_PROJECT_KEY` | Optional | The target JIRA project key where issues should be created. |

*For a complete list of variables, refer to [`docs/VARIABLES.md`](docs/VARIABLES.md).*

### 3. Include the Component in Your Pipeline

To utilize the scanner in a downstream application, simply `include` the component in your project's `.gitlab-ci.yml` file and extend the base job.

```yaml
# your-project/.gitlab-ci.yml
include:
  - project: 'security/blackduck-cicd' # Adjust to match your GitLab project path
    ref: main
    file: 'gitlab/blackduck-scan.yml'

stages:
  - build
  - test
  - scan
  - deploy

blackduck-sca:
  extends: .blackduck_scan
  stage: scan
  variables:
    BD_PROJECT_NAME: "my-application"
    BD_PROJECT_VERSION: "$CI_COMMIT_REF_SLUG"
    BD_POLICY_FAIL_ON_SEVERITIES: "CRITICAL,HIGH"
```

---

## 🏗️ Architecture Details

### The Docker Image

The custom Docker image is built on top of `eclipse-temurin:17-jre-alpine` to provide a lightweight Java runtime environment. It bundles the following components:

*   **Synopsys Detect CLI:** The core scanning engine (version is configurable via the `DETECT_VERSION` build argument).
*   **Python 3 Environment:** Required for executing the custom post-scan Python scripts.
*   **System Utilities:** `bash`, `curl`, and `jq` are included for shell-based hooks and JSON processing.

The `entrypoint.sh` script acts as the orchestrator for the container, performing the following sequence:
1.  **Pre-scan Validation:** Pings the Black Duck Hub to verify token validity and asserts that required project names are provided.
2.  **Execution:** Runs `detect.sh` with the appropriate mapped properties.
3.  **Evaluation:** Executes `policy_gate.py` to determine if the build should pass or fail.
4.  **Artifact Generation:** Executes `sbom_export.py` to extract SBOMs.
5.  **Alerting:** Triggers Slack and JIRA notifications conditionally based on the scan results.

### The Policy Gate

The `scripts/policy_gate.py` script acts as the enforcement mechanism. It parses the Black Duck risk report JSON generated during the scan and applies your configured thresholds.

```bash
# Example internal execution by the entrypoint script
# Exit 0 = Pass, Exit 1 = Policy Violation
python3 policy_gate.py \
  --report-dir /tmp/blackduck/reports \
  --fail-on-severities CRITICAL,HIGH \
  --max-cvss 8.5
```

*Detailed logic and configuration options are documented in [`docs/POLICY_GATE.md`](docs/POLICY_GATE.md).*

### SBOM Export

Following a successful (or conditionally failed) scan, `scripts/sbom_export.py` interacts with the Black Duck REST API to download standardized SBOMs:
*   `sbom-cyclonedx.json` (CycloneDX format, v1.4)
*   `sbom-spdx.json` (SPDX format, v2.3)

These files are automatically published as GitLab job artifacts, making them easily accessible for compliance reporting or ingestion into artifact registries.

---

## 🏷️ Versioning & Tagging Strategy

When referencing the CI component or the Docker image, adhere to the following tagging strategy:

| Tag Format | Usage | Description |
| :--- | :--- | :--- |
| `latest` | Development | Tracks the `main` branch. **Do not use in production pipelines.** |
| `vX.Y.Z` | Production | Semantic versioning for stable, pinned releases. Use this in consumer pipelines. |
| `detect-X.Y.Z` | Specific | Tied to a specific underlying Synopsys Detect CLI release version. |

---

## 🤝 Contributing

Contributions are welcome and encouraged! To contribute to this project:

1.  Create a feature branch off of `main`.
2.  Make your modifications.
3.  Run local linting and tests using `make lint` and `make test`.
4.  If adding new CI variables, ensure you update `docs/VARIABLES.md`.
5.  Open a Merge Request (MR) / Pull Request (PR) with a detailed description of your changes.

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for complete details.
