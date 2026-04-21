# Setup Guide

## Prerequisites

- Black Duck Hub instance (on-prem or cloud) — version 2023.x or later
- GitLab instance with Docker-capable runners
- Container registry (GitLab Registry, Harbor, ECR, etc.)
- (Optional) Slack workspace with incoming webhooks enabled
- (Optional) JIRA project with API access

---

## 1. Black Duck Hub — Create an API Token

1. Log in to Black Duck Hub as an admin or project owner.
2. Navigate to **User Preferences** → **User API Tokens**.
3. Click **Create Token**, give it a name like `gitlab-ci-scanner`.
4. Copy the token — you'll only see it once.
5. Store it as a **masked** GitLab CI/CD variable: `BD_TOKEN`.

---

## 2. Build and Push the Scanner Image

```bash
# Clone this repo
git clone https://gitlab.example.com/security/blackduck-cicd.git
cd blackduck-cicd

# Build — pin Detect version with build arg
docker build \
  --build-arg DETECT_VERSION=9.2.0 \
  -t your-registry.example.com/security/blackduck-detect:v1.0.0 \
  ./docker

# Push
docker push your-registry.example.com/security/blackduck-detect:v1.0.0
```

---

## 3. Configure GitLab Group-Level CI/CD Variables

Set these at the **Group** level so all child projects inherit them:

| Variable | Value | Masked | Protected |
|---|---|---|---|
| `BD_URL` | `https://hub.example.com` | No | No |
| `BD_TOKEN` | (paste token) | **Yes** | **Yes** |
| `BD_DETECT_IMAGE` | `your-registry.example.com/security/blackduck-detect:v1.0.0` | No | No |
| `BD_TRUST_CERT` | `true` (if self-signed) | No | No |
| `SLACK_WEBHOOK_URL` | (optional) | Yes | No |
| `JIRA_URL` | (optional) | No | No |
| `JIRA_TOKEN` | (optional) | Yes | No |
| `JIRA_PROJECT_KEY` | (optional) | No | No |

---

## 4. Configure Runner

The scan job requires a runner with the `docker` tag and Docker-in-Docker or Docker executor.

Minimum runner resources:
- **CPU**: 2 cores
- **RAM**: 6 GB (4 GB for Detect JVM + overhead)
- **Disk**: 10 GB (for Detect download cache and scan output)

Example runner `config.toml` section:

```toml
[[runners]]
  name = "docker-security"
  tags = ["docker"]
  executor = "docker"
  [runners.docker]
    image = "docker:24-dind"
    privileged = false
    volumes = ["/var/run/docker.sock:/var/run/docker.sock", "/cache"]
    memory = "6g"
```

---

## 5. Add to a Consumer Project

See [`gitlab/example-consumer.gitlab-ci.yml`](../gitlab/example-consumer.gitlab-ci.yml) for a complete example.

Minimum addition to an existing pipeline:

```yaml
include:
  - project: 'security/blackduck-cicd'
    ref: v1.0.0
    file: 'gitlab/blackduck-scan.yml'

blackduck-sca:
  extends: .blackduck_scan
  stage: scan
  variables:
    BD_PROJECT_NAME: "your-project-name"
```

---

## 6. Verify First Run

1. Open a Merge Request in the consumer project.
2. The `blackduck-sca` job should appear in the `scan` stage.
3. Monitor job logs for:
   - `Hub reachable (HTTP 200)` — connectivity OK
   - `Detect scan complete` — scan finished
   - `POLICY GATE PASSED` or violation details

Artifacts (`sbom-cyclonedx.json`, `sbom-spdx.json`, risk report PDF) will be available under **Job → Artifacts**.
