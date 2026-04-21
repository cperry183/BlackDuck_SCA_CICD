# syntax=docker/dockerfile:1.6
# -------------------------------------------------------------------
# BlackDuck SCA Scanner Image
# Base: eclipse-temurin (JRE) + Python for post-scan scripts
# -------------------------------------------------------------------

ARG DETECT_VERSION=9.2.0
ARG JAVA_IMAGE=eclipse-temurin:17-jre-alpine

FROM ${JAVA_IMAGE} AS base

ARG DETECT_VERSION
ENV DETECT_VERSION=${DETECT_VERSION} \
    DETECT_HOME=/opt/blackduck/detect \
    DETECT_JAR_DOWNLOAD_DIR=/opt/blackduck/detect/download \
    DETECT_OUTPUT_PATH=/tmp/blackduck/output \
    DETECT_SCAN_OUTPUT_PATH=/tmp/blackduck/scan \
    PYTHONUNBUFFERED=1

# --- system deps ---
RUN apk add --no-cache \
    bash \
    curl \
    jq \
    python3 \
    py3-pip \
    git \
    ca-certificates \
    && pip3 install --no-cache-dir \
        requests \
        packaging \
    && mkdir -p \
        "${DETECT_HOME}" \
        "${DETECT_JAR_DOWNLOAD_DIR}" \
        "${DETECT_OUTPUT_PATH}" \
        "${DETECT_SCAN_OUTPUT_PATH}" \
    && chmod -R 775 /opt/blackduck /tmp/blackduck

# --- download pinned Detect shell script ---
RUN curl -fsSL \
    "https://detect.synopsys.com/detect${DETECT_VERSION%%.*}.sh" \
    -o /opt/blackduck/detect/detect.sh \
    && chmod +x /opt/blackduck/detect/detect.sh

# --- copy scripts ---
COPY scripts/policy_gate.py      /opt/blackduck/scripts/policy_gate.py
COPY scripts/sbom_export.py      /opt/blackduck/scripts/sbom_export.py
COPY scripts/notify_slack.py     /opt/blackduck/scripts/notify_slack.py
COPY scripts/create_jira_issue.py /opt/blackduck/scripts/create_jira_issue.py
COPY docker/detect-config.yml    /opt/blackduck/detect/detect-config.yml
COPY docker/entrypoint.sh        /opt/blackduck/entrypoint.sh

RUN chmod +x /opt/blackduck/entrypoint.sh \
    && chmod +x /opt/blackduck/scripts/*.py

# --- non-root user ---
RUN addgroup -S scanner && adduser -S scanner -G scanner \
    && chown -R scanner:scanner /opt/blackduck /tmp/blackduck

USER scanner
WORKDIR /workspace

LABEL org.opencontainers.image.title="blackduck-detect-runner" \
      org.opencontainers.image.description="Containerized Synopsys Black Duck SCA scanner" \
      org.opencontainers.image.version="${DETECT_VERSION}" \
      org.opencontainers.image.source="https://github.com/your-org/blackduck-cicd"

ENTRYPOINT ["/opt/blackduck/entrypoint.sh"]
