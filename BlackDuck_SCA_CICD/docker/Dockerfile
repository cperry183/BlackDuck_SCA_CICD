
# BlackDuck SCA Scanner Image 

# --- Stage 1: Builder ---
FROM eclipse-temurin:17-jre-alpine AS builder

RUN apk add --no-cache python3 py3-pip git

# Create a virtualenv to isolate Python dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir requests packaging

# --- Stage 2: Final Runner ---
FROM eclipse-temurin:17-jre-alpine

ARG DETECT_VERSION=9.2.0

# Install only minimal runtime dependencies
RUN apk add --no-cache bash curl jq python3

# Set environment variables
ENV DETECT_VERSION=${DETECT_VERSION} \
    DETECT_HOME=/opt/blackduck/detect \
    DETECT_JAR_DOWNLOAD_DIR=/opt/blackduck/detect/download \
    DETECT_OUTPUT_PATH=/tmp/blackduck/output \
    DETECT_SCAN_OUTPUT_PATH=/tmp/blackduck/scan \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv

# Setup directories
RUN mkdir -p \
    "${DETECT_HOME}" \
    "${DETECT_JAR_DOWNLOAD_DIR}" \
    "${DETECT_OUTPUT_PATH}" \
    "${DETECT_SCAN_OUTPUT_PATH}"

# Download pinned Detect shell script
RUN curl -fsSL "https://detect.synopsys.com/detect${DETECT_VERSION%%.*}.sh" \
    -o /opt/blackduck/detect/detect.sh \
    && chmod +x /opt/blackduck/detect/detect.sh

# Copy scripts and config
COPY scripts/ /opt/blackduck/scripts/
COPY docker/detect-config.yml /opt/blackduck/detect/detect-config.yml
COPY docker/entrypoint.sh /opt/blackduck/entrypoint.sh

# Permissions
RUN chmod +x /opt/blackduck/entrypoint.sh \
    && chmod +x /opt/blackduck/scripts/*.py \
    && addgroup -S scanner && adduser -S scanner -G scanner \
    && chown -R scanner:scanner /opt/blackduck /tmp/blackduck \
    && chmod -R 775 /opt/blackduck /tmp/blackduck

USER scanner
WORKDIR /workspace

LABEL org.opencontainers.image.title="blackduck-detect-runner" \
      org.opencontainers.image.description="Containerized Synopsys Black Duck SCA scanner (Multi-Stage)" \
      org.opencontainers.image.version="${DETECT_VERSION}"

ENTRYPOINT ["/opt/blackduck/entrypoint.sh"]

