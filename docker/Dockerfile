# -----------------------------------------------------------------------------
# Dockerfile — BlackDuck SCA Container Runner (multi-stage)
# -----------------------------------------------------------------------------
# Build args:
#   DETECT_VERSION  — Synopsys Detect CLI version to bundle (default: latest)
#   DETECT_URL      — Override download URL for air-gapped environments
# -----------------------------------------------------------------------------

ARG JAVA_IMAGE=eclipse-temurin:17-jre-alpine
FROM ${JAVA_IMAGE} AS builder

# Build args
ARG DETECT_VERSION=9
ARG DETECT_URL=https://detect.synopsys.com/detect${DETECT_VERSION}.sh

# Install build-time dependencies (kept in builder only)
RUN apk add --no-cache \
      bash \
      curl \
      jq \
      python3 \
      py3-pip \
      build-base \
      libffi-dev \
      openssl-dev \
      ca-certificates

# Install Python deps into an isolated venv so we can copy the venv into the final image
WORKDIR /tmp/pip
COPY docker/requirements.txt ./requirements.txt
RUN python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --upgrade pip \
  && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Download Synopsys Detect CLI into /opt/detect
RUN mkdir -p /opt/detect \
  && curl --silent --fail --location \
       --retry 3 --retry-delay 5 \
       --output /opt/detect/detect.sh \
       "${DETECT_URL}" \
  && chmod +x /opt/detect/detect.sh

# ---------------------------------------------------------------------------
# Final runtime image (slim)
# ---------------------------------------------------------------------------
FROM ${JAVA_IMAGE} AS final

# Metadata build args (kept for labels)
ARG BUILD_DATE
ARG GIT_SHA
ARG DETECT_VERSION

# Install only runtime packages
RUN apk add --no-cache \
      bash \
      curl \
      jq \
      python3 \
      ca-certificates \
  && update-ca-certificates

# Create non-root scanner user and prepare directories
RUN addgroup -S scanner \
  && adduser -S -G scanner -h /home/scanner -s /sbin/nologin scanner \
  && mkdir -p /tmp/blackduck/reports /tmp/blackduck/sbom \
  && chown -R scanner:scanner /tmp/blackduck

# Copy detect and the prebuilt Python venv from the builder stage
COPY --from=builder /opt/detect /opt/detect
COPY --from=builder /opt/venv /opt/venv

# Ensure the venv binaries are available in PATH
ENV PATH="/opt/venv/bin:${PATH}"

# Copy application scripts and entrypoint, set ownership
WORKDIR /app
COPY --chown=scanner:scanner scripts/    ./scripts/
COPY --chown=scanner:scanner docker/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh \
  && chown -R scanner:scanner /opt/detect /opt/venv /app

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="BlackDuck SCA Runner" \
      org.opencontainers.image.description="Containerized Synopsys Black Duck SCA scanner for GitLab CI/CD" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.source="https://github.com/cperry183/BlackDuck_SCA_CICD" \
      org.opencontainers.image.licenses="MIT"

# Default report/sbom directories — override via env vars
ENV REPORT_DIR=/tmp/blackduck/reports \
    SBOM_OUTPUT_DIR=/tmp/blackduck/sbom

USER scanner

ENTRYPOINT ["/app/entrypoint.sh"]
