# ==============================================================================
# Dockerfile — BlackDuck SCA Container Runner
# ==============================================================================
# Build args:
#   DETECT_VERSION  — Synopsys Detect CLI version to bundle (default: latest)
#   DETECT_URL      — Override download URL for air-gapped environments
# ==============================================================================

ARG JAVA_IMAGE=eclipse-temurin:17-jre-alpine
FROM ${JAVA_IMAGE} AS base

# ── Build arguments ────────────────────────────────────────────────────────────
ARG DETECT_VERSION=9
ARG DETECT_URL=https://detect.synopsys.com/detect${DETECT_VERSION}.sh

# ── System dependencies ────────────────────────────────────────────────────────
# Pin minor versions to ensure reproducible builds; bump deliberately.
# hadolint ignore=DL3018
RUN apk add --no-cache \
      bash \
      curl \
      jq \
      python3 \
      py3-pip \
      ca-certificates \
  && update-ca-certificates

# ── Python dependencies ────────────────────────────────────────────────────────
WORKDIR /tmp/pip
COPY docker/requirements.txt ./requirements.txt
# hadolint ignore=DL3013
RUN pip3 install --no-cache-dir --upgrade pip \
  && pip3 install --no-cache-dir -r requirements.txt

# ── Download Synopsys Detect CLI ───────────────────────────────────────────────
RUN mkdir -p /opt/detect \
  && curl --silent --fail --location \
       --retry 3 --retry-delay 5 \
       --output /opt/detect/detect.sh \
       "${DETECT_URL}" \
  && chmod +x /opt/detect/detect.sh

# ── Create non-root scanner user ───────────────────────────────────────────────
RUN addgroup -S scanner \
  && adduser -S -G scanner -h /home/scanner -s /sbin/nologin scanner \
  && mkdir -p /tmp/blackduck/reports /tmp/blackduck/sbom \
  && chown -R scanner:scanner /tmp/blackduck /opt/detect

# ── Copy application scripts ───────────────────────────────────────────────────
WORKDIR /app
COPY --chown=scanner:scanner scripts/    ./scripts/
COPY --chown=scanner:scanner docker/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

# ── Final image ────────────────────────────────────────────────────────────────
USER scanner

# Metadata labels (OCI standard)
ARG BUILD_DATE
ARG GIT_SHA
LABEL org.opencontainers.image.title="BlackDuck SCA Runner" \
      org.opencontainers.image.description="Containerized Synopsys Black Duck SCA scanner for GitLab CI/CD" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.source="https://github.com/cperry183/BlackDuck_SCA_CICD" \
      org.opencontainers.image.licenses="MIT"

# Default report/sbom directories — override via env vars
ENV REPORT_DIR=/tmp/blackduck/reports \
    SBOM_OUTPUT_DIR=/tmp/blackduck/sbom

ENTRYPOINT ["/app/entrypoint.sh"]
