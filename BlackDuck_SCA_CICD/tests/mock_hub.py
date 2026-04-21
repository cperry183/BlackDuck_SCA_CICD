#!/usr/bin/env python3
"""
mock_hub.py — Lightweight Black Duck Hub mock server

Runs a local HTTP server that mimics the Hub REST API endpoints
consumed by policy_gate.py, sbom_export.py, and entrypoint.sh.

Useful for:
  - Local development without a Hub instance
  - Integration tests in CI (no credentials required)
  - Validating policy gate logic against synthetic findings

Usage:
  # Start server (default port 8888)
  python3 tests/mock_hub.py

  # Start with a specific scenario
  BD_MOCK_SCENARIO=violations python3 tests/mock_hub.py

  # Point your scripts at it
  export BD_URL=http://localhost:8888
  export BD_TOKEN=mock-token-any-value
  export BD_TRUST_CERT=false

Scenarios (set via BD_MOCK_SCENARIO env var):
  clean       — No vulnerabilities (default)
  violations  — CRITICAL + HIGH findings (gate should fail)
  cvss_high   — Single CVSS 9.8 finding (fails on --max-cvss 8.5)
  empty       — Project version with zero BOM components
"""

import json
import logging
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    level=logging.INFO,
)
log = logging.getLogger("mock_hub")

PORT = int(os.environ.get("BD_MOCK_PORT", 8888))
SCENARIO = os.environ.get("BD_MOCK_SCENARIO", "clean")

# ---------------------------------------------------------------------------
# Synthetic vulnerability data per scenario
# ---------------------------------------------------------------------------
SCENARIOS = {
    "clean": [],
    "empty": [],
    "violations": [
        {
            "componentName": "log4j-core",
            "componentVersionName": "2.14.1",
            "vulnerabilityWithRemediation": [
                {
                    "vulnerabilityName": "CVE-2021-44228",
                    "severity": "CRITICAL",
                    "overallScore": 10.0,
                    "remediationStatus": "NEW",
                    "description": "Log4Shell RCE",
                },
                {
                    "vulnerabilityName": "CVE-2021-45046",
                    "severity": "CRITICAL",
                    "overallScore": 9.0,
                    "remediationStatus": "NEW",
                    "description": "Log4Shell bypass",
                },
            ],
        },
        {
            "componentName": "spring-webmvc",
            "componentVersionName": "5.3.17",
            "vulnerabilityWithRemediation": [
                {
                    "vulnerabilityName": "CVE-2022-22965",
                    "severity": "HIGH",
                    "overallScore": 9.8,
                    "remediationStatus": "NEW",
                    "description": "Spring4Shell",
                }
            ],
        },
        {
            "componentName": "jackson-databind",
            "componentVersionName": "2.13.0",
            "vulnerabilityWithRemediation": [
                {
                    "vulnerabilityName": "CVE-2022-42003",
                    "severity": "MEDIUM",
                    "overallScore": 7.5,
                    "remediationStatus": "IGNORED",
                    "description": "Deserialization issue",
                }
            ],
        },
    ],
    "cvss_high": [
        {
            "componentName": "openssl",
            "componentVersionName": "1.1.1t",
            "vulnerabilityWithRemediation": [
                {
                    "vulnerabilityName": "CVE-2023-0286",
                    "severity": "HIGH",
                    "overallScore": 9.8,
                    "remediationStatus": "NEW",
                    "description": "X.400 address type confusion",
                }
            ],
        }
    ],
}

PROJECT_ID = "mock-project-id-001"
VERSION_ID = "mock-version-id-001"
REPORT_ID = "mock-report-id-001"


class MockHubHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("  %s %s", self.path, args[1] if len(args) > 1 else "")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path

        # Token authentication
        if path == "/api/tokens/authenticate":
            self.send_json({"bearerToken": f"mock-bearer-{uuid.uuid4().hex}"})
            return

        # SBOM export request
        if "/sbom-reports" in path:
            report_href = f"http://localhost:{PORT}/api/sbom-reports/{REPORT_ID}"
            self.send_response(202)
            self.send_header("Location", report_href)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"_meta": {"href": report_href}}).encode())
            return

        self.send_json({"error": "not found"}, 404)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # Hub version check (connectivity ping)
        if path == "/api/current-version":
            self.send_json({
                "version": "2023.10.0",
                "buildNumber": "mock",
                "_meta": {"href": f"http://localhost:{PORT}/api/current-version"},
            })
            return

        # Projects list
        if path == "/api/projects":
            self.send_json({
                "totalCount": 1,
                "items": [{
                    "name": "mock-project",
                    "projectLevelAdjustments": False,
                    "_meta": {
                        "href": f"http://localhost:{PORT}/api/projects/{PROJECT_ID}",
                        "links": [{
                            "rel": "versions",
                            "href": f"http://localhost:{PORT}/api/projects/{PROJECT_ID}/versions",
                        }],
                    },
                }],
            })
            return

        # Project versions
        if f"/projects/{PROJECT_ID}/versions" in path:
            self.send_json({
                "totalCount": 1,
                "items": [{
                    "versionName": qs.get("q", ["versionName:mock-version"])[0].replace("versionName:", ""),
                    "_meta": {
                        "href": f"http://localhost:{PORT}/api/projects/{PROJECT_ID}/versions/{VERSION_ID}",
                        "links": [],
                    },
                }],
            })
            return

        # Vulnerable BOM components — core of the policy gate
        if f"/versions/{VERSION_ID}/vulnerable-bom-components" in path:
            vulns = SCENARIOS.get(SCENARIO, [])
            log.info("  Scenario='%s' → returning %d component(s)", SCENARIO, len(vulns))
            self.send_json({
                "totalCount": len(vulns),
                "items": vulns,
            })
            return

        # SBOM report status (poll endpoint)
        if f"/api/sbom-reports/{REPORT_ID}" in path:
            self.send_json({
                "status": "COMPLETED",
                "_meta": {
                    "href": f"http://localhost:{PORT}/api/sbom-reports/{REPORT_ID}",
                    "links": [{
                        "rel": "download",
                        "href": f"http://localhost:{PORT}/api/sbom-reports/{REPORT_ID}/download",
                    }],
                },
            })
            return

        # SBOM download — return a minimal CycloneDX stub
        if f"/api/sbom-reports/{REPORT_ID}/download" in path:
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                "version": 1,
                "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                "components": [
                    {"type": "library", "name": c["componentName"], "version": c["componentVersionName"]}
                    for c in SCENARIOS.get(SCENARIO, [])
                ],
            }
            self.send_json(sbom)
            return

        log.warning("Unhandled GET: %s", path)
        self.send_json({"error": "not implemented", "path": path}, 404)


def main():
    log.info("Starting mock Black Duck Hub on http://localhost:%d", PORT)
    log.info("Scenario: %s", SCENARIO)
    log.info("Set BD_MOCK_SCENARIO to: %s", " | ".join(SCENARIOS.keys()))
    log.info("Press Ctrl+C to stop.\n")

    server = HTTPServer(("0.0.0.0", PORT), MockHubHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")


if __name__ == "__main__":
    main()
