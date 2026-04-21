#!/usr/bin/env python3
"""
policy_gate.py — Black Duck SCA Policy Gate

Queries the Black Duck Hub REST API for the BOM component vulnerability
summary of a given project/version and exits non-zero if the configured
severity or CVSS thresholds are breached.

Exit codes:
    0  — all policies passed
    1  — policy violation (pipeline should fail)
    2  — configuration / API error
"""

import argparse
import json
import logging
import sys
from typing import Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Black Duck SCA policy gate")
    parser.add_argument("--bd-url", required=True)
    parser.add_argument("--bd-token", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--fail-on-severities",
        default="CRITICAL",
        help="Comma-separated list of severities that trigger failure (e.g. CRITICAL,HIGH)",
    )
    parser.add_argument(
        "--max-cvss",
        type=float,
        default=None,
        help="Fail if any vulnerability has CVSS score >= this value",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    return parser.parse_args()


def get_bearer_token(bd_url: str, api_token: str, verify: bool) -> str:
    """Exchange the BD API token for a short-lived bearer token."""
    resp = requests.post(
        f"{bd_url}/api/tokens/authenticate",
        headers={"Authorization": f"token {api_token}"},
        verify=verify,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["bearerToken"]


def find_project_version(
    bd_url: str, headers: dict, project_name: str, version_name: str, verify: bool
) -> Optional[str]:
    """Return the href of the matching project version, or None."""
    resp = requests.get(
        f"{bd_url}/api/projects",
        headers=headers,
        params={"q": f"name:{project_name}", "limit": 10},
        verify=verify,
        timeout=30,
    )
    resp.raise_for_status()
    projects = resp.json().get("items", [])

    for project in projects:
        if project["name"] != project_name:
            continue
        versions_href = next(
            (l["href"] for l in project["_meta"]["links"] if l["rel"] == "versions"),
            None,
        )
        if not versions_href:
            continue
        vresp = requests.get(
            versions_href,
            headers=headers,
            params={"q": f"versionName:{version_name}", "limit": 10},
            verify=verify,
            timeout=30,
        )
        vresp.raise_for_status()
        for version in vresp.json().get("items", []):
            if version["versionName"] == version_name:
                return version["_meta"]["href"]

    return None


def get_vuln_summary(version_href: str, headers: dict, verify: bool) -> dict:
    """Return the vulnerability counts and high-severity details."""
    resp = requests.get(
        f"{version_href}/vulnerable-bom-components",
        headers=headers,
        params={"limit": 500},
        verify=verify,
        timeout=60,
    )
    resp.raise_for_status()
    items = resp.json().get("items", [])

    counts = {s: 0 for s in SEVERITY_ORDER}
    max_cvss = 0.0
    violations = []

    for item in items:
        for vuln in item.get("vulnerabilityWithRemediation", [{}]):
            sev = vuln.get("severity", "INFO").upper()
            cvss = vuln.get("overallScore", 0.0)
            counts[sev] = counts.get(sev, 0) + 1
            if cvss > max_cvss:
                max_cvss = cvss
            violations.append(
                {
                    "component": item.get("componentName", "?"),
                    "version": item.get("componentVersionName", "?"),
                    "vuln_id": vuln.get("vulnerabilityName", "?"),
                    "severity": sev,
                    "cvss": cvss,
                    "remediation": vuln.get("remediationStatus", "NEW"),
                }
            )

    return {"counts": counts, "max_cvss": max_cvss, "violations": violations}


def main() -> int:
    args = parse_args()
    fail_severities = [s.strip().upper() for s in args.fail_on_severities.split(",")]
    verify = not args.insecure

    if args.insecure:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        log.warning("TLS verification disabled")

    log.info("Authenticating with Black Duck Hub...")
    try:
        token = get_bearer_token(args.bd_url, args.bd_token, verify)
    except requests.HTTPError as exc:
        log.error("Authentication failed: %s", exc)
        return 2

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json",
    }

    log.info("Locating project '%s' version '%s'...", args.project, args.version)
    version_href = find_project_version(
        args.bd_url, headers, args.project, args.version, verify
    )
    if not version_href:
        log.error(
            "Project '%s' / version '%s' not found in Black Duck Hub.",
            args.project,
            args.version,
        )
        return 2

    log.info("Fetching vulnerability summary...")
    summary = get_vuln_summary(version_href, headers, verify)
    counts = summary["counts"]
    max_cvss = summary["max_cvss"]

    log.info("--- Vulnerability Summary ---")
    for sev in SEVERITY_ORDER:
        log.info("  %-10s %d", sev, counts.get(sev, 0))
    log.info("  Max CVSS   %.1f", max_cvss)
    log.info("-----------------------------")

    # Evaluate policy
    policy_failed = False
    failure_reasons = []

    for sev in fail_severities:
        count = counts.get(sev, 0)
        if count > 0:
            reason = f"{count} {sev} vulnerability/vulnerabilities found"
            failure_reasons.append(reason)
            policy_failed = True

    if args.max_cvss is not None and max_cvss >= args.max_cvss:
        reason = f"Max CVSS {max_cvss:.1f} >= threshold {args.max_cvss:.1f}"
        failure_reasons.append(reason)
        policy_failed = True

    if policy_failed:
        log.error("POLICY GATE FAILED:")
        for r in failure_reasons:
            log.error("  • %s", r)

        # Print top violating components
        critical_high = [
            v for v in summary["violations"] if v["severity"] in ("CRITICAL", "HIGH")
        ]
        critical_high.sort(key=lambda x: x["cvss"], reverse=True)
        if critical_high:
            log.error("Top violations:")
            for v in critical_high[:10]:
                log.error(
                    "  [%s %.1f] %s@%s — %s (%s)",
                    v["severity"],
                    v["cvss"],
                    v["component"],
                    v["version"],
                    v["vuln_id"],
                    v["remediation"],
                )
        return 1

    log.info("✓ POLICY GATE PASSED — no violations above threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
