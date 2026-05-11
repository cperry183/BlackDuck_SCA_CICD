#!/usr/bin/env python3
"""
policy_gate.py — BlackDuck SCA Policy Enforcement

Parses the Black Duck risk report JSON produced by Synopsys Detect and
evaluates it against configurable severity and CVSS thresholds.

Exit codes:
    0  — All checks passed; no violations found.
    1  — Policy violation: one or more vulns exceeded configured thresholds.
    2  — Infrastructure / configuration error (missing report, bad JSON, etc.)
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# ── Data classes ───────────────────────────────────────────────────────────────
@dataclass
class Violation:
    cve_id: str
    severity: str
    cvss_score: float
    component: str
    component_version: str
    reason: str  # "severity" | "cvss"

    def to_dict(self) -> dict:
        return {
            "cve_id":            self.cve_id,
            "severity":          self.severity,
            "cvss_score":        self.cvss_score,
            "component":         self.component,
            "component_version": self.component_version,
            "reason":            self.reason,
        }

    def __str__(self) -> str:
        return (
            f"{self.cve_id} | {self.severity} | CVSS={self.cvss_score:.1f} | "
            f"{self.component}@{self.component_version} | reason={self.reason}"
        )


@dataclass
class PolicyResult:
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    total_scanned: int = 0

# ── Report loading ─────────────────────────────────────────────────────────────
def find_report(report_dir: str) -> Path:
    """
    Locate the Black Duck risk report JSON.
    Detect writes it as:  <report_dir>/BlackDuck_RiskReport_*.json
    Falls back to a recursive glob for resilience across Detect versions.
    """
    report_dir_path = Path(report_dir)
    if not report_dir_path.is_dir():
        log.error("Report directory does not exist: %s", report_dir)
        sys.exit(2)

    # Primary pattern (Detect ≥8)
    candidates = sorted(report_dir_path.glob("BlackDuck_RiskReport_*.json"))
    if not candidates:
        # Fallback: recursive scan
        candidates = sorted(report_dir_path.rglob("*risk*report*.json"))
    if not candidates:
        log.error(
            "No risk report JSON found under '%s'. "
            "Ensure Detect completed successfully and REPORT_DIR is correct.",
            report_dir,
        )
        sys.exit(2)

    if len(candidates) > 1:
        log.warning(
            "Multiple report files found — using the most recent: %s",
            candidates[-1],
        )
    return candidates[-1]


def load_report(report_path: Path) -> dict:
    log.info("Loading report: %s", report_path)
    try:
        with report_path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        log.error("Report JSON is malformed: %s", exc)
        sys.exit(2)
    except OSError as exc:
        log.error("Cannot read report file: %s", exc)
        sys.exit(2)

# ── Evaluation ─────────────────────────────────────────────────────────────────
def evaluate(
    report: dict,
    fail_severities: set[str],
    max_cvss: float | None,
) -> PolicyResult:
    """
    Walk every vulnerability in the report and collect those that breach
    the configured severity list or CVSS ceiling.

    The report structure (Detect ≥8) looks like:
    {
      "securityRiskProfile": { "counts": { ... } },
      "items": [
        {
          "vulnerabilityWithRemediation": {
            "vulnerabilityName": "CVE-2023-XXXX",
            "severity": "CRITICAL",
            "overallScore": 9.8,
            "componentName": "log4j",
            "componentVersionName": "2.14.1"
          }
        }, ...
      ]
    }
    Older versions may embed vulns differently; we handle both shapes.
    """
    raw_items: list[dict] = report.get("items", [])
    violations: list[Violation] = []
    total = 0

    for item in raw_items:
        # Support both flat and nested vuln shapes
        vuln = item.get("vulnerabilityWithRemediation") or item
        cve_id          = vuln.get("vulnerabilityName") or vuln.get("id", "UNKNOWN")
        severity        = (vuln.get("severity") or vuln.get("vulnerabilitySeverity", "")).upper()
        cvss_score      = float(vuln.get("overallScore") or vuln.get("cvssScore", 0.0))
        component       = vuln.get("componentName") or item.get("componentName", "unknown")
        component_ver   = vuln.get("componentVersionName") or item.get("componentVersionName", "unknown")
        total += 1

        # Severity check
        if fail_severities and severity in fail_severities:
            violations.append(Violation(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                component=component,
                component_version=component_ver,
                reason="severity",
            ))
            continue  # don't double-count

        # CVSS threshold check (strict greater-than, not >=, to match common policy wording)
        if max_cvss is not None and cvss_score > max_cvss:
            violations.append(Violation(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                component=component,
                component_version=component_ver,
                reason="cvss",
            ))

    return PolicyResult(
        passed=len(violations) == 0,
        violations=violations,
        total_scanned=total,
    )

# ── Output helpers ─────────────────────────────────────────────────────────────
def write_violations_json(violations: list[Violation], output_path: str) -> None:
    payload = {"violation_count": len(violations), "violations": [v.to_dict() for v in violations]}
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    log.info("Violations JSON written to: %s", output_path)


def print_summary(result: PolicyResult, fail_severities: set[str], max_cvss: float | None) -> None:
    log.info("─" * 60)
    log.info("Policy Gate Summary")
    log.info("  Severities that fail : %s", ", ".join(sorted(fail_severities)) or "(none)")
    log.info("  Max CVSS threshold   : %s", f">{max_cvss}" if max_cvss is not None else "(none)")
    log.info("  Total vulns scanned  : %d", result.total_scanned)
    log.info("  Violations found     : %d", len(result.violations))
    log.info("─" * 60)
    if result.violations:
        log.error("POLICY GATE FAILED — violations:")
        for v in result.violations:
            log.error("  ✗ %s", v)
    else:
        log.info("POLICY GATE PASSED — no violations.")
    log.info("─" * 60)

# ── CLI ────────────────────────────────────────────────────────────────────────
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate Black Duck scan results against policy thresholds.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--report-dir",
        required=True,
        help="Directory containing the Black Duck risk report JSON.",
    )
    parser.add_argument(
        "--fail-on-severities",
        default="CRITICAL,HIGH",
        help="Comma-separated list of severities that trigger a gate failure.",
    )
    parser.add_argument(
        "--max-cvss",
        type=float,
        default=None,
        help="Gate fails when any vuln has a CVSS score strictly greater than this value.",
    )
    parser.add_argument(
        "--violations-out",
        default="",
        help="Optional path to write a violations JSON file (consumed by notify/JIRA scripts).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    fail_severities: set[str] = {
        s.strip().upper() for s in args.fail_on_severities.split(",") if s.strip()
    }

    report_path = find_report(args.report_dir)
    report      = load_report(report_path)
    result      = evaluate(report, fail_severities, args.max_cvss)

    print_summary(result, fail_severities, args.max_cvss)

    if args.violations_out:
        write_violations_json(result.violations, args.violations_out)

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
