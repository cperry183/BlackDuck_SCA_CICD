#!/usr/bin/env python3
"""
sbom_export.py — Export CycloneDX and SPDX SBOMs from Black Duck Hub

Downloads both formats and saves them to the configured output directory
for GitLab CI artifact upload.
"""

import argparse
import logging
import os
import sys
import time

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def parse_args():
    p = argparse.ArgumentParser(description="Export SBOM from Black Duck")
    p.add_argument("--bd-url", required=True)
    p.add_argument("--bd-token", required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--insecure", action="store_true")
    return p.parse_args()


def authenticate(bd_url, api_token, verify):
    r = requests.post(
        f"{bd_url}/api/tokens/authenticate",
        headers={"Authorization": f"token {api_token}"},
        verify=verify, timeout=30,
    )
    r.raise_for_status()
    return r.json()["bearerToken"]


def find_version_href(bd_url, headers, project, version, verify):
    r = requests.get(f"{bd_url}/api/projects",
                     headers=headers,
                     params={"q": f"name:{project}", "limit": 10},
                     verify=verify, timeout=30)
    r.raise_for_status()
    for proj in r.json().get("items", []):
        if proj["name"] != project:
            continue
        for link in proj["_meta"]["links"]:
            if link["rel"] == "versions":
                vr = requests.get(link["href"], headers=headers,
                                  params={"q": f"versionName:{version}", "limit": 10},
                                  verify=verify, timeout=30)
                vr.raise_for_status()
                for v in vr.json().get("items", []):
                    if v["versionName"] == version:
                        return v["_meta"]["href"]
    return None


def request_sbom_export(version_href, headers, report_type, verify):
    """Trigger an async SBOM export and poll until complete."""
    payload = {
        "reportFormat": "JSON",
        "reportType": report_type,  # "SPDX_22" or "CYCLONEDX_14"
        "versionId": version_href.split("/")[-1],
    }
    r = requests.post(
        f"{version_href}/sbom-reports",
        headers={**headers, "Content-Type": "application/json"},
        json=payload,
        verify=verify,
        timeout=60,
    )
    if r.status_code not in (200, 201, 202):
        log.warning("SBOM export request returned %d for %s", r.status_code, report_type)
        return None

    report_href = r.headers.get("Location") or r.json().get("_meta", {}).get("href")
    if not report_href:
        log.warning("No report location returned for %s", report_type)
        return None

    # Poll for completion
    for attempt in range(20):
        time.sleep(6)
        poll = requests.get(report_href, headers=headers, verify=verify, timeout=30)
        poll.raise_for_status()
        status = poll.json().get("status", "")
        log.info("  SBOM %s status: %s (attempt %d)", report_type, status, attempt + 1)
        if status == "COMPLETED":
            # Get download link
            for link in poll.json().get("_meta", {}).get("links", []):
                if link.get("rel") == "download":
                    return link["href"]
        elif status in ("FAILED", "ERROR"):
            log.warning("SBOM export failed for %s", report_type)
            return None

    log.warning("SBOM export timed out for %s", report_type)
    return None


def download(url, headers, output_path, verify):
    r = requests.get(url, headers=headers, verify=verify, stream=True, timeout=120)
    r.raise_for_status()
    with open(output_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
    size_kb = os.path.getsize(output_path) // 1024
    log.info("  Saved %s (%d KB)", output_path, size_kb)


def main():
    args = parse_args()
    verify = not args.insecure
    if args.insecure:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    os.makedirs(args.output_dir, exist_ok=True)

    token = authenticate(args.bd_url, args.bd_token, verify)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    log.info("Locating project version...")
    version_href = find_version_href(args.bd_url, headers, args.project, args.version, verify)
    if not version_href:
        log.error("Project/version not found: %s/%s", args.project, args.version)
        return 1

    exports = [
        ("CYCLONEDX_14", "sbom-cyclonedx.json"),
        ("SPDX_22",      "sbom-spdx.json"),
    ]

    success = 0
    for report_type, filename in exports:
        log.info("Requesting SBOM export: %s", report_type)
        download_url = request_sbom_export(version_href, headers, report_type, verify)
        if download_url:
            out_path = os.path.join(args.output_dir, filename)
            download(download_url, headers, out_path, verify)
            success += 1
        else:
            log.warning("Skipping %s — export unavailable", report_type)

    log.info("SBOM export complete: %d/%d formats exported.", success, len(exports))
    return 0 if success > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
