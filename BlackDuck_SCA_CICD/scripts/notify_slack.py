#!/usr/bin/env python3
"""
notify_slack.py — Post Black Duck policy violation alert to Slack
"""

import argparse
import json
import logging
import os
import sys

import requests

logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--webhook-url", required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--bd-url", required=True)
    p.add_argument("--severities", default="CRITICAL,HIGH")
    return p.parse_args()


def build_message(project, version, bd_url, severities, ci_env):
    pipeline_url = ci_env.get("CI_PIPELINE_URL", "")
    job_url = ci_env.get("CI_JOB_URL", "")
    ref = ci_env.get("CI_COMMIT_REF_NAME", "unknown")
    sha = ci_env.get("CI_COMMIT_SHORT_SHA", "")

    project_link = f"{bd_url}/api/projects"  # approximate; deep link requires project ID

    return {
        "text": f":rotating_light: *BlackDuck Policy Violation* — `{project}@{version}`",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 Black Duck SCA — Policy Gate FAILED",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Project:*\n{project}"},
                    {"type": "mrkdwn", "text": f"*Version:*\n{version}"},
                    {"type": "mrkdwn", "text": f"*Branch/Ref:*\n{ref} ({sha})"},
                    {"type": "mrkdwn", "text": f"*Blocking Severities:*\n{severities}"},
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Pipeline"},
                        "url": pipeline_url,
                        "style": "danger",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open Black Duck"},
                        "url": bd_url,
                    },
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Job: {job_url} | Review findings in Black Duck Hub and remediate or mark as reviewed.",
                    }
                ],
            },
        ],
    }


def main():
    args = parse_args()
    ci_env = {k: os.environ.get(k, "") for k in [
        "CI_PIPELINE_URL", "CI_JOB_URL", "CI_COMMIT_REF_NAME", "CI_COMMIT_SHORT_SHA"
    ]}

    payload = build_message(
        args.project, args.version, args.bd_url, args.severities, ci_env
    )

    log.info("Sending Slack notification...")
    r = requests.post(
        args.webhook_url,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    if r.status_code == 200:
        log.info("Slack notification sent.")
        return 0
    else:
        log.warning("Slack returned %d: %s", r.status_code, r.text[:200])
        return 1


if __name__ == "__main__":
    sys.exit(main())
