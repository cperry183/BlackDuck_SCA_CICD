#!/usr/bin/env python3
"""
create_jira_issue.py — Create a JIRA issue on Black Duck policy violation

Creates a single issue per pipeline run (deduplication by summary).
If an open issue already exists for this project/version, adds a comment.
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
    p.add_argument("--jira-url", required=True)
    p.add_argument("--jira-token", required=True)
    p.add_argument("--project-key", required=True)
    p.add_argument("--bd-project", required=True)
    p.add_argument("--bd-version", required=True)
    p.add_argument("--bd-url", required=True)
    p.add_argument("--issue-type", default="Bug")
    p.add_argument("--priority", default="High")
    return p.parse_args()


def jira_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def find_existing_issue(jira_url, token, project_key, summary_prefix):
    jql = (
        f'project = "{project_key}" '
        f'AND summary ~ "{summary_prefix}" '
        f'AND statusCategory != Done '
        f'ORDER BY created DESC'
    )
    r = requests.get(
        f"{jira_url}/rest/api/3/search",
        headers=jira_headers(token),
        params={"jql": jql, "maxResults": 1},
        timeout=30,
    )
    r.raise_for_status()
    issues = r.json().get("issues", [])
    return issues[0] if issues else None


def add_comment(jira_url, token, issue_key, body_text):
    payload = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": body_text}],
                }
            ],
        }
    }
    r = requests.post(
        f"{jira_url}/rest/api/3/issue/{issue_key}/comment",
        headers=jira_headers(token),
        json=payload,
        timeout=30,
    )
    r.raise_for_status()
    log.info("Comment added to existing issue %s", issue_key)


def create_issue(jira_url, token, project_key, issue_type, priority,
                 bd_project, bd_version, bd_url, ci_env):
    pipeline_url = ci_env.get("CI_PIPELINE_URL", "")
    ref = ci_env.get("CI_COMMIT_REF_NAME", "unknown")
    sha = ci_env.get("CI_COMMIT_SHORT_SHA", "")
    summary = f"[BlackDuck] Policy violation: {bd_project} @ {bd_version}"

    description_text = (
        f"Black Duck SCA policy gate failed for project '{bd_project}' "
        f"version '{bd_version}'.\n\n"
        f"Branch: {ref} ({sha})\n"
        f"Pipeline: {pipeline_url}\n"
        f"Black Duck Hub: {bd_url}\n\n"
        f"Review the vulnerability findings in Black Duck Hub and remediate "
        f"or mark them as accepted/ignored as appropriate."
    )

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "issuetype": {"name": issue_type},
            "priority": {"name": priority},
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description_text}],
                    }
                ],
            },
            "labels": ["security", "blackduck", "sca", "automated"],
        }
    }

    r = requests.post(
        f"{jira_url}/rest/api/3/issue",
        headers=jira_headers(token),
        json=payload,
        timeout=30,
    )
    r.raise_for_status()
    issue = r.json()
    log.info("Created JIRA issue: %s/browse/%s", jira_url, issue["key"])
    return issue["key"]


def main():
    args = parse_args()
    ci_env = {k: os.environ.get(k, "") for k in [
        "CI_PIPELINE_URL", "CI_COMMIT_REF_NAME", "CI_COMMIT_SHORT_SHA"
    ]}

    summary_prefix = f"[BlackDuck] Policy violation: {args.bd_project}"

    log.info("Checking for existing open JIRA issue...")
    existing = find_existing_issue(
        args.jira_url, args.jira_token, args.project_key, summary_prefix
    )

    if existing:
        issue_key = existing["key"]
        log.info("Found existing issue %s — adding comment.", issue_key)
        comment = (
            f"Scan re-triggered: {args.bd_project}@{args.bd_version} still failing. "
            f"Pipeline: {ci_env.get('CI_PIPELINE_URL', 'N/A')}"
        )
        add_comment(args.jira_url, args.jira_token, issue_key, comment)
    else:
        create_issue(
            args.jira_url, args.jira_token, args.project_key,
            args.issue_type, args.priority,
            args.bd_project, args.bd_version, args.bd_url, ci_env,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
