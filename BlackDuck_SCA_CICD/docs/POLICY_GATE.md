# Policy Gate Reference

The policy gate (`scripts/policy_gate.py`) is the enforcement layer that determines whether a pipeline passes or fails based on vulnerability findings in Black Duck Hub.

---

## How It Works

After Detect finishes a scan and uploads results to the Black Duck Hub, the policy gate:

1. Authenticates with the Hub REST API using `BD_TOKEN`
2. Locates the project version by name
3. Fetches all vulnerable BOM components
4. Evaluates two independent thresholds:
   - **Severity-based**: Fails if any vulnerability matches a blocked severity
   - **CVSS-based**: Fails if any vulnerability's CVSS score meets or exceeds a threshold
5. On failure: logs top violations, triggers notifications, exits 1

---

## Severity Thresholds

Set `BD_POLICY_FAIL_ON_SEVERITIES` to a comma-separated list:

```
BD_POLICY_FAIL_ON_SEVERITIES: "CRITICAL,HIGH"
```

Valid values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

The gate counts all vulnerabilities at or above each listed severity and fails if any count > 0.

---

## CVSS Threshold

Set `BD_MAX_CVSS` to a float value:

```
BD_MAX_CVSS: "8.5"
```

The gate fails if any single vulnerability has an `overallScore` (CVSS v3) ≥ this value.

Use this alongside severity thresholds for precise control. For example:
- Block all CRITICAL + any HIGH with CVSS ≥ 8.5
- Block any vulnerability regardless of label if CVSS ≥ 9.0

---

## Remediation Status Filtering

The gate currently evaluates **all** vulnerabilities regardless of remediation status. If your team marks vulnerabilities as `IGNORED` or `MITIGATED` in Black Duck Hub, those are still counted.

To exclude accepted/ignored findings, the Black Duck Hub policy configuration (under **Manage** → **Policies**) is the recommended approach. This keeps the accept/ignore workflow inside Hub, not in the CI gate.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All policies passed |
| `1` | Policy violation — pipeline should fail |
| `2` | Configuration or API error — check BD_URL, BD_TOKEN, project name |

---

## Onboarding Mode

During initial rollout, set `allow_failure: true` on the job (or use the `.blackduck_scan_informational` variant) to surface findings without blocking deployments:

```yaml
blackduck-sca:
  extends: .blackduck_scan_informational   # non-blocking
  variables:
    BD_PROJECT_NAME: "my-app"
```

Transition to `.blackduck_scan` (blocking) once the team has triaged existing findings.
