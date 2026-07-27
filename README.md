# AWS IAM Least-Privilege Auditor

A Python tool that scans AWS IAM users, roles, and their attached/inline policies for common over-permissive patterns — wildcard actions (`*`, `s3:*`, `ec2:*`), wildcard resources, and sensitive actions like `iam:PassRole`.

## Why this exists

Least-privilege enforcement is one of the most cited (and most commonly failed) IAM controls in cloud security audits. This tool automates the first pass of that review so misconfigured policies surface before an auditor — or an attacker — finds them.

## Features
- Flags wildcard `Action` and `Resource` grants
- Flags sensitive actions (`PassRole`, `CreateAccessKey`, `AttachUserPolicy`, etc.)
- Severity-tiered output (HIGH / MEDIUM)
- Works against a live AWS account via `boto3`, or in `--demo` mode with no AWS credentials required
- Optional JSON report export

## Usage

```bash
pip install -r requirements.txt

# Run against sample data (no AWS account needed)
python iam_auditor.py --demo

# Run against your live AWS account (requires configured AWS credentials)
python iam_auditor.py

# Export findings to JSON
python iam_auditor.py --demo --output report.json
```

## Sample output

```
IAM Least-Privilege Audit — 2026-07-24T15:26:23+00:00
============================================================
Total findings: 7  (HIGH: 3, MEDIUM: 4)

[HIGH  ] user/dev-jsmith           (InlineFullAccess) — Wildcard/broad action '*' allowed
[HIGH  ] user/svc-backup           (S3BackupAccess) — Wildcard/broad action 's3:*' allowed
[HIGH  ] role/ci-deploy-role       (DeployPermissions) — Wildcard/broad action 'ec2:*' allowed
[MEDIUM] user/dev-jsmith           (InlineFullAccess) — Resource scope is wildcard '*' (applies to all resources)
```

## Requirements
- Python 3.9+
- `boto3` (only needed for live AWS scans; demo mode has no dependency)
- For live scans: AWS credentials with `iam:List*` / `iam:Get*` read permissions

## Notes
This is a read-only auditing tool — it never modifies IAM policies. It's meant as a starting point for a manual least-privilege review, not a replacement for AWS IAM Access Analyzer or a full policy simulation.
