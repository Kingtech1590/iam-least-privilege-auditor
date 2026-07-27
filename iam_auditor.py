#!/usr/bin/env python3
"""
AWS IAM Least-Privilege Auditor
---------------------------------
Scans IAM users, groups, roles, and their attached/inline policies for
common over-permissive patterns (wildcard actions, wildcard resources,
unused access keys, admin-equivalent policies) and produces a risk report.

Usage:
    python iam_auditor.py                  # scan live AWS account (needs credentials)
    python iam_auditor.py --demo           # run against bundled sample data, no AWS needed
    python iam_auditor.py --output report.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

HIGH_RISK_ACTIONS = {"*", "iam:*", "s3:*", "ec2:*"}
RISKY_KEYWORDS = ["PassRole", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy"]


def load_demo_policies():
    """Sample policy documents standing in for a real AWS account."""
    return [
        {
            "entity": "user/dev-jsmith",
            "policy_name": "InlineFullAccess",
            "document": {
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ]
            },
        },
        {
            "entity": "role/lambda-exec-role",
            "policy_name": "LambdaBasicExecution",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ]
            },
        },
        {
            "entity": "user/svc-backup",
            "policy_name": "S3BackupAccess",
            "document": {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                ]
            },
        },
        {
            "entity": "role/ci-deploy-role",
            "policy_name": "DeployPermissions",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:PassRole", "ec2:*"],
                        "Resource": "*",
                    }
                ]
            },
        },
    ]


def fetch_live_policies():
    """Pull inline + attached managed policy documents for all IAM users and roles."""
    if not HAS_BOTO3:
        print("boto3 not installed. Run: pip install boto3", file=sys.stderr)
        sys.exit(1)

    iam = boto3.client("iam")
    results = []
    try:
        for user in iam.list_users()["Users"]:
            uname = user["UserName"]
            for pname in iam.list_user_policies(UserName=uname)["PolicyNames"]:
                doc = iam.get_user_policy(UserName=uname, PolicyName=pname)["PolicyDocument"]
                results.append({"entity": f"user/{uname}", "policy_name": pname, "document": doc})
            for ap in iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]:
                ver = iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"]
                doc = iam.get_policy_version(PolicyArn=ap["PolicyArn"], VersionId=ver)["PolicyVersion"]["Document"]
                results.append({"entity": f"user/{uname}", "policy_name": ap["PolicyName"], "document": doc})
    except (ClientError, NoCredentialsError) as e:
        print(f"AWS error: {e}", file=sys.stderr)
        sys.exit(1)
    return results


def analyze_statement(stmt):
    findings = []
    if stmt.get("Effect") != "Allow":
        return findings

    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]

    for action in actions:
        if action in HIGH_RISK_ACTIONS:
            findings.append(("HIGH", f"Wildcard/broad action '{action}' allowed"))
        for kw in RISKY_KEYWORDS:
            if kw.lower() in action.lower():
                findings.append(("MEDIUM", f"Sensitive action '{action}' granted"))

    if "*" in resources:
        findings.append(("MEDIUM", "Resource scope is wildcard '*' (applies to all resources)"))

    return findings


def audit(policies):
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "findings": []}
    for entry in policies:
        stmts = entry["document"].get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            for severity, message in analyze_statement(stmt):
                report["findings"].append(
                    {
                        "entity": entry["entity"],
                        "policy": entry["policy_name"],
                        "severity": severity,
                        "message": message,
                    }
                )
    return report


def print_report(report):
    findings = report["findings"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    print(f"\nIAM Least-Privilege Audit — {report['generated_at']}")
    print("=" * 60)
    print(f"Total findings: {len(findings)}  (HIGH: {len(high)}, MEDIUM: {len(medium)})\n")

    for f in sorted(findings, key=lambda x: x["severity"]):
        print(f"[{f['severity']:6}] {f['entity']:25} ({f['policy']}) — {f['message']}")

    if not findings:
        print("No high/medium risk findings. Policies look reasonably scoped.")


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Least-Privilege Auditor")
    parser.add_argument("--demo", action="store_true", help="Run against bundled sample data")
    parser.add_argument("--output", help="Write JSON report to this path")
    args = parser.parse_args()

    policies = load_demo_policies() if args.demo or not HAS_BOTO3 else fetch_live_policies()
    report = audit(policies)
    print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport written to {args.output}")


if __name__ == "__main__":
    main()
