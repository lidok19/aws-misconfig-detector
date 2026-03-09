"""
☁️ Cloud Misconfig Detector for AWS/GCP
----------------------------------------
Checks S3 buckets, IAM policies, and Security Groups
for common misconfigurations via boto3.
Can be deployed as an AWS Lambda function.
"""

import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone


# ─────────────────────────────────────────────
# FINDINGS COLLECTOR
# ─────────────────────────────────────────────

findings = []

def add_finding(severity: str, resource_type: str, resource_id: str, issue: str, recommendation: str):
    findings.append({
        "severity": severity,          # CRITICAL / HIGH / MEDIUM / LOW
        "resource_type": resource_type,
        "resource_id": resource_id,
        "issue": issue,
        "recommendation": recommendation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ─────────────────────────────────────────────
# S3 CHECKS
# ─────────────────────────────────────────────

def check_s3_buckets():
    s3 = boto3.client("s3")
    
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"[ERROR] Cannot list S3 buckets: {e}")
        return

    for bucket in buckets:
        name = bucket["Name"]

        # 1. Public ACL check
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    add_finding(
                        "CRITICAL", "S3", name,
                        f"Bucket ACL grants public access to '{uri}'",
                        "Remove public ACL grants; use bucket policies with least privilege."
                    )
        except ClientError:
            pass

        # 2. Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            if not all([
                cfg.get("BlockPublicAcls"),
                cfg.get("IgnorePublicAcls"),
                cfg.get("BlockPublicPolicy"),
                cfg.get("RestrictPublicBuckets"),
            ]):
                add_finding(
                    "HIGH", "S3", name,
                    "Public Access Block is not fully enabled",
                    "Enable all four PublicAccessBlock settings on the bucket."
                )
        except ClientError:
            add_finding(
                "HIGH", "S3", name,
                "Public Access Block configuration is missing",
                "Enable PublicAccessBlock on the bucket."
            )

        # 3. Bucket encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                add_finding(
                    "MEDIUM", "S3", name,
                    "Default server-side encryption is not enabled",
                    "Enable SSE-S3 or SSE-KMS as the default encryption rule."
                )

        # 4. Versioning
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                add_finding(
                    "LOW", "S3", name,
                    "Bucket versioning is not enabled",
                    "Enable versioning to protect against accidental deletion."
                )
        except ClientError:
            pass

        # 5. Bucket policy allows public '*' principal
        try:
            policy_str = s3.get_bucket_policy(Bucket=name).get("Policy", "{}")
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect = stmt.get("Effect", "")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    add_finding(
                        "CRITICAL", "S3", name,
                        "Bucket policy allows public access (Principal: '*')",
                        "Restrict the bucket policy to specific AWS principals."
                    )
        except ClientError:
            pass  # No policy set — fine


# ─────────────────────────────────────────────
# IAM CHECKS
# ─────────────────────────────────────────────

def check_iam_policies():
    iam = boto3.client("iam")

    # --- Customer-managed policies with dangerous actions ---
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            pid = policy["PolicyId"]
            pname = policy["PolicyName"]
            arn = policy["Arn"]
            version_id = policy["DefaultVersionId"]

            try:
                doc = iam.get_policy_version(
                    PolicyArn=arn, VersionId=version_id
                )["PolicyVersion"]["Document"]

                for stmt in doc.get("Statement", []):
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    effect = stmt.get("Effect", "")
                    resource = stmt.get("Resource", "")

                    # Check for wildcard admin
                    if effect == "Allow" and "*" in actions and resource == "*":
                        add_finding(
                            "CRITICAL", "IAM Policy", pname,
                            "Policy grants full admin access (Action: *, Resource: *)",
                            "Apply least privilege — restrict actions and resources."
                        )
                    # Check for dangerous broad actions
                    dangerous = {"iam:*", "sts:*", "s3:*", "ec2:*", "lambda:*"}
                    for act in actions:
                        if act in dangerous and resource == "*":
                            add_finding(
                                "HIGH", "IAM Policy", pname,
                                f"Overly broad action '{act}' on all resources",
                                f"Restrict '{act}' to specific resource ARNs."
                            )
            except ClientError:
                pass

    # --- Root account MFA check ---
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            add_finding(
                "CRITICAL", "IAM", "root-account",
                "Root account does not have MFA enabled",
                "Enable MFA on the root account immediately."
            )
    except ClientError:
        pass

    # --- Users with console access but no MFA ---
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            uname = user["UserName"]
            try:
                iam.get_login_profile(UserName=uname)  # raises if no console access
                mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
                if not mfa_devices:
                    add_finding(
                        "HIGH", "IAM User", uname,
                        "Console user has no MFA device attached",
                        "Enforce MFA for all IAM users with console access."
                    )
            except ClientError:
                pass  # No login profile = programmatic user only

    # --- Access keys older than 90 days ---
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            uname = user["UserName"]
            try:
                keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
                for key in keys:
                    age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                    if age > 90:
                        add_finding(
                            "MEDIUM", "IAM User", uname,
                            f"Access key '{key['AccessKeyId']}' is {age} days old (>90)",
                            "Rotate access keys every 90 days or less."
                        )
            except ClientError:
                pass


# ─────────────────────────────────────────────
# SECURITY GROUP CHECKS
# ─────────────────────────────────────────────

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    2375: "Docker daemon (unencrypted)",
}

def check_security_groups():
    ec2 = boto3.client("ec2")

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", sg_id)
                label = f"{sg_name} ({sg_id})"

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    protocol = rule.get("IpProtocol", "-1")

                    open_to_all_v4 = any(
                        r.get("CidrIp") == "0.0.0.0/0"
                        for r in rule.get("IpRanges", [])
                    )
                    open_to_all_v6 = any(
                        r.get("CidrIpv6") == "::/0"
                        for r in rule.get("Ipv6Ranges", [])
                    )
                    open_to_all = open_to_all_v4 or open_to_all_v6

                    if not open_to_all:
                        continue

                    # All traffic open
                    if protocol == "-1":
                        add_finding(
                            "CRITICAL", "Security Group", label,
                            "All inbound traffic allowed from 0.0.0.0/0 (any protocol/port)",
                            "Restrict inbound rules to required ports and trusted sources."
                        )
                        continue

                    # Check specific sensitive ports
                    for port, svc in SENSITIVE_PORTS.items():
                        if from_port <= port <= to_port:
                            severity = "CRITICAL" if port in (22, 3389) else "HIGH"
                            add_finding(
                                severity, "Security Group", label,
                                f"Port {port} ({svc}) open to the entire internet",
                                f"Restrict port {port} to specific trusted IP ranges."
                            )

                    # Wide port range open
                    if (to_port - from_port) > 100 and protocol in ("tcp", "udp"):
                        add_finding(
                            "HIGH", "Security Group", label,
                            f"Wide port range {from_port}-{to_port} open to 0.0.0.0/0",
                            "Narrow the port range to only what is required."
                        )

    except ClientError as e:
        print(f"[ERROR] Cannot describe security groups: {e}")


# ─────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────

def print_report():
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x["severity"], 9))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in sorted_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print("\n" + "═" * 60)
    print("  ☁️  CLOUD MISCONFIG DETECTOR — REPORT")
    print("═" * 60)
    print(f"  Total findings : {len(sorted_findings)}")
    for sev, cnt in counts.items():
        if cnt:
            print(f"  {sev:<10}: {cnt}")
    print("═" * 60 + "\n")

    for f in sorted_findings:
        print(f"[{f['severity']}] {f['resource_type']} → {f['resource_id']}")
        print(f"  Issue          : {f['issue']}")
        print(f"  Recommendation : {f['recommendation']}")
        print()

    return sorted_findings


# ─────────────────────────────────────────────
# LAMBDA HANDLER  (also works as a plain script)
# ─────────────────────────────────────────────

def lambda_handler(event=None, context=None):
    """
    Entry point for AWS Lambda.
    Also callable directly: python misconfig_detector.py
    """
    global findings
    findings = []  # reset between invocations

    print("[*] Checking S3 buckets …")
    check_s3_buckets()

    print("[*] Checking IAM policies & users …")
    check_iam_policies()

    print("[*] Checking Security Groups …")
    check_security_groups()

    result = print_report()

    # When running as Lambda, return JSON summary
    return {
        "statusCode": 200,
        "total_findings": len(result),
        "findings": result,
    }


if __name__ == "__main__":
    lambda_handler()
