# ☁️ AWS Misconfig Detector

Python tool that automatically detects security misconfigurations in AWS infrastructure.

## What it checks

- **S3 Buckets** — public access, encryption, versioning
- **IAM** — overly permissive policies, MFA, old access keys
- **Security Groups** — dangerous open ports (SSH, RDP, databases)

## Technologies used

- Python 3
- boto3 (AWS SDK)
- AWS IAM, S3, EC2

## How to run
```bash
python3 misconfig_detector.py
```

## Example output
```
[CRITICAL] IAM → root-account
Issue: Root account does not have MFA enabled
Recommendation: Enable MFA on the root account immediately.
```
