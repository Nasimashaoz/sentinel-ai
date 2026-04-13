# Sentinel AI — AWS CloudTrail Monitoring

Detect suspicious AWS activity: IAM changes, root usage, S3 policy changes, security group modifications, and more.

## Requirements

```bash
pip install boto3
```

## Enable in `.env`

```env
AWS_ENABLED=true
AWS_DEFAULT_REGION=us-east-1
AWS_LOOKBACK_MINUTES=5

# Credentials (or use IAM role — preferred)
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
```

## IAM Permissions Required

Create a read-only IAM policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "cloudtrail:LookupEvents",
      "cloudtrail:GetTrailStatus"
    ],
    "Resource": "*"
  }]
}
```

## What Gets Detected

| Event | Type | Risk |
|---|---|---|
| Root account login or API call | `AWS_ROOT_USAGE` | CRITICAL |
| CloudTrail logging disabled | `AWS_LOGGING_DISABLED` | CRITICAL |
| IAM user/key creation | `AWS_SUSPICIOUS_API` | HIGH |
| Privilege escalation (AttachPolicy) | `AWS_SUSPICIOUS_API` | HIGH |
| S3 bucket policy changed | `AWS_SUSPICIOUS_API` | HIGH |
| Security group opened | `AWS_SUSPICIOUS_API` | HIGH |
| Unexpected EC2 launch | `AWS_SUSPICIOUS_API` | MEDIUM |
