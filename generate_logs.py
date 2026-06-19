"""
Synthetic CloudTrail Log Generator
----------------------------------
Generates a CloudTrail-formatted JSON log file containing:
  - Benign "normal" admin/dev activity (noise)
  - A realistic multi-stage attack chain simulating compromised
    credentials being used for recon, privilege escalation,
    persistence, defense evasion, and impact

Output matches the real AWS CloudTrail event schema, so detection
logic written against this file ports directly to real CloudTrail
data with zero changes.
"""

import json
import uuid
from datetime import datetime, timedelta

ACCOUNT_ID = "520089507142"
REGION = "us-east-2"

def event(time, source, name, user_arn, user_type, user_name,
          source_ip, user_agent="aws-cli/2.15.0", request_params=None,
          response_elements=None, error_code=None):
    return {
        "eventVersion": "1.08",
        "eventTime": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": REGION,
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "requestParameters": request_params or {},
        "responseElements": response_elements,
        "errorCode": error_code,
        "userIdentity": {
            "type": user_type,
            "arn": user_arn,
            "accountId": ACCOUNT_ID,
            "userName": user_name,
        },
        "eventID": str(uuid.uuid4()),
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": ACCOUNT_ID,
    }


def build_log():
    records = []
    base = datetime(2026, 6, 19, 9, 0, 0)

    # ---------- BENIGN NOISE: normal workday activity ----------
    jsmith_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/jsmith-dev"
    admin_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/admin-anjali"

    records.append(event(base, "signin.amazonaws.com", "ConsoleLogin",
        jsmith_arn, "IAMUser", "jsmith-dev", "24.10.5.12",
        user_agent="Mozilla/5.0", response_elements={"ConsoleLogin": "Success"}))

    records.append(event(base + timedelta(minutes=12), "s3.amazonaws.com",
        "GetObject", jsmith_arn, "IAMUser", "jsmith-dev", "24.10.5.12",
        request_params={"bucketName": "company-docs", "key": "weekly-report.csv"}))

    records.append(event(base + timedelta(minutes=40), "ec2.amazonaws.com",
        "DescribeInstances", admin_arn, "IAMUser", "admin-anjali", "73.15.88.201"))

    records.append(event(base + timedelta(hours=2), "iam.amazonaws.com",
        "ListUsers", admin_arn, "IAMUser", "admin-anjali", "73.15.88.201"))

    records.append(event(base + timedelta(hours=3, minutes=10), "s3.amazonaws.com",
        "PutObject", jsmith_arn, "IAMUser", "jsmith-dev", "24.10.5.12",
        request_params={"bucketName": "company-docs", "key": "notes.txt"}))

    # ---------- ATTACK CHAIN: compromised jsmith-dev credentials ----------
    # Attacker IP is geographically implausible vs. the 09:00 NY login
    attacker_ip = "185.220.101.45"  # simulated Amsterdam exit node
    t = base + timedelta(hours=5, minutes=2)  # 14:02

    # 1. Initial access via valid (stolen) credentials — T1078.004
    records.append(event(t, "signin.amazonaws.com", "ConsoleLogin",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip,
        user_agent="Mozilla/5.0", response_elements={"ConsoleLogin": "Success"}))

    # 2. Discovery / recon burst — T1087.004, T1526
    t += timedelta(seconds=70)
    records.append(event(t, "iam.amazonaws.com", "ListUsers",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip))

    t += timedelta(seconds=15)
    records.append(event(t, "iam.amazonaws.com", "ListRoles",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip))

    t += timedelta(seconds=15)
    records.append(event(t, "iam.amazonaws.com", "GetAccountAuthorizationDetails",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip))

    t += timedelta(seconds=22)
    records.append(event(t, "iam.amazonaws.com", "ListAttachedUserPolicies",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip,
        request_params={"userName": "svc-backup"}))

    # 3. Privilege escalation — T1098.003
    t += timedelta(seconds=93)
    records.append(event(t, "iam.amazonaws.com", "AttachUserPolicy",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip,
        request_params={"userName": "jsmith-dev",
                         "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))

    # 4. Persistence — new access key on existing service account, T1098.003
    t += timedelta(seconds=75)
    records.append(event(t, "iam.amazonaws.com", "CreateAccessKey",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip,
        request_params={"userName": "svc-backup"},
        response_elements={"accessKey": {"accessKeyId": "AKIAFAKEKEY00001", "status": "Active"}}))

    # 5. Persistence — backdoor account, T1136.003
    t += timedelta(seconds=75)
    records.append(event(t, "iam.amazonaws.com", "CreateUser",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip,
        request_params={"userName": "svc-update-01"}))

    # 6. Defense evasion — disable logging, T1562.008
    t += timedelta(seconds=65)
    records.append(event(t, "cloudtrail.amazonaws.com", "StopLogging",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip,
        request_params={"name": "threat-hunt-lab-trail"}))

    # 7. Impact — open RDP to the world, T1190 / Impact
    t += timedelta(seconds=40)
    records.append(event(t, "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip,
        request_params={"groupId": "sg-0a1b2c3d", "ipPermissions": {
            "items": [{"ipProtocol": "tcp", "fromPort": 3389, "toPort": 3389,
                       "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}))

    # 8. Impact — public S3 bucket, T1530
    t += timedelta(seconds=35)
    records.append(event(t, "s3.amazonaws.com", "PutBucketAcl",
        jsmith_arn, "IAMUser", "jsmith-dev", attacker_ip,
        request_params={"bucketName": "company-backups", "accessControlList": "public-read"}))

    return {"Records": records}


if __name__ == "__main__":
    log = build_log()
    with open("synthetic_cloudtrail_logs.json", "w") as f:
        json.dump(log, f, indent=2)
    print(f"Generated {len(log['Records'])} synthetic CloudTrail events -> synthetic_cloudtrail_logs.json")