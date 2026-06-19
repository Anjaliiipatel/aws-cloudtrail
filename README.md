# Cloud Threat Hunting with MITRE ATT&CK for Cloud

A detection engine that hunts for adversary behavior in AWS CloudTrail logs,
built as an extension of the AWS Cloud Guardrail project. Where Guardrail
focuses on *prevention* (catching misconfigurations before they're exploited),
this project focuses on *detection* — finding an attacker who is already
inside, using a realistic simulated compromise as the test case.

This version runs entirely on **synthetic, locally-generated CloudTrail-formatted
logs** — no AWS account, billing, or API calls required. The log schema matches
real CloudTrail output exactly, so `detect.py` works unmodified against a real
account's logs if you later want to point it at one.

## How it works

`generate_logs.py` builds a JSON file of CloudTrail events representing:
- Normal background activity from two legitimate users
- A six-stage simulated attack chain using compromised credentials

`detect.py` loads those events and runs five hunting rules against them,
each mapped to a MITRE ATT&CK for Cloud technique.

```bash
pip install pandas
python generate_logs.py
python detect.py synthetic_cloudtrail_logs.json
```

Findings print to the console and are also written to `findings.json`.

## The simulated incident

| Time (UTC) | Stage | Event | ATT&CK Technique |
|---|---|---|---|
| 14:02 | Initial Access | `ConsoleLogin` from an IP geographically inconsistent with the user's prior login | T1078.004 – Valid Accounts: Cloud Accounts |
| 14:03–14:04 | Discovery | `ListUsers`, `ListRoles`, `GetAccountAuthorizationDetails`, `ListAttachedUserPolicies` | T1087.004 – Account Discovery: Cloud Account / T1526 – Cloud Service Discovery |
| 14:05 | Privilege Escalation | `AttachUserPolicy` granting AdministratorAccess to self | T1098.003 – Account Manipulation: Additional Cloud Roles |
| 14:06 | Persistence | `CreateAccessKey` on an existing service account | T1098.003 |
| 14:08 | Persistence | `CreateUser` — new backdoor account | T1136.003 – Create Account: Cloud Account |
| 14:09 | Defense Evasion | `StopLogging` — disables CloudTrail | T1562.008 – Impair Defenses: Disable Cloud Logs |
| 14:09 | Impact | `AuthorizeSecurityGroupIngress` opens RDP (3389) to 0.0.0.0/0 | T1190 – Exploit Public-Facing Application |
| 14:10 | Impact / Exfil setup | `PutBucketAcl` sets an S3 bucket to public-read | T1530 – Data from Cloud Storage Object |

## Detection logic

- **Impossible travel** — flags console logins by the same identity from
  geographically distant locations in an implausibly short time window
  (haversine distance / elapsed time > plausible travel speed).
- **Recon-then-escalate** — flags privilege-escalating calls
  (`AttachUserPolicy`, `CreateAccessKey`) preceded within 15 minutes by
  two or more discovery-type API calls from the same actor.
- **Dangerous rare calls** — immediately flags any call that should almost
  never fire in normal operation (`StopLogging`, `DeleteTrail`).
- **Persistence** — flags new IAM user creation as a potential backdoor account.
- **Public exposure** — flags security group or S3 ACL/policy changes that
  introduce `0.0.0.0/0` or public-read access.

## Next steps for the full write-up

- [ ] Add an executive summary paragraph (who, what, when, business impact)
- [ ] Add a timeline diagram/visual of the attack chain
- [ ] Add a remediation section per finding (e.g. SCP to block `StopLogging`,
      least-privilege IAM boundary policies, MFA enforcement on console login)
- [ ] Screenshot the console output / findings.json as evidence
- [ ] (Optional) Re-run against real CloudTrail logs from a sandbox AWS account
      once cost is no longer a concern, to validate the rules against live data
- [ ] Wire `findings.json` into the existing AWS Cloud Guardrail Streamlit
      dashboard so posture findings and threat-hunting findings live in one place

## Resume bullets

- Built a cloud threat detection engine simulating a six-stage adversary
  compromise (initial access through impact) in AWS, with custom hunting
  logic across CloudTrail events mapped to MITRE ATT&CK for Cloud.
- Engineered detection rules for privilege escalation chains, impossible
  travel, defense evasion, and persistence, achieving full detection
  coverage against a simulated attack scenario.