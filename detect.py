"""
Cloud Threat Hunting Detection Engine
--------------------------------------
Loads CloudTrail-formatted JSON logs (real or synthetic) and runs a set
of hunting rules against them, flagging suspicious activity and mapping
each finding to a specific MITRE ATT&CK for Cloud technique.

Usage:
    python detect.py synthetic_cloudtrail_logs.json
"""

import sys
import json
import pandas as pd
from datetime import timedelta

# Static IP -> approx (lat, lon, label) lookup for the impossible-travel
# rule. In a production version, swap this for a real geo-IP API/database.
IP_GEO = {
    "24.10.5.12":      (40.7128, -74.0060, "New York, US"),
    "73.15.88.201":     (40.7306, -73.9352, "Brooklyn, US"),
    "185.220.101.45":   (52.3676, 4.9041,  "Amsterdam, NL"),
}

DISCOVERY_EVENTS = {
    "ListUsers", "ListRoles", "GetAccountAuthorizationDetails",
    "ListAttachedUserPolicies", "ListGroups", "ListPolicies",
}

DANGEROUS_EVENTS = {
    "StopLogging": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    "DeleteTrail": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    "DeleteFlowLogs": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
}

ESCALATION_EVENTS = {
    "AttachUserPolicy": ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
    "PutUserPolicy": ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
    "CreateAccessKey": ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
}

PERSISTENCE_EVENTS = {
    "CreateUser": ("T1136.003", "Create Account: Cloud Account"),
}

PUBLIC_EXPOSURE_RULES = {
    "AuthorizeSecurityGroupIngress": ("T1190", "Exploit Public-Facing Application (exposure setup)"),
    "PutBucketAcl": ("T1530", "Data from Cloud Storage Object"),
    "PutBucketPolicy": ("T1530", "Data from Cloud Storage Object"),
}


def haversine_km(lat1, lon1, lat2, lon2):
    from math import radians, sin, cos, sqrt, atan2
    r = 6371
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * r * atan2(sqrt(a), sqrt(1 - a))


def load_events(path):
    with open(path) as f:
        data = json.load(f)
    df = pd.DataFrame(data["Records"])
    df["eventTime"] = pd.to_datetime(df["eventTime"])
    df["userName"] = df["userIdentity"].apply(lambda u: u.get("userName"))
    return df.sort_values("eventTime").reset_index(drop=True)


def detect_impossible_travel(df, max_plausible_kmh=900):
    findings = []
    logins = df[df["eventName"] == "ConsoleLogin"]
    for user, group in logins.groupby("userName"):
        group = group.sort_values("eventTime")
        prev = None
        for _, row in group.iterrows():
            geo = IP_GEO.get(row["sourceIPAddress"])
            if prev is not None and geo and prev["geo"]:
                hours = (row["eventTime"] - prev["time"]).total_seconds() / 3600
                if hours <= 0:
                    hours = 0.01
                dist = haversine_km(*prev["geo"][:2], *geo[:2])
                speed = dist / hours
                if speed > max_plausible_kmh and prev["geo"][2] != geo[2]:
                    findings.append({
                        "technique": "T1078.004",
                        "technique_name": "Valid Accounts: Cloud Accounts (impossible travel)",
                        "severity": "HIGH",
                        "user": user,
                        "detail": f"Login from {prev['geo'][2]} then {geo[2]} "
                                  f"in {hours:.2f}h (~{speed:.0f} km/h implied)",
                        "eventTime": str(row["eventTime"]),
                    })
            prev = {"time": row["eventTime"], "geo": geo}
    return findings


def detect_recon_then_escalate(df, window_minutes=15):
    findings = []
    for idx, row in df.iterrows():
        if row["eventName"] in ESCALATION_EVENTS:
            tech, name = ESCALATION_EVENTS[row["eventName"]]
            window_start = row["eventTime"] - timedelta(minutes=window_minutes)
            prior = df[(df["eventTime"] >= window_start) &
                       (df["eventTime"] < row["eventTime"]) &
                       (df["userName"] == row["userName"]) &
                       (df["eventName"].isin(DISCOVERY_EVENTS))]
            if len(prior) >= 2:
                findings.append({
                    "technique": tech,
                    "technique_name": name,
                    "severity": "HIGH",
                    "user": row["userName"],
                    "detail": f"{row['eventName']} preceded by {len(prior)} recon calls "
                              f"({', '.join(prior['eventName'].unique())}) within {window_minutes}m",
                    "eventTime": str(row["eventTime"]),
                })
    return findings


def detect_dangerous_calls(df):
    findings = []
    for idx, row in df.iterrows():
        if row["eventName"] in DANGEROUS_EVENTS:
            tech, name = DANGEROUS_EVENTS[row["eventName"]]
            findings.append({
                "technique": tech,
                "technique_name": name,
                "severity": "CRITICAL",
                "user": row["userName"],
                "detail": f"{row['eventName']} called — logging/monitoring impairment",
                "eventTime": str(row["eventTime"]),
            })
    return findings


def detect_persistence(df, window_minutes=15):
    findings = []
    for idx, row in df.iterrows():
        if row["eventName"] in PERSISTENCE_EVENTS:
            tech, name = PERSISTENCE_EVENTS[row["eventName"]]
            findings.append({
                "technique": tech,
                "technique_name": name,
                "severity": "HIGH",
                "user": row["userName"],
                "detail": f"{row['eventName']} — new account created "
                          f"(params: {row['requestParameters']})",
                "eventTime": str(row["eventTime"]),
            })
    return findings


def detect_public_exposure(df):
    findings = []
    for idx, row in df.iterrows():
        if row["eventName"] in PUBLIC_EXPOSURE_RULES:
            params = row["requestParameters"] or {}
            params_str = json.dumps(params)
            if "0.0.0.0/0" in params_str or "public-read" in params_str or "Allow" in params_str:
                tech, name = PUBLIC_EXPOSURE_RULES[row["eventName"]]
                findings.append({
                    "technique": tech,
                    "technique_name": name,
                    "severity": "CRITICAL",
                    "user": row["userName"],
                    "detail": f"{row['eventName']} created public exposure",
                    "eventTime": str(row["eventTime"]),
                })
    return findings


def run(path):
    df = load_events(path)
    findings = []
    findings += detect_impossible_travel(df)
    findings += detect_recon_then_escalate(df)
    findings += detect_dangerous_calls(df)
    findings += detect_persistence(df)
    findings += detect_public_exposure(df)

    findings.sort(key=lambda f: f["eventTime"])

    print(f"\nLoaded {len(df)} events from {path}")
    print(f"Generated {len(findings)} findings\n")
    print(f"{'TIME':<22}{'SEV':<10}{'TECHNIQUE':<32}{'USER':<14}DETAIL")
    print("-" * 110)
    for f in findings:
        print(f"{f['eventTime']:<22}{f['severity']:<10}"
              f"{f['technique'] + ' ' + f['technique_name'][:24]:<32}"
              f"{f['user']:<14}{f['detail'][:50]}")

    with open("findings.json", "w") as out:
        json.dump(findings, out, indent=2)
    print("\nFull findings written to findings.json")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "synthetic_cloudtrail_logs.json"
    run(path)