"""Generate deterministic sample CloudTrail events matching data/sample_data.json."""
import json
from datetime import datetime, timedelta, timezone

A = "123456789012"
NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
ev = []

def add(days_ago, hour, name, ident, ip="203.0.113.10", params=None, err=None, extra=None, resp=None):
    t = NOW - timedelta(days=days_ago, hours=hour)
    e = {"eventVersion": "1.08", "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": "sts.amazonaws.com",
         "eventName": name, "awsRegion": "us-east-1", "sourceIPAddress": ip, "userIdentity": ident}
    if params: e["requestParameters"] = params
    if err: e["errorCode"] = err
    if extra: e["additionalEventData"] = extra
    if resp: e["responseElements"] = resp
    ev.append(e)

user = lambda n: {"type": "IAMUser", "arn": f"arn:aws:iam::{A}:user/{n}", "userName": n}
assumed = lambda r: {"type": "AssumedRole", "arn": f"arn:aws:sts::{A}:assumed-role/{r}/session1"}
role = lambda r: f"arn:aws:iam::{A}:role/{r}"

for d in range(1, 15):                                   # bob -> DevRole daily
    add(d, 1, "AssumeRole", user("bob.jones"), params={"roleArn": role("DevRole")})
for d in (2, 5, 9):                                      # DevRole -> DataAdminRole occasionally
    add(d, 3, "AssumeRole", assumed("DevRole"), params={"roleArn": role("DataAdminRole")})
for d in range(1, 8):                                    # lambda service assumes its role
    add(d, 5, "AssumeRole", {"type": "AWSService", "invokedBy": "lambda.amazonaws.com"},
        params={"roleArn": role("lambda-etl-role")}, ip="lambda.amazonaws.com")
for h in range(6):                                       # svc-backup probing the break-glass admin
    add(1, h, "AssumeRole", user("svc-backup"), ip="198.51.100.77",
        params={"roleArn": role("BreakGlassAdmin")}, err="AccessDenied")
add(3, 2, "AssumeRole", user("svc-backup"), ip="198.51.100.77",     # successful but NOT explained by policies
    params={"roleArn": role("DataAdminRole")})
add(4, 0, "ConsoleLogin", user("bob.jones"), extra={"MFAUsed": "No"}, resp={"ConsoleLogin": "Success"})
add(6, 0, "ConsoleLogin", user("alice.smith"), extra={"MFAUsed": "Yes"}, resp={"ConsoleLogin": "Success"})
ev.sort(key=lambda e: e["eventTime"])
json.dump({"Records": ev}, open("data/sample_cloudtrail.json", "w"), indent=2)
print(len(ev), "events")
