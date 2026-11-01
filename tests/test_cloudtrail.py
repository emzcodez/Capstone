import json

from analyzer import synthetic as S
from analyzer.iam_graph import build_graph
from collector.cloudtrail import (annotate_graph, caller_arn, cloudtrail_findings, load_events, summarize_usage)

A = S.ACCT


def ev(name, who, t="2026-10-30T10:00:00Z", role=None, err=None, extra=None, resp=None, ip="1.1.1.1"):
    e = {"eventTime": t, "eventName": name, "userIdentity": who, "sourceIPAddress": ip}
    if role:
        e["requestParameters"] = {"roleArn": role}
    if err:
        e["errorCode"] = err
    if extra:
        e["additionalEventData"] = extra
    if resp:
        e["responseElements"] = resp
    return e


BOB = {"type": "IAMUser", "arn": S.arn_user("bob")}
G = build_graph(S.env([S.user("bob", [S.assume("r1")]), S.role("r1", S.trust([("AWS", S.arn_user("bob"))])),
                       S.role("r2", S.trust([("AWS", S.arn_user("bob"))])), S.user("eve")], [S.bucket("b")]))


def test_caller_arn_mapping():
    assert caller_arn(BOB) == S.arn_user("bob")
    assert caller_arn({"type": "AssumedRole", "arn": f"arn:aws:sts::{A}:assumed-role/Dev/sess"}) == S.arn_role("Dev")
    assert caller_arn({"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}) == "service:lambda.amazonaws.com"
    assert caller_arn({"type": "Root"}) == "root"
    assert caller_arn({"type": "Unknown"}) is None


def test_usage_counts_success_and_failures_separately():
    u = summarize_usage([ev("AssumeRole", BOB, role=S.arn_role("r1")),
                         ev("AssumeRole", BOB, role=S.arn_role("r1"), t="2026-10-31T10:00:00Z"),
                         ev("AssumeRole", BOB, role=S.arn_role("r2"), err="AccessDenied")])
    assert u["assume"][(S.arn_user("bob"), S.arn_role("r1"))]["count"] == 2
    assert (S.arn_user("bob"), S.arn_role("r2")) in u["failed_assume"]
    assert u["window"]["days"] == 2


def test_unused_and_unexpected_edges():
    u = summarize_usage([ev("AssumeRole", BOB, role=S.arn_role("r1")),
                         ev("AssumeRole", {"type": "IAMUser", "arn": S.arn_user("eve")}, role=S.arn_role("r1"))])
    link = annotate_graph(G, u)
    assert (S.arn_user("bob"), S.arn_role("r2")) in link["unused"]            # permitted, never used
    assert [(a, b) for a, b, _ in link["unexpected"]] == [(S.arn_user("eve"), S.arn_role("r1"))]


def test_findings_for_probing_console_without_mfa_and_root():
    events = [ev("AssumeRole", BOB, role=S.arn_role("r2"), err="AccessDenied") for _ in range(3)]
    events += [ev("ConsoleLogin", BOB, extra={"MFAUsed": "No"}, resp={"ConsoleLogin": "Success"}),
               ev("ConsoleLogin", BOB, extra={"MFAUsed": "Yes"}, resp={"ConsoleLogin": "Success"}),
               ev("ConsoleLogin", BOB, extra={"MFAUsed": "No"}, resp={"ConsoleLogin": "Failure"}),
               ev("DescribeInstances", {"type": "Root"})]
    u = summarize_usage(events)
    rules = [f["rule"] for f in cloudtrail_findings(G, u, annotate_graph(G, u))]
    assert rules.count("CT_FAILED_ASSUME") == 1 and rules.count("CT_CONSOLE_NO_MFA") == 1   # only the successful no-MFA
    assert "CT_ROOT_USAGE" in rules


def test_few_failures_below_threshold_are_ignored():
    u = summarize_usage([ev("AssumeRole", BOB, role=S.arn_role("r2"), err="AccessDenied")])
    assert "CT_FAILED_ASSUME" not in [f["rule"] for f in cloudtrail_findings(G, u, annotate_graph(G, u))]


def test_load_events_accepts_records_wrapper_and_plain_list(tmp_path):
    e = [ev("AssumeRole", BOB, role=S.arn_role("r1"))]
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps({"Records": e}))
    b.write_text(json.dumps(e))
    assert load_events(str(a)) == load_events(str(b)) == e


def test_empty_events_do_not_crash():
    u = summarize_usage([])
    assert u["window"]["days"] == 0 and cloudtrail_findings(G, u, annotate_graph(G, u)) != []  # all edges unused
