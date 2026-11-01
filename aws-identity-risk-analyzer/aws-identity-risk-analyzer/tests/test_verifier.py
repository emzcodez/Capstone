from analyzer.access_verifier import verify_access

BUCKET = {"name": "b", "arn": "arn:aws:s3:::b", "policy": {}}


def role(statements, trust_principal=None, trust_cond=None):
    trust = {"Effect": "Allow", "Principal": trust_principal or {"Service": "ec2.amazonaws.com"},
             "Action": "sts:AssumeRole"}
    if trust_cond:
        trust["Condition"] = trust_cond
    return {"name": "r", "arn": "arn:aws:iam::111111111111:role/r", "trust_policy": {"Statement": [trust]},
            "policies": [{"name": "p", "document": {"Statement": statements}}]}


ALLOW = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}


def test_allowed():
    assert verify_access(role([ALLOW]), "ec2.amazonaws.com", BUCKET)["status"] == "allowed"


def test_blocked_when_not_trusted():
    assert verify_access(role([ALLOW]), "lambda.amazonaws.com", BUCKET)["status"] == "blocked"


def test_blocked_by_explicit_deny():
    deny = {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
    assert verify_access(role([ALLOW, deny]), "ec2.amazonaws.com", BUCKET)["status"] == "blocked"


def test_blocked_implicit_deny():
    other = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::other/*"}
    assert verify_access(role([other]), "ec2.amazonaws.com", BUCKET)["status"] == "blocked"


def test_inconclusive_with_condition():
    cond = dict(ALLOW, Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
    assert verify_access(role([cond]), "ec2.amazonaws.com", BUCKET)["status"] == "inconclusive"


def test_account_root_trust():
    r = role([ALLOW], trust_principal={"AWS": "arn:aws:iam::222222222222:root"})
    assert verify_access(r, "arn:aws:iam::222222222222:user/x", BUCKET)["status"] == "allowed"


def test_result_schema_and_evidence():
    res = verify_access(role([ALLOW]), "ec2.amazonaws.com", BUCKET)
    for key in ("status", "principal", "role", "resource", "action", "evidence"):
        assert key in res
    assert res["evidence"]
