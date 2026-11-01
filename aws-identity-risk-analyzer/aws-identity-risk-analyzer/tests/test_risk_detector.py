from analyzer.risk_detector import detect_risks


def ident(name, policies=None, trust=None, **kw):
    d = {"name": name, "arn": f"arn:aws:iam::111111111111:role/{name}", "kind": "role",
         "policies": policies or [], "trust_policy": trust or {}}
    d.update(kw)
    return d


def pol(*stmts):
    return {"name": "p", "document": {"Statement": list(stmts)}}


def titles(findings):
    return {f["title"] for f in findings}


def test_admin_wildcard_is_critical():
    f = detect_risks({"identities": [ident("a", [pol({"Effect": "Allow", "Action": "*", "Resource": "*"})])]})
    assert f[0]["severity"] == "critical"


def test_open_trust_detected():
    t = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    assert "Role can be assumed by anyone" in titles(detect_risks({"identities": [ident("o", trust=t)]}))


def test_least_privilege_role_is_clean():
    p = pol({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    assert detect_risks({"identities": [ident("ok", [p])]}) == []


def test_console_user_without_mfa():
    u = ident("u", kind="user", has_console_access=True, mfa_enabled=False)
    assert "Console user without MFA" in titles(detect_risks({"identities": [u]}))


def test_public_bucket():
    b = {"name": "b", "type": "s3", "arn": "arn:aws:s3:::b", "public_access_block": True,
         "policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}}
    assert "Public S3 bucket policy" in titles(detect_risks({"resources": [b]}))


def test_findings_have_required_fields():
    f = detect_risks({"identities": [ident("a", [pol({"Effect": "Allow", "Action": "*", "Resource": "*"})])]})
    for key in ("id", "identity", "severity", "title", "reason", "resource", "remediation"):
        assert key in f[0]
