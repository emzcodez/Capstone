"""Member 2 - risk detection. detect_risks(data) -> list of finding dicts.

Finding schema:
  id, identity, identity_arn, severity (critical|high|medium|low),
  title, reason, resource, remediation
"""
from datetime import datetime, timezone

from analyzer.policy_utils import as_list, identity_statements, statements, trust_principals

INACTIVE_DAYS = 90
PRIV_ESC_ACTIONS = {"iam:passrole", "iam:*", "iam:attachuserpolicy", "iam:putuserpolicy",
                    "iam:createaccesskey", "iam:attachrolepolicy", "sts:assumerole"}


def _f(identity, severity, title, reason, resource, remediation):
    return {"identity": identity.get("name", "N/A"), "identity_arn": identity.get("arn", ""),
            "severity": severity, "title": title, "reason": reason,
            "resource": resource, "remediation": remediation}


def _allow(st):
    return st.get("Effect") == "Allow"


def _check_permissions(identity):
    out = []
    seen = set()
    for pname, st in identity_statements(identity):
        if not _allow(st):
            continue
        actions = [a.lower() for a in as_list(st.get("Action"))]
        resources = as_list(st.get("Resource"))
        wild_res = "*" in resources
        cond = bool(st.get("Condition"))
        res_txt = ", ".join(resources) or "N/A"

        if "*" in actions and wild_res and not cond:
            out.append(_f(identity, "critical", "Full administrator access",
                          f"Policy '{pname}' allows Action '*' on Resource '*'.", "*",
                          "Replace with least-privilege policies scoped to required actions and resources."))
            seen.add("admin")
            continue
        svc_wild = [a for a in actions if a.endswith(":*") and a != "*"]
        if svc_wild:
            sev = "high" if wild_res else "medium"
            out.append(_f(identity, sev, f"Service-wide wildcard ({', '.join(svc_wild)})",
                          f"Policy '{pname}' grants {', '.join(svc_wild)} on {res_txt}.", res_txt,
                          "List only the specific actions needed and restrict Resource to exact ARNs."))
        esc = [a for a in actions if a in PRIV_ESC_ACTIONS and a != "iam:*"]
        if esc and wild_res and "admin" not in seen:
            out.append(_f(identity, "high", "Possible privilege escalation path",
                          f"Policy '{pname}' allows {', '.join(esc)} on Resource '*'.", "*",
                          "Restrict iam:PassRole/iam:Attach*/sts:AssumeRole to specific ARNs and add conditions."))
        s3_wild_res = [a for a in actions if a.startswith("s3:") and not a.endswith(":*")]
        if s3_wild_res and wild_res and not svc_wild:
            out.append(_f(identity, "medium", "S3 access on all buckets",
                          f"Policy '{pname}' allows {', '.join(s3_wild_res)} on every resource.", "*",
                          "Limit Resource to the specific bucket and prefix ARNs required."))
    return out


def _check_trust(identity):
    out = []
    for st in statements(identity.get("trust_policy")):
        if not _allow(st):
            continue
        cond = bool(st.get("Condition"))
        for kind, val in trust_principals(st):
            if kind == "AWS" and val == "*":
                sev = "high" if cond else "critical"
                out.append(_f(identity, sev, "Role can be assumed by anyone",
                              "Trust policy Principal is '*'" + (" (conditions present, review them)." if cond else " with no conditions."),
                              identity.get("arn", ""),
                              "Restrict Principal to specific accounts/roles and add conditions (e.g. sts:ExternalId, aws:PrincipalOrgID)."))
            elif kind == "AWS" and val.endswith(":root") and not cond:
                acct = val.split(":")[4] if val.count(":") >= 5 else "?"
                if acct not in identity.get("arn", ""):
                    out.append(_f(identity, "high", "Cross-account trust without conditions",
                                  f"Entire external account {acct} can assume this role; no ExternalId/condition.",
                                  identity.get("arn", ""),
                                  "Trust a specific role in that account and require sts:ExternalId or aws:PrincipalOrgID."))
    return out


def _check_user_hygiene(identity):
    out = []
    if identity.get("kind") == "user" and identity.get("has_console_access") and not identity.get("mfa_enabled"):
        out.append(_f(identity, "high", "Console user without MFA",
                      "IAM user can sign in to the console but has no MFA device.", identity.get("arn", ""),
                      "Enforce MFA via an IAM policy condition (aws:MultiFactorAuthPresent) and enrol a device."))
    if identity.get("last_used"):
        try:
            last = datetime.fromisoformat(identity["last_used"].replace("Z", "+00:00"))
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - last).days
            if days > INACTIVE_DAYS:
                out.append(_f(identity, "low", "Inactive identity",
                              f"Not used for {days} days (threshold {INACTIVE_DAYS}).", identity.get("arn", ""),
                              "Disable or delete unused identities and credentials."))
        except ValueError:
            pass
    return out


def _check_bucket(bucket):
    out = []
    ident = {"name": "N/A (resource)", "arn": ""}
    for st in statements(bucket.get("policy")):
        p = st.get("Principal")
        public = p == "*" or (isinstance(p, dict) and "*" in as_list(p.get("AWS")))
        if _allow(st) and public and not st.get("Condition"):
            out.append(_f(ident, "critical", "Public S3 bucket policy",
                          f"Bucket '{bucket['name']}' policy allows {', '.join(as_list(st.get('Action')))} to everyone.",
                          bucket["arn"], "Remove the public statement and enable S3 Block Public Access."))
    if not bucket.get("public_access_block"):
        out.append(_f(ident, "medium", "S3 Block Public Access not fully enabled",
                      f"Bucket '{bucket['name']}' does not block all public access settings.", bucket["arn"],
                      "Enable all four Block Public Access settings on the bucket (and account)."))
    return out


def detect_risks(data):
    findings = []
    for ident in data.get("identities", []):
        findings += _check_permissions(ident) + _check_trust(ident) + _check_user_hygiene(ident)
    for res in data.get("resources", []):
        if res.get("type") == "s3":
            findings += _check_bucket(res)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order[f["severity"]])
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:03d}"
    return findings
