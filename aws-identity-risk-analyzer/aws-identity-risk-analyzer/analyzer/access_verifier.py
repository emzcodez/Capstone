"""Member 3 - access-path verification.

verify_access(identity, principal, resource, action="s3:GetObject") answers:
  1. Can `principal` assume the role `identity`?   (trust policy)
  2. Do the role's permissions allow `action` on `resource`? (identity + bucket policy)

Offline evaluation covers: Allow/Deny, wildcards, trust principals.
Not evaluated (reported as evidence): Condition blocks => inconclusive,
SCPs, permission boundaries, session policies, KMS, ACLs.
Optional: use_simulator=True cross-checks with IAM simulate_principal_policy.
Return: {status: allowed|blocked|inconclusive, principal, role, resource, action, evidence[]}
"""
from fnmatch import fnmatchcase

from analyzer.policy_utils import as_list, identity_statements, statements, trust_principals

BUCKET_LEVEL = {"s3:listbucket", "s3:getbucketlocation", "s3:getbucketpolicy",
                "s3:listbucketversions", "s3:getbucketacl"}


def _kind_of(principal):
    if principal.endswith(".amazonaws.com"):
        return "Service"
    if ":saml-provider/" in principal or ":oidc-provider/" in principal:
        return "Federated"
    return "AWS"


def _aws_match(pattern, arn):
    if pattern == "*" or pattern == arn:
        return True
    acct = arn.split(":")[4] if arn.count(":") >= 4 else ""
    return bool(acct) and pattern in (f"arn:aws:iam::{acct}:root", acct)


def _trust_check(identity, principal):
    """Return (outcome, evidence) with outcome in allow|deny|conditional|none."""
    kind = _kind_of(principal)
    outcome, ev = "none", []
    for st in statements(identity.get("trust_policy")):
        acts = [a.lower() for a in as_list(st.get("Action"))]
        if not any(fnmatchcase("sts:assumerole", a) or a.startswith("sts:assumerolewith") for a in acts):
            continue
        for k, v in trust_principals(st):
            if k != kind:
                continue
            hit = _aws_match(v, principal) if k == "AWS" else v == principal
            if not hit:
                continue
            cond = bool(st.get("Condition"))
            if st.get("Effect") == "Deny":
                return "deny", [f"Trust policy explicitly denies {principal}."]
            if cond:
                if outcome != "allow":
                    outcome = "conditional"
                ev.append(f"Trust allows {principal} but only under Condition {st['Condition']} (not evaluated).")
            else:
                outcome = "allow"
                ev.append(f"Trust policy allows {principal} to assume the role (matched Principal '{v}').")
    if outcome == "none":
        ev.append(f"No trust-policy statement lets {principal} assume the role (implicit deny).")
    return outcome, ev


def _target_arn(action, resource_arn):
    if action.lower() in BUCKET_LEVEL or resource_arn.rsplit(":", 1)[-1].count("/"):
        return resource_arn
    return resource_arn + "/*"


def _stmt_matches(st, action, target):
    if "NotAction" in st or "NotResource" in st:
        return "unsupported"
    a_ok = any(fnmatchcase(action.lower(), a.lower()) for a in as_list(st.get("Action")))
    r_ok = any(fnmatchcase(target, r) for r in as_list(st.get("Resource")))
    return a_ok and r_ok


def _permission_check(identity, action, resource_arn):
    target = _target_arn(action, resource_arn)
    ev, allow, cond_allow, deny = [], False, False, False
    for pname, st in identity_statements(identity):
        m = _stmt_matches(st, action, target)
        if m == "unsupported":
            ev.append(f"Policy '{pname}' uses NotAction/NotResource (unsupported, skipped).")
            cond_allow = True
            continue
        if not m:
            continue
        if st.get("Effect") == "Deny":
            if st.get("Condition"):
                ev.append(f"Policy '{pname}' has a conditional Deny (not evaluated).")
                cond_allow = True
            else:
                deny = True
                ev.append(f"Explicit Deny in policy '{pname}' on {target}.")
        elif st.get("Effect") == "Allow":
            if st.get("Condition"):
                cond_allow = True
                ev.append(f"Policy '{pname}' allows {action} on {target} only under Condition {st['Condition']}.")
            else:
                allow = True
                ev.append(f"Policy '{pname}' allows {action} on {target}.")
    if not (allow or cond_allow or deny):
        ev.append(f"No identity policy allows {action} on {target} (implicit deny).")
    return deny, allow, cond_allow, ev


def _bucket_policy_deny(resource, role_arn, action, target):
    ev = []
    for st in statements((resource or {}).get("policy")):
        if st.get("Effect") != "Deny" or st.get("Condition"):
            continue
        p = st.get("Principal")
        who = as_list(p.get("AWS")) if isinstance(p, dict) else as_list(p)
        if any(w == "*" or w == role_arn for w in who) and _stmt_matches(st, action, target) is True:
            ev.append("Bucket policy explicitly denies this role.")
    return ev


def simulate_with_aws(role_arn, action, resource_arn, session=None):
    """Call IAM simulate_principal_policy; returns 'allowed' | 'explicitDeny' | 'implicitDeny'."""
    import boto3
    iam = (session or boto3.Session()).client("iam")
    resp = iam.simulate_principal_policy(PolicySourceArn=role_arn, ActionNames=[action],
                                         ResourceArns=[_target_arn(action, resource_arn)])
    return resp["EvaluationResults"][0]["EvalDecision"]


def verify_access(identity, principal, resource, action="s3:GetObject", use_simulator=False, session=None):
    res_dict = resource if isinstance(resource, dict) else {"arn": resource, "policy": {}}
    res_arn = res_dict.get("arn", "")
    result = {"status": "inconclusive", "principal": principal, "role": identity.get("name", "?"),
              "role_arn": identity.get("arn", ""), "resource": res_arn, "action": action, "evidence": []}
    try:
        t_out, t_ev = _trust_check(identity, principal)
        result["evidence"] += [f"[trust] {e}" for e in t_ev]
        if t_out in ("deny", "none"):
            result["status"] = "blocked"
            return result

        deny, allow, cond, p_ev = _permission_check(identity, action, res_arn)
        result["evidence"] += [f"[permission] {e}" for e in p_ev]
        b_ev = _bucket_policy_deny(res_dict, identity.get("arn", ""), action, _target_arn(action, res_arn))
        result["evidence"] += [f"[resource] {e}" for e in b_ev]

        if use_simulator and identity.get("arn"):
            try:
                dec = simulate_with_aws(identity["arn"], action, res_arn, session)
                result["evidence"].append(f"[simulator] IAM Policy Simulator decision: {dec}.")
                if dec == "allowed" and not (deny or b_ev) and t_out == "allow":
                    result["status"] = "allowed"
                    return result
                if dec in ("explicitDeny", "implicitDeny"):
                    result["status"] = "blocked"
                    return result
            except Exception as exc:  # simulator unavailable -> fall back to offline result
                result["evidence"].append(f"[simulator] unavailable ({exc}); using offline evaluation.")

        if deny or b_ev:
            result["status"] = "blocked"
        elif allow and t_out == "allow":
            result["status"] = "allowed"
        elif (allow or cond) and t_out in ("allow", "conditional"):
            result["status"] = "inconclusive"
            result["evidence"].append("Result depends on Conditions that this tool does not evaluate.")
        else:
            result["status"] = "blocked"
    except Exception as exc:
        result["status"] = "inconclusive"
        result["evidence"].append(f"Verifier error: {exc}")
    return result
