import pytest

from analyzer import synthetic as S
from analyzer.iam_graph import (ALLOWED, CONDITIONAL, DENIED, build_graph, detect_role_chains, evaluate,
                                find_access_paths, privilege_level, verify_multihop)

B = "data"
BA = S.arn_bucket(B)


def graph(identities, buckets=None):
    return build_graph(S.env(identities, buckets or [S.bucket(B)]))


# ------------------------------------------------------------- evaluate()
def test_allow_and_implicit_deny():
    u = S.user("u", [S.s3_rw(B)])
    assert evaluate(u, "s3:GetObject", BA + "/k")["decision"] == ALLOWED
    assert evaluate(u, "s3:DeleteObject", BA + "/k")["decision"] == DENIED
    assert evaluate(u, "s3:GetObject", S.arn_bucket("other") + "/k")["decision"] == DENIED


def test_explicit_deny_overrides_allow():
    u = S.user("u", [S.s3_rw(B), S.pol("Deny", "s3:GetObject", "*", effect="Deny")])
    assert evaluate(u, "s3:GetObject", BA + "/k")["decision"] == DENIED


def test_condition_makes_allow_conditional():
    u = S.user("u", [S.pol("P", "s3:GetObject", "*", condition={"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}})])
    assert evaluate(u, "s3:GetObject", BA + "/k")["decision"] == CONDITIONAL


def test_conditional_deny_downgrades_allow():
    u = S.user("u", [S.s3_rw(B), S.pol("D", "s3:*", "*", effect="Deny", condition={"Bool": {"aws:SecureTransport": "false"}})])
    assert evaluate(u, "s3:GetObject", BA + "/k")["decision"] == CONDITIONAL


def test_notaction_and_notresource():
    u = S.user("u", [S.pol("NA", None, "*", not_action=["iam:*"])])
    assert evaluate(u, "s3:GetObject", BA)["decision"] == ALLOWED
    assert evaluate(u, "iam:CreateUser", "*")["decision"] == DENIED
    u2 = S.user("u2", [S.pol("NR", "s3:*", None, not_resource=[BA + "/*"])])
    assert evaluate(u2, "s3:GetObject", BA + "/k")["decision"] == DENIED
    assert evaluate(u2, "s3:GetObject", S.arn_bucket("zzz") + "/k")["decision"] == ALLOWED


def test_privilege_levels():
    assert privilege_level(S.user("a", [S.ADMIN])) == 3
    assert privilege_level(S.user("b", [S.pol("I", "iam:AttachRolePolicy", "*")])) == 2
    assert privilege_level(S.user("c", [S.pol("R", "s3:GetObject", "*")])) == 1
    assert privilege_level(S.user("d")) == 0


# ------------------------------------------------------------ assume edges
def test_explicit_same_account_trust_needs_no_caller_policy():
    G = graph([S.user("alice"), S.role("r", S.trust([("AWS", S.arn_user("alice"))]), [S.s3_rw(B)])])
    assert G.has_edge(S.arn_user("alice"), S.arn_role("r"))


def test_account_root_trust_requires_caller_allow():
    t = S.trust([("AWS", f"arn:aws:iam::{S.ACCT}:root")])
    no = graph([S.user("alice"), S.role("r", t)])
    yes = graph([S.user("alice", [S.assume("r")]), S.role("r", t)])
    assert not no.has_edge(S.arn_user("alice"), S.arn_role("r"))
    assert yes.has_edge(S.arn_user("alice"), S.arn_role("r"))


def test_caller_explicit_deny_blocks_root_trust_edge():
    t = S.trust([("AWS", f"arn:aws:iam::{S.ACCT}:root")])
    a = S.user("alice", [S.assume("r"), S.pol("D", "sts:AssumeRole", "*", effect="Deny")])
    assert not graph([a, S.role("r", t)]).has_edge(S.arn_user("alice"), S.arn_role("r"))


def test_external_service_and_public_principals():
    G = graph([S.role("ext", S.trust([("AWS", "arn:aws:iam::999999999999:root")])),
               S.role("svc", S.trust([("Service", "lambda.amazonaws.com")])),
               S.role("pub", S.trust([("AWS", "*")]))])
    assert G.has_edge("external-account:999999999999", S.arn_role("ext"))
    assert G.has_edge("service:lambda.amazonaws.com", S.arn_role("svc"))
    assert G.has_edge("public:*", S.arn_role("pub"))
    assert G.nodes["public:*"]["external"] and G.nodes["external-account:999999999999"]["external"]


def test_trust_condition_marks_edge_conditional():
    t = S.trust([("AWS", S.arn_user("alice"))], condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})
    G = graph([S.user("alice"), S.role("r", t, [S.s3_rw(B)])])
    e = next(iter(G.get_edge_data(S.arn_user("alice"), S.arn_role("r")).values()))
    assert e["conditional"] and e["condition_keys"] == ["aws:MultiFactorAuthPresent"]
    v = verify_multihop(G, S.arn_user("alice"), BA, action="s3:GetObject")
    assert v["status"] == "inconclusive" and v["unresolved"]


# ------------------------------------------------------------- multi-hop
def chain_env(n):
    ids = [S.user("alice", [S.assume("c1")])]
    for i in range(1, n + 1):
        prev = S.arn_user("alice") if i == 1 else S.arn_role(f"c{i-1}")
        pols = [S.assume(f"c{i+1}")] if i < n else [S.s3_rw(B)]
        ids.append(S.role(f"c{i}", S.trust([("AWS", prev)]), pols))
    return graph(ids)


def test_multihop_reaches_bucket_and_reports_path():
    G = chain_env(3)
    v = verify_multihop(G, S.arn_user("alice"), BA, action="s3:GetObject")
    assert v["status"] == "allowed" and v["hops"] == 3
    assert v["path"] == ["alice", "c1", "c2", "c3"]


def test_hop_limit_blocks():
    assert verify_multihop(chain_env(3), S.arn_user("alice"), BA, max_hops=2)["status"] == "blocked"


def test_action_not_granted_is_blocked():
    v = verify_multihop(chain_env(2), S.arn_user("alice"), BA, action="s3:PutBucketPolicy")
    assert v["status"] == "blocked"


def test_via_constrains_to_role():
    G = chain_env(2)
    assert verify_multihop(G, S.arn_user("alice"), BA, via=S.arn_role("c2"))["status"] == "allowed"
    assert verify_multihop(G, S.arn_user("alice"), BA, via=S.arn_role("nope"))["status"] == "blocked"


def test_cycle_terminates_and_is_reported():
    ids = [S.role("a", S.trust([("AWS", S.arn_role("b"))]), [S.assume("b")]),
           S.role("b", S.trust([("AWS", S.arn_role("a"))]), [S.assume("a")])]
    G = graph(ids)
    assert find_access_paths(G) == []                       # terminates
    assert any(f["rule"] == "ROLE_CYCLE" for f in detect_role_chains(G))


# ---------------------------------------------------------- bucket policy
def test_public_bucket_policy_creates_public_edge_unless_blocked():
    pol_ = S.bucket_pol("s3:GetObject", "*", B)
    G = graph([], [S.bucket(B, policy=pol_)])
    assert G.has_edge("public:*", BA)
    blocked = graph([], [S.bucket(B, policy=pol_, pab={"BlockPublicPolicy": True, "RestrictPublicBuckets": True})])
    assert not blocked.has_node("public:*") or not blocked.has_edge("public:*", BA)


# ------------------------------------------------------------ role chains
def test_chain_from_external_to_admin_is_critical():
    ids = [S.role("entry", S.trust([("AWS", "arn:aws:iam::999999999999:root")]), [S.assume("mid")]),
           S.role("mid", S.trust([("AWS", S.arn_role("entry"))]), [S.assume("root-ish")]),
           S.role("root-ish", S.trust([("AWS", S.arn_role("mid"))]), [S.ADMIN])]
    fs = detect_role_chains(graph(ids))
    assert fs and fs[0]["severity"] == "critical" and fs[0]["rule"] == "ROLE_CHAIN"


def test_escalation_chain_from_limited_user_is_high_and_subchains_deduped():
    ids = [S.user("bob", [S.assume("dev")]),
           S.role("dev", S.trust([("AWS", S.arn_user("bob"))]), [S.assume("adm")]),
           S.role("adm", S.trust([("AWS", S.arn_role("dev"))]), [S.ADMIN])]
    fs = [f for f in detect_role_chains(graph(ids)) if f["rule"] == "ROLE_CHAIN"]
    assert len(fs) == 1 and fs[0]["severity"] == "high" and fs[0]["evidence"]["hops"] == 2


def test_single_hop_is_not_a_chain():
    ids = [S.user("bob", [S.assume("r")]), S.role("r", S.trust([("AWS", S.arn_user("bob"))]), [S.ADMIN])]
    assert detect_role_chains(graph(ids)) == []
