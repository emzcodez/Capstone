"""Builders for small IAM environments (tests) and a seeded generator with injected anomalies (evaluation)."""
from __future__ import annotations

import random
from typing import Dict, List, Optional, Sequence, Tuple

ACCT = "111111111111"


def arn_user(name, acct=ACCT):
    return f"arn:aws:iam::{acct}:user/{name}"


def arn_role(name, acct=ACCT):
    return f"arn:aws:iam::{acct}:role/{name}"


def arn_bucket(name):
    return f"arn:aws:s3:::{name}"


def pol(name, actions, resources, effect="Allow", condition=None, **extra):
    st = {"Effect": effect, "Action": actions}
    if "not_action" in extra:
        st = {"Effect": effect, "NotAction": extra["not_action"]}
    if "not_resource" in extra:
        st["NotResource"] = extra["not_resource"]
    else:
        st["Resource"] = resources
    if condition:
        st["Condition"] = condition
    return {"name": name, "document": {"Version": "2012-10-17", "Statement": [st]}}


def bucket_pol(actions="s3:GetObject", principal="*", bucket="b", effect="Allow", condition=None):
    st = {"Effect": effect, "Principal": principal if principal == "*" else {"AWS": principal},
          "Action": actions, "Resource": [arn_bucket(bucket), arn_bucket(bucket) + "/*"]}
    if condition:
        st["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [st]}


def user(name, policies: Sequence[dict] = (), tags=None, console=False, mfa=False, keys=0, acct=ACCT):
    return {"id": arn_user(name, acct), "arn": arn_user(name, acct), "name": name, "type": "user", "kind": "user",
            "path": "/", "tags": tags or {}, "has_console_access": console, "mfa_enabled": mfa,
            "access_keys": [{"id": f"AKIA{i}", "status": "Active", "created": "2025-01-01T00:00:00+00:00"}
                            for i in range(keys)],
            "attached_policies": list(policies), "inline_policies": [], "group_policies": [], "trust_policy": None}


def trust(principals: Sequence[Tuple[str, str]], condition=None, effect="Allow"):
    """principals: [("AWS", arn), ("Service", "lambda.amazonaws.com"), ("AWS", "*")]"""
    stmts = []
    for kind, val in principals:
        st = {"Effect": effect, "Principal": {kind: val},
              "Action": "sts:AssumeRole"}
        if condition:
            st["Condition"] = condition
        stmts.append(st)
    return {"Version": "2012-10-17", "Statement": stmts}


def role(name, trust_policy, policies: Sequence[dict] = (), acct=ACCT, path="/", tags=None):
    return {"id": arn_role(name, acct), "arn": arn_role(name, acct), "name": name, "type": "role", "kind": "role",
            "path": path, "tags": tags or {}, "attached_policies": list(policies), "inline_policies": [],
            "group_policies": [], "trust_policy": trust_policy}


def bucket(name, sensitive=False, policy=None, pab=None):
    return {"id": arn_bucket(name), "arn": arn_bucket(name), "name": name, "type": "s3_bucket",
            "tags": {"Classification": "confidential"} if sensitive else {}, "bucket_policy": policy,
            "public_access_block": pab}


def env(identities, buckets=(), account=ACCT):
    return {"metadata": {"account_id": account}, "identities": list(identities), "resources": list(buckets)}


ADMIN = pol("AdministratorAccess", "*", "*")


def assume(*role_names, acct=ACCT):
    return pol("AssumeRoles", "sts:AssumeRole", [arn_role(r, acct) for r in role_names])


def s3_rw(bucket_name, actions=("s3:GetObject", "s3:PutObject", "s3:ListBucket")):
    return pol(f"S3-{bucket_name}", list(actions), [arn_bucket(bucket_name), arn_bucket(bucket_name) + "/*"])


# ------------------------------------------------------------------ generator
def generate_environment(seed: int = 0, n_teams: int = 6, users_per_team: int = 4,
                         inject: Sequence[str] = ("hub", "overreach", "long_chain", "external_admin")):
    """Teams of identical shape (users -> team role -> team bucket) plus injected anomalies.

    Returns (data, anomalous_arns). Seeded; small random variation keeps teams from being identical."""
    rnd = random.Random(seed)
    ids: List[dict] = []
    buckets: List[dict] = []
    anomalies: set = set()
    team_roles = []
    for t in range(n_teams):
        b, r = f"team{t}-data", f"team{t}-role"
        buckets.append(bucket(b, sensitive=(t == 0)))
        members = [f"u{t}_{k}" for k in range(users_per_team)]
        ids.append(role(r, trust([("AWS", arn_user(m)) for m in members]),
                        [s3_rw(b)]))
        team_roles.append(r)
        for m in members:
            ids.append(user(m, [assume(r)], console=True, mfa=rnd.random() > 0.2))
        if rnd.random() < 0.3:                              # benign variation: a read-only role
            ro = f"team{t}-readonly"
            ids.append(role(ro, trust([("AWS", arn_user(members[0]))]), [s3_rw(b, ("s3:GetObject",))]))
            ids[[i["name"] for i in ids].index(members[0])]["attached_policies"].append(assume(ro))
    names = {i["name"]: i for i in ids}

    if "hub" in inject:                                      # role bridging many teams
        picks = rnd.sample(range(n_teams), min(4, n_teams))
        users = [f"u{t}_0" for t in picks]
        ids.append(role("ops-hub", trust([("AWS", arn_user(u)) for u in users]),
                        [assume(*[team_roles[t] for t in picks])]))
        for u in users:
            names[u]["attached_policies"].append(assume("ops-hub"))
        for t in picks:
            names[team_roles[t]]["trust_policy"]["Statement"].append(
                {"Effect": "Allow", "Principal": {"AWS": arn_role("ops-hub")}, "Action": "sts:AssumeRole"})
        anomalies.add(arn_role("ops-hub"))
    if "overreach" in inject:                                # one user with access to every bucket
        ids.append(user("u_overreach", [pol("S3All", "s3:*", [arn_bucket(b["name"]) for b in buckets]
                                            + [arn_bucket(b["name"]) + "/*" for b in buckets])],
                        console=True, mfa=False))
        anomalies.add(arn_user("u_overreach"))
    if "long_chain" in inject:                               # user -> c1 -> c2 -> c3 -> admin
        start = f"u{rnd.randrange(n_teams)}_1"
        chain = ["chain1", "chain2", "chain3", "chain-admin"]
        prev_arn = arn_user(start)
        for i, c in enumerate(chain):
            nxt = chain[i + 1] if i + 1 < len(chain) else None
            pols = [ADMIN] if nxt is None else [assume(nxt)]
            ids.append(role(c, trust([("AWS", prev_arn)]), pols))
            prev_arn = arn_role(c)
            anomalies.add(arn_role(c))
        names[start]["attached_policies"].append(assume("chain1"))
    if "external_admin" in inject:                           # admin role trusted by an outside account
        ids.append(role("vendor-admin", trust([("AWS", "arn:aws:iam::999999999999:root")]), [ADMIN]))
        anomalies.add(arn_role("vendor-admin"))
    return env(ids, buckets), anomalies
