"""IAM graph construction, multi-hop access verification and role-chain detection.

Graph (networkx.MultiDiGraph)
  nodes : identities (user/role, id = ARN), resources (S3 buckets, id = ARN) and external principal
          nodes: "service:<name>", "federated:<arn>", "external-account:<id>", "public:*"
  edges : etype="assume"  principal -> role   (trust policy allows it AND, where AWS requires it,
                                               the caller's own identity policy allows sts:AssumeRole)
          etype="access"  identity/public -> bucket (identity policy or bucket policy grants actions)

Everything here is OFFLINE policy evaluation (no AWS calls). It ignores SCPs, permission boundaries,
session policies and evaluates no Condition values: a statement with a Condition is reported as
"conditional" rather than allowed. The IAM Policy Simulator remains the ground truth.
"""
from __future__ import annotations

import fnmatch
from typing import Dict, Iterable, List, Optional

import networkx as nx

from .policy_utils import as_list, identity_statements, statements, trust_principals

ALLOWED, CONDITIONAL, DENIED = "allowed", "conditional", "denied"
S3_ACTIONS = {
    "read": "s3:GetObject", "list": "s3:ListBucket", "write": "s3:PutObject",
    "delete": "s3:DeleteObject", "admin": "s3:PutBucketPolicy",
}
ADMIN_PROBES = ["iam:CreateUser", "iam:AttachRolePolicy", "ec2:RunInstances", "s3:DeleteBucket"]
ESCALATION_PROBES = ["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:CreatePolicyVersion",
                     "iam:PassRole", "iam:UpdateAssumeRolePolicy"]
MAX_HOPS = 4


# ------------------------------------------------------------------ helpers
def _glob(patterns, value: str) -> bool:
    return any(fnmatch.fnmatchcase(value.lower(), str(p).lower()) for p in as_list(patterns))


def account_of(arn: str) -> Optional[str]:
    parts = (arn or "").split(":")
    return parts[4] if len(parts) > 4 and parts[4] else None


def _stmt_matches(st: dict, action: str, resource: str) -> bool:
    if "NotAction" in st:
        a_ok = not _glob(st["NotAction"], action)
    else:
        a_ok = _glob(st.get("Action"), action)
    if "NotResource" in st:
        r_ok = not _glob(st["NotResource"], resource)
    else:
        r_ok = _glob(st.get("Resource"), resource) if "Resource" in st else False
    return a_ok and r_ok


def evaluate(identity: dict, action: str, resource: str) -> dict:
    """Offline identity-policy evaluation: returns {decision, evidence}."""
    allow, deny_cond, evidence = [], [], []
    for pname, st in identity_statements(identity):
        if not _stmt_matches(st, action, resource):
            continue
        cond = bool(st.get("Condition"))
        if st.get("Effect") == "Deny":
            if not cond:
                return {"decision": DENIED, "evidence": [f"Explicit Deny in '{pname}'"]}
            deny_cond.append(pname)
        elif st.get("Effect") == "Allow":
            allow.append((pname, cond))
    if not allow:
        return {"decision": DENIED, "evidence": ["No Allow statement (implicit deny)"]}
    unconditional = any(not c for _, c in allow)
    evidence = [f"Allow in '{p}'" + (" (has Condition)" if c else "") for p, c in allow]
    if deny_cond:
        evidence.append(f"Conditional Deny in {deny_cond}")
    decision = ALLOWED if unconditional and not deny_cond else CONDITIONAL
    return {"decision": decision, "evidence": evidence}


def privilege_level(identity: dict) -> int:
    """0 none, 1 limited, 2 sensitive/escalation capable, 3 full admin (offline heuristic)."""
    if all(evaluate(identity, a, "*")["decision"] == ALLOWED for a in ADMIN_PROBES):
        return 3
    if any(evaluate(identity, a, "*")["decision"] != DENIED for a in ESCALATION_PROBES):
        return 2
    if evaluate(identity, S3_ACTIONS["write"], "arn:aws:s3:::x/y")["decision"] != DENIED:
        return 2
    return 1 if list(identity_statements(identity)) else 0


def is_sensitive(resource: dict) -> bool:
    tags = {k.lower(): str(v).lower() for k, v in (resource.get("tags") or {}).items()}
    return resource.get("sensitive") is True or tags.get("classification") in (
        "confidential", "restricted", "secret", "sensitive", "pii")


# --------------------------------------------------------------- build graph
def _principal_node(G, kind: str, value: str) -> str:
    if value == "*":
        nid, attrs = "public:*", dict(kind="public", label="Anyone (*)", external=True)
    elif kind == "Service":
        nid, attrs = f"service:{value}", dict(kind="service", label=value, external=False)
    elif kind == "Federated":
        nid, attrs = f"federated:{value}", dict(kind="federated", label=value.split("/")[-1], external=False)
    else:
        acct = account_of(value) or value
        nid, attrs = f"external-account:{acct}", dict(kind="external_account", label=f"Account {acct}", external=True)
    if nid not in G:
        G.add_node(nid, **attrs)
    return nid


def build_graph(data: dict) -> nx.MultiDiGraph:
    G = nx.MultiDiGraph()
    ids = {i["arn"]: i for i in data.get("identities", [])}
    accounts = {account_of(a) for a in ids} | {(data.get("metadata") or {}).get("account_id")}
    accounts.discard(None)

    for arn, i in ids.items():
        cls = (i.get("classification") or {}).get("category", "uncertain")
        G.add_node(arn, kind=i["type"], label=i["name"], category=cls, privilege=privilege_level(i),
                   external=False)
    buckets = {r["arn"]: r for r in data.get("resources", []) if r.get("type") == "s3_bucket"}
    for arn, r in buckets.items():
        G.add_node(arn, kind="s3_bucket", label=r["name"], sensitive=is_sensitive(r), external=False)

    # ---- assume edges (trust policy x caller's identity policy)
    for role_arn, role in ids.items():
        if role["type"] != "role":
            continue
        for st in statements(role.get("trust_policy")):
            if st.get("Effect") != "Allow" or not any(
                    a.lower() in ("sts:assumerole", "sts:*", "*") or a.lower().startswith("sts:assume")
                    for a in as_list(st.get("Action"))):
                continue
            cond = st.get("Condition") or {}
            cond_keys = sorted({k for kv in cond.values() for k in kv})
            for kind, val in trust_principals(st):
                common = dict(etype="assume", conditional=bool(cond), condition_keys=cond_keys)
                caller_acct = account_of(val)
                targets: List[tuple] = []          # (src_node, needs_identity_policy, evidence)
                if kind == "AWS" and val in ids:
                    needs = caller_acct != account_of(role_arn)
                    targets.append((val, needs, f"Trust names {ids[val]['name']} explicitly"))
                elif kind == "AWS" and val.endswith(":root") and caller_acct in accounts:
                    for arn, i in ids.items():
                        if account_of(arn) == caller_acct and arn != role_arn:
                            targets.append((arn, True, "Trust delegates to account root; caller policy must allow"))
                else:
                    targets.append((_principal_node(G, kind, val), False,
                                    "Trust allows an external/service principal"))
                for src, needs, ev in targets:
                    evidence = [ev]
                    cond_flag = common["conditional"]
                    if needs:
                        res = evaluate(ids[src], "sts:AssumeRole", role_arn)
                        evidence += [f"Caller policy: {e}" for e in res["evidence"]]
                        if res["decision"] == DENIED:
                            continue
                        cond_flag = cond_flag or res["decision"] == CONDITIONAL
                    G.add_edge(src, role_arn, **{**common, "conditional": cond_flag, "evidence": evidence})

    # ---- access edges (identity policies)
    for arn, i in ids.items():
        for b_arn, b in buckets.items():
            granted = {}
            for label, act in S3_ACTIONS.items():
                res_arn = b_arn if label in ("list", "admin") else b_arn + "/*"
                r = evaluate(i, act, res_arn)
                if r["decision"] != DENIED:
                    granted[act] = {"decision": r["decision"], "evidence": r["evidence"]}
            if granted:
                G.add_edge(arn, b_arn, etype="access", actions=granted, via="identity_policy",
                           conditional=all(g["decision"] == CONDITIONAL for g in granted.values()))

    # ---- access edges (bucket policy: public / named principals)
    for b_arn, b in buckets.items():
        pab = b.get("public_access_block") or {}
        public_blocked = bool(pab.get("RestrictPublicBuckets") or pab.get("BlockPublicPolicy"))
        for st in statements(b.get("bucket_policy")):
            if st.get("Effect") != "Allow":
                continue
            cond = bool(st.get("Condition"))
            acts = {}
            for label, act in S3_ACTIONS.items():
                res_arn = b_arn if label in ("list", "admin") else b_arn + "/*"
                if _stmt_matches(st, act, res_arn):
                    acts[act] = {"decision": CONDITIONAL if cond else ALLOWED,
                                 "evidence": ["Bucket policy statement" + (" (has Condition)" if cond else "")]}
            if not acts:
                continue
            for kind, val in trust_principals(st):
                if val == "*":
                    if public_blocked:
                        continue
                    src = _principal_node(G, kind, "*")
                elif val in ids:
                    src = val
                else:
                    continue
                G.add_edge(src, b_arn, etype="access", actions=acts, via="bucket_policy", conditional=cond)
    return G


# ---------------------------------------------------------- multi-hop search
def _assume_hops(G, node, visited) -> Iterable[tuple]:
    for _, dst, k, d in G.out_edges(node, keys=True, data=True):
        if d.get("etype") == "assume" and dst not in visited:
            yield dst, d


def _paths_from(G, source: str, max_hops: int):
    """DFS over assume edges; yield (node_path, [assume edge data]) incl. the zero-hop path."""
    stack = [([source], [])]
    while stack:
        path, edges = stack.pop()
        yield path, edges
        if len(edges) >= max_hops:
            continue
        for dst, d in _assume_hops(G, path[-1], set(path)):
            stack.append((path + [dst], edges + [d]))


def find_access_paths(G, source: Optional[str] = None, target: Optional[str] = None,
                      max_hops: int = MAX_HOPS, action: Optional[str] = None) -> List[dict]:
    """All principal -> (assume)* -> resource paths. Zero-hop paths are direct access."""
    sources = [source] if source else [n for n, d in G.nodes(data=True)
                                       if d.get("kind") not in ("s3_bucket",)]
    results = []
    for s in sources:
        for path, edges in _paths_from(G, s, max_hops):
            last = path[-1]
            for _, res, d in G.out_edges(last, data=True):
                if d.get("etype") != "access" or (target and res != target):
                    continue
                if action and not _glob(list(d["actions"]), action):
                    continue
                conditional = d["conditional"] or any(e["conditional"] for e in edges)
                results.append({
                    "source": s, "source_label": G.nodes[s]["label"], "target": res,
                    "target_label": G.nodes[res]["label"], "path": path,
                    "path_labels": [G.nodes[n]["label"] for n in path], "hops": len(edges),
                    "actions": sorted(d["actions"]), "via": d["via"],
                    "status": CONDITIONAL if conditional else ALLOWED,
                    "sensitive": G.nodes[res].get("sensitive", False),
                    "conditions": sorted({k for e in edges for k in e["condition_keys"]}),
                    "evidence": [x for e in edges for x in e["evidence"]]
                                + [x for a in d["actions"].values() for x in a["evidence"]],
                })
    return results


def verify_multihop(G, source: str, target: str, max_hops: int = MAX_HOPS,
                    action: Optional[str] = None, via: Optional[str] = None) -> dict:
    """Is there a feasible chain source -> ... -> target? Shape mirrors access_verifier.verify_access."""
    paths = find_access_paths(G, source, target, max_hops, action)
    if via:
        paths = [p for p in paths if via in p["path"]]
    base = {"principal": G.nodes[source]["label"] if source in G else source, "role": None,
            "resource": target, "action": action or "s3:*",
            "verification_level": "graph_offline_evaluation", "unresolved": [],
            "disclaimer": "Offline policy evaluation (no SCP/boundary/condition evaluation). "
                          "Confirm with the IAM Policy Simulator."}
    if not paths:
        return {**base, "status": "blocked", "path": [], "hops": None, "actions": [],
                "evidence": [f"No assume/access path within {max_hops} hops"],
                "explanation": "No feasible path found in the IAM graph."}
    best = min(paths, key=lambda p: (p["status"] != ALLOWED, p["hops"]))
    status = "allowed" if best["status"] == ALLOWED else "inconclusive"
    if status == "inconclusive":
        base["unresolved"].append(f"Path depends on Condition keys: {best['conditions'] or ['identity/bucket policy']}")
    return {**base, "status": status, "role": best["path"][-1], "path": best["path_labels"],
            "hops": best["hops"], "actions": best["actions"], "evidence": best["evidence"],
            "explanation": f"{' -> '.join(best['path_labels'])} -> {best['target_label']} "
                           f"({best['hops']} assume hop(s), via {best['via']})"}


# ------------------------------------------------------------ role chains
def detect_role_chains(G, min_hops: int = 2, max_hops: int = MAX_HOPS) -> List[dict]:
    """Findings for assume-role chains (>= min_hops), privilege escalation along them, and cycles."""
    findings, seen = [], set()
    for s, sd in G.nodes(data=True):
        if sd.get("kind") == "s3_bucket":
            continue
        for path, edges in _paths_from(G, s, max_hops):
            if len(edges) < min_hops:
                continue
            key = tuple(path)
            if key in seen:
                continue
            seen.add(key)
            end = G.nodes[path[-1]]
            start_priv, end_priv = sd.get("privilege", 0), end.get("privilege", 0)
            accts = [account_of(n) for n in path if n.startswith("arn:")]
            cross = len({a for a in accts if a}) > 1
            ext_start = bool(sd.get("external"))
            conditional = any(e["conditional"] for e in edges)
            escalation = end_priv > start_priv
            if end_priv == 3 and (ext_start or escalation):
                sev = "critical" if ext_start else "high"
            elif ext_start or (escalation and end_priv >= 2) or cross:
                sev = "high" if ext_start else "medium"
            else:
                sev = "low"
            if conditional and sev != "low":
                sev = {"critical": "high", "high": "medium", "medium": "low"}[sev]
            labels = [G.nodes[n]["label"] for n in path]
            findings.append({
                "rule": "ROLE_CHAIN", "severity": sev, "risk": sev.title(),
                "title": f"Role chain of {len(edges)} hops ending in "
                         f"{'admin' if end_priv == 3 else 'privileged' if end_priv == 2 else 'limited'} role",
                "identity": sd["label"], "identity_arn": s if s.startswith("arn:") else None,
                "resource": path[-1],
                "reason": f"{' -> '.join(labels)}. Start privilege={start_priv}, end privilege={end_priv}"
                          + (", crosses accounts" if cross else "")
                          + (", starts from an external/public principal" if ext_start else "")
                          + (", depends on Conditions" if conditional else ""),
                "evidence": {"path": path, "hops": len(edges), "escalation": escalation,
                             "cross_account": cross, "conditional": conditional},
                "remediation": "Remove unnecessary sts:AssumeRole permissions or tighten the intermediate "
                               "trust policies (specific principals, ExternalId/OrgID, MFA conditions); "
                               "avoid chains that end in administrative roles.",
            })
    paths_kept = [f["evidence"]["path"] for f in findings]
    findings = [f for f in findings if not any(
        len(o) > len(f["evidence"]["path"]) and o[-len(f["evidence"]["path"]):] == f["evidence"]["path"]
        for o in paths_kept)]
    # cycles among identities
    sub = nx.DiGraph((u, v) for u, v, d in G.edges(data=True) if d.get("etype") == "assume"
                     and u.startswith("arn:") and v.startswith("arn:"))
    for cyc in nx.simple_cycles(sub):
        labels = [G.nodes[n]["label"] for n in cyc]
        findings.append({
            "rule": "ROLE_CYCLE", "severity": "medium", "risk": "Medium",
            "title": "Circular role-assumption trust", "identity": labels[0], "identity_arn": cyc[0],
            "resource": cyc[0], "reason": "Roles can assume each other in a loop: " + " -> ".join(labels + labels[:1]),
            "evidence": {"cycle": cyc}, "conditional": False,
            "remediation": "Break the loop: remove one of the mutual trust relationships or sts:AssumeRole grants.",
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: order[f["severity"]])


def graph_to_dict(G) -> dict:
    """JSON-serialisable node/edge lists (for the dashboard)."""
    return {"nodes": [{"id": n, **{k: v for k, v in d.items()}} for n, d in G.nodes(data=True)],
            "edges": [{"source": u, "target": v, "etype": d["etype"], "conditional": d["conditional"],
                       "label": ", ".join(sorted(d["actions"])) if d["etype"] == "access" else "AssumeRole"}
                      for u, v, d in G.edges(data=True)]}


_DOT_STYLE = {"user": ("ellipse", "#cfe8ff"), "role": ("box", "#d9f2d9"), "s3_bucket": ("cylinder", "#ffe9b3"),
              "service": ("hexagon", "#eeeeee"), "federated": ("hexagon", "#eeeeee"),
              "external_account": ("octagon", "#ffd0d0"), "public": ("octagon", "#ff9b9b")}


def to_dot(graph: dict, highlight: Optional[List[str]] = None) -> str:
    """Graphviz DOT for st.graphviz_chart. `highlight` is a node-id path drawn in red."""
    hl = set(zip(highlight or [], (highlight or [])[1:]))
    hn = set(highlight or [])
    lines = ["digraph G {", "rankdir=LR;", 'node [fontname="Helvetica", fontsize=10, style=filled];']
    for n in graph["nodes"]:
        shape, color = _DOT_STYLE.get(n.get("kind"), ("box", "#ffffff"))
        if n.get("kind") == "s3_bucket" and n.get("sensitive"):
            color = "#ffb347"
        pen = ', color="#d00000", penwidth=2' if n["id"] in hn else ""
        label = n["label"].replace('"', "'")
        if n.get("privilege") == 3:
            label += "\\n(admin)"
        lines.append(f'"{n["id"]}" [label="{label}", shape={shape}, fillcolor="{color}"{pen}];')
    for e in graph["edges"]:
        on = (e["source"], e["target"]) in hl
        style = "solid" if e["etype"] == "assume" else "dashed"
        col = "#d00000" if on else ("#999999" if e["etype"] == "access" else "#333333")
        lab = e["label"] if e["etype"] == "assume" else ""
        lines.append(f'"{e["source"]}" -> "{e["target"]}" [style={style}, color="{col}", '
                     f'penwidth={2.5 if on else 1}, label="{lab}", fontsize=8{", fontcolor=red" if on else ""}];')
    lines.append("}")
    return "\n".join(lines)
