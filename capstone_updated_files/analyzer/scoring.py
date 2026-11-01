"""Context-aware risk scoring.

score = clamp( severity_base + sum(context adjustments), 0, 100 ), with every adjustment recorded in
`score_factors` so the dashboard can explain it. Context comes from the IAM graph (exposure, reach,
sensitivity), identity metadata (MFA, key age), CloudTrail usage and the anomaly detector.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Dict, List, Optional

import networkx as nx

BASE = {"critical": 75, "high": 55, "medium": 35, "low": 15}
CONTEXT_CAP = 25.0       # max points context can add on top of the severity base (diminishing returns)
PRIORITY = [(75, "P1 - fix now"), (55, "P2 - fix this sprint"), (35, "P3 - plan"), (0, "P4 - monitor")]


def priority_for(score: float) -> str:
    return next(label for floor, label in PRIORITY if score >= floor)


def _lookup(findings_identity: dict, identities: Dict[str, dict], by_name: Dict[str, dict]) -> Optional[dict]:
    return identities.get(findings_identity.get("identity_arn") or "") or by_name.get(findings_identity.get("identity"))


def _key_age_days(identity: dict, now: datetime) -> int:
    ages = []
    for k in identity.get("access_keys", []):
        c = k.get("created")
        if c and k.get("status", "Active") == "Active":
            ages.append((now - datetime.fromisoformat(c)).days)
    return max(ages, default=0)


def score_findings(findings: List[dict], data: dict, G: Optional[nx.MultiDiGraph] = None,
                   usage: Optional[dict] = None, anomalies: Optional[List[dict]] = None,
                   now: Optional[datetime] = None) -> List[dict]:
    now = now or datetime.now(timezone.utc)
    ids = {i["arn"]: i for i in data.get("identities", [])}
    by_name = {i["name"]: i for i in data.get("identities", [])}
    anomaly = {a["id"]: a for a in (anomalies or [])}
    sensitive_buckets = {n for n, d in (G.nodes(data=True) if G else []) if d.get("sensitive")}
    n_buckets = max(1, sum(1 for _, d in (G.nodes(data=True) if G else []) if d.get("kind") == "s3_bucket"))
    out = []
    for f in findings:
        sev = str(f.get("severity") or f.get("risk") or "low").lower()
        base = float(BASE.get(sev, 15))
        factors = [{"factor": f"base severity ({sev})", "points": base, "applied": True}]
        raw = []

        def add(points, why):
            raw.append(points)
            factors.append({"factor": why, "points": points, "applied": False})

        ident = _lookup(f, ids, by_name)
        arn = ident["arn"] if ident else None
        if G is not None and arn in G:
            anc = nx.ancestors(G, arn)
            kinds = {G.nodes[a].get("kind") for a in anc}
            if "public" in kinds:
                add(+12, "assumable by anyone (public principal)")
            elif "external_account" in kinds:
                add(+8, "reachable from an external AWS account")
            desc = nx.descendants(G, arn)
            reach_sensitive = desc & sensitive_buckets
            if reach_sensitive:
                add(+10, f"can reach {len(reach_sensitive)} sensitive bucket(s)")
            reach_buckets = sum(1 for d in desc if G.nodes[d].get("kind") == "s3_bucket")
            if reach_buckets and n_buckets > 1:
                add(round(5 * reach_buckets / n_buckets, 1), f"blast radius: {reach_buckets}/{n_buckets} buckets")
            if G.nodes[arn].get("privilege", 0) == 3:
                add(+8, "identity is full administrator")
        if ident:
            cls = (ident.get("classification") or {}).get("category")
            if ident["type"] == "user" and ident.get("has_console_access") and not ident.get("mfa_enabled"):
                add(+8, "console user without MFA")
            age = _key_age_days(ident, now)
            if age > 90:
                add(+5, f"active access key is {age} days old")
            if cls == "non_human" and ident.get("has_console_access"):
                add(+5, "non-human identity with console access")
            if cls == "uncertain":
                add(+2, "classification uncertain (owner unknown)")
        if usage and ident:
            rec = usage["identities"].get(arn)
            if rec and rec["last_seen"] and (now - rec["last_seen"]).days <= 30:
                add(+5, "identity actively used in last 30 days (exploitable now)")
            elif usage["window"]["days"] >= 30 and not rec:
                add(-6, f"no activity in {usage['window']['days']} days of CloudTrail (dormant)")
            failed = sum(r["count"] for (u, _), r in usage["failed_assume"].items() if u == arn)
            if failed >= 3:
                add(+5, f"{failed} denied role-assumption attempts")
        if arn in anomaly and anomaly[arn]["is_anomaly"]:
            add(round(10 * anomaly[arn]["score"], 1), "graph-embedding anomaly (Node2Vec+LOF)")
        ev = f.get("evidence")
        if isinstance(ev, dict) and ev.get("conditional"):
            add(-10, "access depends on Condition(s)")
        pos, neg = sum(p for p in raw if p > 0), sum(p for p in raw if p < 0)
        bonus = CONTEXT_CAP * (1 - math.exp(-pos / CONTEXT_CAP))
        factors.append({"factor": f"context total {pos:+g} -> {bonus:+.1f} after diminishing returns"
                                  + (f", mitigations {neg:+g}" if neg else ""), "points": round(bonus + neg, 1),
                        "applied": True})
        score = max(0.0, min(100.0, round(base + bonus + neg, 1)))
        out.append({**f, "severity": sev, "score": score, "priority": priority_for(score), "score_factors": factors})
    return sorted(out, key=lambda x: -x["score"])
