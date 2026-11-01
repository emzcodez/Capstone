"""CloudTrail integration: turn audit events into per-identity / per-edge usage evidence.

Two sources:
  * live  : fetch_cloudtrail_events(session, days)  -> uses cloudtrail:LookupEvents (management events,
            last 90 days only; S3 *data* events are NOT available through LookupEvents)
  * file  : load_events(path)                       -> CloudTrail log files ({"Records": [...]}) or a list

summarize_usage(events) normalises them; annotate_graph() attaches the evidence to the IAM graph;
cloudtrail_findings() produces findings (unused permissions, unexpected assumptions, failed probing,
console login without MFA, root usage).
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

ASSUMED_ROLE_RE = re.compile(r"^arn:aws:sts::(\d+):assumed-role/([^/]+)/")


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# ------------------------------------------------------------------ loading
def load_events(path: str) -> List[dict]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return raw["Records"] if isinstance(raw, dict) else raw


def fetch_cloudtrail_events(session, days: int = 30,
                            event_names=("AssumeRole", "ConsoleLogin"), max_events: int = 5000) -> List[dict]:
    """Fetch management events via LookupEvents (needs cloudtrail:LookupEvents). Failures return []."""
    from botocore.exceptions import BotoCoreError, ClientError
    ct = session.client("cloudtrail")
    start = datetime.now(timezone.utc) - timedelta(days=days)
    events: List[dict] = []
    try:
        for name in event_names:
            pager = ct.get_paginator("lookup_events").paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}], StartTime=start)
            for page in pager:
                for e in page.get("Events", []):
                    events.append(json.loads(e["CloudTrailEvent"]))
                    if len(events) >= max_events:
                        return events
    except (ClientError, BotoCoreError) as exc:
        import logging
        logging.getLogger(__name__).warning("CloudTrail lookup failed: %s", exc)
    return events


# ------------------------------------------------------------ normalisation
def caller_arn(user_identity: dict) -> Optional[str]:
    """Map a CloudTrail userIdentity to the IAM user/role ARN used as a graph node id."""
    t = user_identity.get("type")
    arn = user_identity.get("arn", "")
    if t == "IAMUser":
        return arn
    if t == "AssumedRole":
        m = ASSUMED_ROLE_RE.match(arn)
        return f"arn:aws:iam::{m.group(1)}:role/{m.group(2)}" if m else None
    if t == "AWSService":
        return f"service:{user_identity.get('invokedBy')}"
    if t == "Root":
        return "root"
    return None


def summarize_usage(events: List[dict], window_days: Optional[int] = None) -> dict:
    """Aggregate events. Returns {assume, failed_assume, identities, console_no_mfa, root_events, window}."""
    assume: Dict[tuple, dict] = {}
    failed: Dict[tuple, dict] = {}
    ident: Dict[str, dict] = defaultdict(lambda: {"events": 0, "last_seen": None, "event_names": set(), "ips": set()})
    console_no_mfa, root_events = [], []
    times = []
    for e in events:
        t = _ts(e["eventTime"])
        times.append(t)
        who = caller_arn(e.get("userIdentity", {}))
        if who:
            r = ident[who]
            r["events"] += 1
            r["last_seen"] = max(filter(None, [r["last_seen"], t]))
            r["event_names"].add(e.get("eventName"))
            if e.get("sourceIPAddress"):
                r["ips"].add(e["sourceIPAddress"])
        name = e.get("eventName")
        if name == "AssumeRole":
            role = (e.get("requestParameters") or {}).get("roleArn")
            if not who or not role:
                continue
            bucket = failed if e.get("errorCode") else assume
            rec = bucket.setdefault((who, role), {"count": 0, "first_seen": t, "last_seen": t,
                                                  "ips": set(), "errors": set()})
            rec["count"] += 1
            rec["first_seen"], rec["last_seen"] = min(rec["first_seen"], t), max(rec["last_seen"], t)
            if e.get("sourceIPAddress"):
                rec["ips"].add(e["sourceIPAddress"])
            if e.get("errorCode"):
                rec["errors"].add(e["errorCode"])
        elif name == "ConsoleLogin" and (e.get("responseElements") or {}).get("ConsoleLogin") == "Success":
            if (e.get("additionalEventData") or {}).get("MFAUsed") == "No":
                console_no_mfa.append({"identity": who, "time": e["eventTime"]})
        if who == "root":
            root_events.append({"event": name, "time": e["eventTime"]})
    end = max(times) if times else None
    start = min(times) if times else None
    return {"assume": assume, "failed_assume": failed, "identities": dict(ident),
            "console_no_mfa": console_no_mfa, "root_events": root_events,
            "window": {"start": start, "end": end,
                       "days": window_days or ((end - start).days + 1 if times else 0)}}


# --------------------------------------------------------------- graph link
def annotate_graph(G, usage: dict) -> dict:
    """Attach `observed` data to assume edges; return {'unused': [...], 'unexpected': [...]}."""
    unused, unexpected = [], []
    for u, v, d in G.edges(data=True):
        if d.get("etype") != "assume":
            continue
        rec = usage["assume"].get((u, v))
        d["observed"] = ({"count": rec["count"], "last_seen": rec["last_seen"].isoformat()} if rec else None)
        if not rec and u.startswith("arn:"):          # only judge identity -> role edges
            unused.append((u, v))
    for (u, v), rec in usage["assume"].items():
        if not G.has_edge(u, v) and u in G and v in G:
            unexpected.append((u, v, rec))
    return {"unused": unused, "unexpected": unexpected}


def _label(G, n):
    return G.nodes[n]["label"] if n in G else n.split("/")[-1]


def cloudtrail_findings(G, usage: dict, link: dict, min_failed: int = 3) -> List[dict]:
    out: List[dict] = []
    days = usage["window"]["days"]
    for u, v in link["unused"]:
        out.append({"rule": "CT_UNUSED_ASSUME", "severity": "low", "risk": "Low",
                    "title": "Permitted role assumption never observed",
                    "identity": _label(G, u), "identity_arn": u, "resource": v,
                    "reason": f"{_label(G, u)} may assume {_label(G, v)} but CloudTrail shows no use in "
                              f"{days} day(s) of events. Unused trust is attack surface.",
                    "evidence": {"window_days": days},
                    "remediation": "Remove the unused trust/sts:AssumeRole grant (least privilege)."})
    for u, v, rec in link["unexpected"]:
        out.append({"rule": "CT_UNEXPECTED_ASSUME", "severity": "high", "risk": "High",
                    "title": "Role assumption not explained by collected policies",
                    "identity": _label(G, u), "identity_arn": u, "resource": v,
                    "reason": f"CloudTrail shows {rec['count']} successful assumption(s) of {_label(G, v)} by "
                              f"{_label(G, u)} that the graph does not allow (permission boundary, SCP, "
                              "stale data, or missed policy source).",
                    "evidence": {"count": rec["count"], "ips": sorted(rec["ips"])},
                    "remediation": "Investigate the trust path; refresh collected data; confirm the assumption was authorised."})
    for (u, v), rec in usage["failed_assume"].items():
        if rec["count"] >= min_failed:
            out.append({"rule": "CT_FAILED_ASSUME", "severity": "medium", "risk": "Medium",
                        "title": "Repeated denied role-assumption attempts",
                        "identity": _label(G, u), "identity_arn": u, "resource": v,
                        "reason": f"{rec['count']} denied attempts ({', '.join(sorted(rec['errors']))}) by "
                                  f"{_label(G, u)} to assume {_label(G, v)} - possible probing / misconfigured automation.",
                        "evidence": {"count": rec["count"], "ips": sorted(rec["ips"])},
                        "remediation": "Review the caller; rotate its credentials if the activity is unexpected."})
    for c in usage["console_no_mfa"]:
        out.append({"rule": "CT_CONSOLE_NO_MFA", "severity": "high", "risk": "High",
                    "title": "Console login without MFA", "identity": _label(G, c["identity"] or "?"),
                    "identity_arn": c["identity"], "resource": None,
                    "reason": f"Successful console sign-in without MFA at {c['time']}.",
                    "evidence": c, "remediation": "Enforce MFA via an IAM policy condition (aws:MultiFactorAuthPresent)."})
    if usage["root_events"]:
        out.append({"rule": "CT_ROOT_USAGE", "severity": "critical", "risk": "Critical",
                    "title": "Root account activity observed", "identity": "root", "identity_arn": None,
                    "resource": None, "reason": f"{len(usage['root_events'])} root event(s) in the window.",
                    "evidence": usage["root_events"][:5],
                    "remediation": "Stop using root; enable MFA on root and use IAM roles."})
    return out
