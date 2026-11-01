"""Member 4 - orchestrator. Runs collect -> classify -> detect -> verify.

Usage:  python main.py --sample        (offline demo)
        python main.py --profile myprof [--simulator]
"""
import argparse
import json
import logging
from collections import Counter
from pathlib import Path

from analyzer.policy_utils import trust_principals

log = logging.getLogger("analyzer")
SAMPLE_PATH = Path(__file__).parent / "data" / "sample_data.json"
SEVERITIES = ["critical", "high", "medium", "low"]
STATUSES = ["allowed", "blocked", "inconclusive"]
TEST_ACTIONS = ["s3:GetObject"]
MAX_PATHS = 40


def load_sample():
    with open(SAMPLE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def select_paths(data):
    """Yield (role, principal, bucket, action): every trusted principal x S3 bucket."""
    n = 0
    buckets = [r for r in data.get("resources", []) if r.get("type") in ("s3", "s3_bucket")]
    for ident in data.get("identities", []):
        if (ident.get("type") or ident.get("kind")) != "role":
            continue
        principals = []
        for st in (ident.get("trust_policy") or {}).get("Statement", []):
            if st.get("Effect") != "Allow":
                continue
            principals += [(k, v) for k, v in trust_principals(st)]
        for pr in dict.fromkeys(principals):
            for b in buckets:
                for act in TEST_ACTIONS:
                    if n >= MAX_PATHS:
                        return
                    n += 1
                    yield ident, pr, b, act


def load_cloudtrail(cloudtrail, source, profile, days):
    """cloudtrail: None | path to CloudTrail JSON | 'live' (LookupEvents, AWS source only)."""
    if not cloudtrail:
        return []
    from collector.cloudtrail import fetch_cloudtrail_events, load_events
    if cloudtrail == "live":
        if source != "aws":
            return []
        import boto3
        return fetch_cloudtrail_events(boto3.Session(profile_name=profile), days)
    return load_events(cloudtrail)


def offline_verifications(G, data):
    """Graph-based (offline) verification: every direct trusted principal x bucket x TEST_ACTIONS,
    following multi-hop assume chains. Conclusive without the IAM Policy Simulator."""
    from analyzer.iam_graph import verify_multihop
    out = []
    buckets = [n for n, d in G.nodes(data=True) if d.get("kind") == "s3_bucket"]
    for role in [n for n, d in G.nodes(data=True) if d.get("kind") == "role"]:
        srcs = {u for u, _, d in G.in_edges(role, data=True) if d.get("etype") == "assume"}
        for src in sorted(srcs):
            for b in buckets:
                for act in TEST_ACTIONS:
                    if len(out) >= MAX_PATHS:
                        return out
                    v = verify_multihop(G, src, b, action=act, via=role)
                    v["role"] = role
                    out.append(v)
    return out


def run_analysis(use_sample=False, profile=None, use_simulator=False, cloudtrail=None, ct_days=30):
    """Always returns a dict with identities, resources, findings, verifications, source, warnings."""
    warnings, source = [], "sample" if use_sample else "aws"
    try:
        if use_sample:
            data = load_sample()
        else:
            from collector.aws_collector import collect_aws_data
            data = collect_aws_data(profile=profile)
    except Exception as exc:
        log.exception("Collection failed")
        warnings.append(f"AWS collection failed ({type(exc).__name__}: {exc}). Showing sample data instead.")
        data, source = load_sample(), "sample"

    from analyzer.schema import normalize_data
    data = normalize_data(data)

    try:
        from collector.classifier import classify_identities
        data["identities"] = classify_identities(data["identities"])
    except Exception as exc:
        warnings.append(f"Classification failed: {exc}")

    findings, verifications, graph, paths = [], [], None, []
    try:
        from analyzer.risk_detector import detect_risks
        findings = detect_risks(data)
    except Exception as exc:
        log.exception("Risk detection failed")
        warnings.append(f"Risk detection failed: {exc}")

    from analyzer.remediation import enrich_findings
    findings = enrich_findings(findings, data["identities"])

    G = None
    try:
        from analyzer.iam_graph import build_graph, detect_role_chains, find_access_paths, graph_to_dict
        G = build_graph(data)
        paths = sorted(find_access_paths(G), key=lambda p: (-p["hops"], p["source_label"]))[:300]
        findings = findings + detect_role_chains(G)
        graph = graph_to_dict(G)
    except Exception as exc:
        log.exception("Graph analysis failed")
        warnings.append(f"Graph analysis failed: {exc}")

    try:
        from analyzer.access_verifier import verify_access
        iam_client = None
        if use_simulator and source == "aws":
            import boto3
            iam_client = boto3.Session(profile_name=profile).client("iam")
        if not (use_simulator and source == "aws") and G is not None:
            verifications = offline_verifications(G, data)
        else:
            for ident, (kind, value), bucket, action in select_paths(data):
                resource = bucket.get("arn") or f"arn:aws:s3:::{bucket['name']}"
                if action.startswith(("s3:GetObject", "s3:PutObject")):
                    resource += "/*"
                verifications.append(verify_access(ident, {"type": kind, "value": value}, resource,
                                                   action=action, iam_client=iam_client))
    except Exception as exc:
        log.exception("Verification failed")
        warnings.append(f"Access verification failed: {exc}")

    usage, anomalies = None, []
    if G is not None:
        try:
            from analyzer.anomaly import anomaly_findings, detect_anomalies
            anomalies = detect_anomalies(G)
            findings += anomaly_findings(G, anomalies)
        except Exception as exc:
            log.exception("Anomaly detection failed")
            warnings.append(f"Anomaly detection failed: {exc}")
        try:
            events = load_cloudtrail(cloudtrail, source, profile, ct_days)
            if events:
                from collector.cloudtrail import annotate_graph, cloudtrail_findings, summarize_usage
                usage = summarize_usage(events)
                findings += cloudtrail_findings(G, usage, annotate_graph(G, usage))
                graph = graph_to_dict(G)
        except Exception as exc:
            log.exception("CloudTrail integration failed")
            warnings.append(f"CloudTrail integration failed: {exc}")
        try:
            from analyzer.scoring import score_findings
            findings = score_findings(findings, data, G, usage, anomalies)
        except Exception as exc:
            log.exception("Scoring failed")
            warnings.append(f"Risk scoring failed: {exc}")

    for n, f in enumerate(findings, 1):
        f.setdefault("id", f"F-{n:03d}")
    return {"identities": data["identities"], "resources": data["resources"],
            "findings": findings, "verifications": verifications, "graph": graph, "paths": paths,
            "anomalies": anomalies, "cloudtrail": bool(usage),
            "source": source, "warnings": warnings}

def summarize(R):
    identities = R.get("identities", [])
    findings = R.get("findings", [])
    verifications = R.get("verifications", [])

    human = sum(
        i.get("classification", {}).get("category") == "human"
        for i in identities
    )

    non_human = sum(
        i.get("classification", {}).get("category") == "non_human"
        for i in identities
    )

    by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for f in findings:
        severity = str(
            f.get("severity") or f.get("risk") or "low"
        ).lower()

        if severity in by_severity:
            by_severity[severity] += 1

    by_status = {
        "allowed": 0,
        "blocked": 0,
        "inconclusive": 0,
    }

    for v in verifications:
        status = v.get("status", "inconclusive")

        if status in by_status:
            by_status[status] += 1

    return {
        "total_identities": len(identities),
        "human": human,
        "non_human": non_human,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_status": by_status,
    }

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", action="store_true")
    ap.add_argument("--profile")
    ap.add_argument("--simulator", action="store_true")
    ap.add_argument("--cloudtrail", help="CloudTrail JSON file, or 'live' to query AWS")
    ap.add_argument("--days", type=int, default=30)
    a = ap.parse_args()
    res = run_analysis(use_sample=a.sample, profile=a.profile, use_simulator=a.simulator,
                       cloudtrail=a.cloudtrail, ct_days=a.days)
    print(json.dumps(summarize(res), indent=2))
    for w in res["warnings"]:
        print("WARNING:", w)
