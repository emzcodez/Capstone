"""Member 4 - orchestrator. Runs collect -> classify -> detect -> verify.

Usage:  python main.py --sample        (offline demo)
        python main.py --profile myprof [--simulator]
"""
import argparse
import json
import logging
from collections import Counter
from pathlib import Path

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
    buckets = [r for r in data.get("resources", []) if r.get("type") == "s3"]
    for ident in data.get("identities", []):
        if ident.get("kind", "role") != "role":
            continue
        principals = []
        for st in (ident.get("trust_policy") or {}).get("Statement", []):
            if st.get("Effect") != "Allow":
                continue
            from analyzer.policy_utils import trust_principals
            principals += [v for _, v in trust_principals(st)]
        for pr in dict.fromkeys(principals):
            for b in buckets:
                for act in TEST_ACTIONS:
                    if n >= MAX_PATHS:
                        return
                    n += 1
                    yield ident, pr, b, act


def run_analysis(use_sample=False, profile=None, use_simulator=False):
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

    data.setdefault("identities", [])
    data.setdefault("resources", [])

    try:
        from collector.classifier import classify_identities
        data["identities"] = classify_identities(data["identities"])
    except Exception as exc:
        warnings.append(f"Classification failed: {exc}")

    findings, verifications = [], []
    try:
        from analyzer.risk_detector import detect_risks
        findings = detect_risks(data)
    except Exception as exc:
        log.exception("Risk detection failed")
        warnings.append(f"Risk detection failed: {exc}")

    try:
        from analyzer.access_verifier import verify_access
        session = None
        if use_simulator and source == "aws":
            import boto3
            session = boto3.Session(profile_name=profile)
        for ident, principal, bucket, action in select_paths(data):
            try:
                verifications.append(verify_access(ident, principal, bucket, action=action,
                                                   use_simulator=use_simulator and source == "aws",
                                                   session=session))
            except TypeError:  # teammate's verify_access has the 3-arg signature
                verifications.append(verify_access(ident, principal, bucket))
    except Exception as exc:
        log.exception("Verification failed")
        warnings.append(f"Access verification failed: {exc}")

    return {"identities": data["identities"], "resources": data["resources"],
            "findings": findings, "verifications": verifications,
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
    a = ap.parse_args()
    res = run_analysis(use_sample=a.sample, profile=a.profile, use_simulator=a.simulator)
    print(json.dumps(summarize(res), indent=2))
    for w in res["warnings"]:
        print("WARNING:", w)
