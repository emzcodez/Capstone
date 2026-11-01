import json
from datetime import datetime, timezone

import pytest

import main
from analyzer import synthetic as S
from analyzer.anomaly import detect_anomalies, node2vec_embeddings
from analyzer.iam_graph import build_graph
from analyzer.scoring import BASE, score_findings


# ------------------------------------------------------------------ anomaly
def test_anomaly_needs_enough_identities():
    G = build_graph(S.env([S.user("a"), S.user("b")]))
    assert detect_anomalies(G) == []


def test_embeddings_are_deterministic_across_calls():
    data, _ = S.generate_environment(seed=1)
    G = build_graph(data)
    a, b = node2vec_embeddings(G), node2vec_embeddings(G)
    assert all((a[n] == b[n]).all() for n in a)


def test_anomaly_scores_are_normalised_and_sorted():
    data, _ = S.generate_environment(seed=1)
    out = detect_anomalies(build_graph(data))
    scores = [o["score"] for o in out]
    assert scores == sorted(scores, reverse=True) and 0 <= min(scores) and max(scores) == 1.0
    assert all(o["reasons"] for o in out)


def test_injected_structures_rank_above_typical_identity():
    data, injected = S.generate_environment(seed=3)
    out = detect_anomalies(build_graph(data), use_structural=True)
    rank = {o["id"]: i for i, o in enumerate(out)}
    median_rank = sorted(rank[a] for a in injected)[len(injected) // 2]
    assert median_rank < len(out) / 2                       # injected anomalies concentrate in the top half


# ------------------------------------------------------------------ scoring
def finding(identity_arn, name, sev="high", **kw):
    return {"rule": "X", "severity": sev, "identity": name, "identity_arn": identity_arn, "resource": None, **kw}


NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def test_context_raises_score_for_exposed_identity():
    data = S.env([S.role("pub", S.trust([("AWS", "*")]), [S.s3_rw("b")]),
                  S.role("priv", S.trust([("AWS", S.arn_user("u"))]), [S.s3_rw("b")]), S.user("u")],
                 [S.bucket("b", sensitive=True)])
    G = build_graph(data)
    fs = score_findings([finding(S.arn_role("pub"), "pub"), finding(S.arn_role("priv"), "priv")], data, G, now=NOW)
    sc = {f["identity"]: f["score"] for f in fs}
    assert sc["pub"] > sc["priv"] >= BASE["high"]


def test_scores_bounded_and_factors_explain_total():
    data = S.env([S.role("pub", S.trust([("AWS", "*")]), [S.ADMIN]), S.user("x"), S.user("y"), S.user("z")],
                 [S.bucket("b", sensitive=True), S.bucket("c")])
    G = build_graph(data)
    for sev in BASE:
        f = score_findings([finding(S.arn_role("pub"), "pub", sev)], data, G, now=NOW)[0]
        assert 0 <= f["score"] <= 100
        assert sum(x["points"] for x in f["score_factors"] if x["applied"]) == pytest.approx(f["score"], abs=0.11)


def test_severity_tiers_preserved_without_context():
    data = S.env([S.user("u")])
    fs = score_findings([finding(None, "u", s) for s in ("low", "medium", "high", "critical")], data, None, now=NOW)
    assert [f["severity"] for f in fs] == ["critical", "high", "medium", "low"]


def test_condition_and_dormancy_lower_score():
    data = S.env([S.user("u")])
    base = score_findings([finding(None, "u")], data, None, now=NOW)[0]["score"]
    cond = score_findings([finding(None, "u", evidence={"conditional": True})], data, None, now=NOW)[0]["score"]
    assert cond < base


def test_missing_severity_key_uses_risk_field():
    f = score_findings([{"rule": "X", "risk": "Critical", "identity": "u"}], S.env([S.user("u")]), None, now=NOW)[0]
    assert f["severity"] == "critical" and f["score"] >= BASE["critical"]


# ----------------------------------------------------------------- pipeline
@pytest.fixture(scope="module")
def result():
    return main.run_analysis(use_sample=True, cloudtrail="data/sample_cloudtrail.json")


def test_pipeline_has_no_warnings_and_produces_everything(result):
    assert result["warnings"] == []
    for k in ("identities", "findings", "verifications", "graph", "paths", "anomalies"):
        assert result[k], k
    assert result["cloudtrail"] is True


def test_pipeline_finds_the_planted_scenarios(result):
    rules = {f["rule"] for f in result["findings"]}
    assert {"ROLE_CHAIN", "ROLE_CYCLE", "CT_UNEXPECTED_ASSUME", "CT_FAILED_ASSUME", "CT_CONSOLE_NO_MFA",
            "TRUST_PUBLIC_PRINCIPAL", "GRAPH_ANOMALY"} <= rules
    assert any(v["hops"] == 2 and v["status"] == "allowed" for v in result["verifications"] if v.get("hops"))


def test_every_finding_is_dashboard_ready_and_unique(result):
    fs = result["findings"]
    assert len({f["id"] for f in fs}) == len(fs)
    assert all(f.get("title") and f.get("remediation") and 0 <= f["score"] <= 100 and f["priority"] for f in fs)
    assert [f["score"] for f in fs] == sorted((f["score"] for f in fs), reverse=True)


def test_verifications_are_conclusive_offline(result):
    assert all(v["status"] in ("allowed", "blocked") for v in result["verifications"])


def test_result_is_json_serialisable(result):
    json.dumps(result, default=str)


def test_pipeline_survives_without_cloudtrail_and_is_deterministic():
    a = main.run_analysis(use_sample=True)
    b = main.run_analysis(use_sample=True)
    assert a["warnings"] == [] and not a["cloudtrail"]
    assert [(f["id"], f["score"]) for f in a["findings"]] == [(f["id"], f["score"]) for f in b["findings"]]
