import main
from collector.classifier import classify_identities


def test_sample_run_has_all_keys():
    r = main.run_analysis(use_sample=True)
    for k in ("identities", "resources", "findings", "verifications", "source", "warnings"):
        assert k in r
    assert r["findings"] and r["verifications"]


def test_all_three_statuses_present_in_sample():
    s = main.summarize(main.run_analysis(use_sample=True))
    assert all(s["by_status"][x] > 0 for x in main.STATUSES)


def test_summary_counts_consistent():
    s = main.summarize(main.run_analysis(use_sample=True))
    assert s["human"] + s["non_human"] == s["total_identities"]
    assert sum(s["by_severity"].values()) == s["total_findings"]


def test_aws_failure_falls_back_to_sample(monkeypatch):
    import collector.aws_collector as c
    monkeypatch.setattr(c, "collect_aws_data", lambda **kw: (_ for _ in ()).throw(RuntimeError("no creds")))
    r = main.run_analysis(use_sample=False)
    assert r["source"] == "sample" and any("failed" in w for w in r["warnings"])


def test_detector_failure_is_contained(monkeypatch):
    import analyzer.risk_detector as d
    monkeypatch.setattr(d, "detect_risks", lambda data: 1 / 0)
    r = main.run_analysis(use_sample=True)
    assert r["findings"] == [] and any("Risk detection failed" in w for w in r["warnings"])


def test_classifier_rules():
    out = classify_identities([
        {"name": "x", "kind": "role", "trust_policy": {"Statement": [{"Principal": {"Service": "ec2.amazonaws.com"}}]}},
        {"name": "svc-a", "kind": "user"},
        {"name": "joe", "kind": "user", "has_console_access": True}])
    assert [i["type"] for i in out] == ["non-human", "non-human", "human"]
