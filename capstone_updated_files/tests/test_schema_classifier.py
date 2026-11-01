import json

from analyzer import synthetic as S
from analyzer.schema import normalize_data
from collector.classifier import classify_identities


def test_legacy_schema_is_normalised():
    legacy = {"identities": [
        {"name": "r", "arn": S.arn_role("r"), "kind": "role", "type": "unknown", "path": "/",
         "trust_policy": {"Statement": []},
         "policies": [{"name": "m", "type": "managed", "document": {}}, {"name": "i", "type": "inline", "document": {}},
                      {"name": "ERROR", "type": "error", "document": {}}]},
        {"name": "u", "arn": S.arn_user("u"), "kind": "user", "type": "human", "access_key_count": 2}],
        "resources": [{"name": "b", "type": "s3"}]}
    n = normalize_data(legacy)
    r, u = n["identities"]
    assert r["type"] == "role" and u["type"] == "user"
    assert [p["name"] for p in r["attached_policies"]] == ["m"] and [p["name"] for p in r["inline_policies"]] == ["i"]
    assert len(u["access_keys"]) == 2
    assert n["resources"][0]["type"] == "s3_bucket" and n["resources"][0]["arn"] == "arn:aws:s3:::b"


def test_canonical_schema_is_idempotent():
    d = json.load(open("data/sample_data.json"))
    once = normalize_data(d)
    assert normalize_data(once) == once


def cat(identity):
    return classify_identities([identity])[0]["classification"]["category"]


def test_classifier_never_overwrites_type():
    u = S.user("alice.smith", console=True, mfa=True)
    assert classify_identities([u])[0]["type"] == "user"


def test_classifier_categories():
    assert cat(S.user("alice.smith", console=True, mfa=True)) == "human"
    assert cat(S.user("svc-backup", tags={"Type": "service"}, keys=1)) == "non_human"
    assert cat(S.role("fn", S.trust([("Service", "lambda.amazonaws.com")]))) == "non_human"
    assert cat(S.role("AWSReservedSSO_Admin_x", S.trust([("Federated", "arn:aws:iam::1:saml-provider/AWSSSO_x")]),
                      path="/aws-reserved/sso.amazonaws.com/")) == "human"


def test_ambiguous_identities_are_uncertain_not_guessed():
    assert cat(S.user("legacy-user-01", keys=1)) == "uncertain"          # keys only, weak signal
    assert cat(S.role("x", S.trust([("AWS", "arn:aws:iam::1:root")]))) == "uncertain"
    c = classify_identities([S.user("legacy-user-01", keys=1)])[0]["classification"]
    assert c["needs_review"] and c["signals"]
