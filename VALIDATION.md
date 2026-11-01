# Validation report (existing code, commit 9e494a2)

Baseline: `pytest` 40/40 passing (only Member 2's risk-detector tests exist at root level).
`python main.py --sample` ran without errors but **silently produced 0 verifications**.

## Bugs found and fixed
| # | Problem | Impact | Fix |
|---|---|---|---|
| 1 | Two incompatible schemas: live collector emits `kind=user/role`, `type=human/non-human`, flat `policies`, bucket type `s3`; sample data / risk detector use `type=user/role`, split policy lists, `s3_bucket` | Live-AWS runs would behave differently from sample runs | `analyzer/schema.py::normalize_data` accepts both and outputs the canonical schema; called in `run_analysis` |
| 2 | `collector/classifier.py` overwrote `identity["type"]` (user/role) with `human`/`non-human` | `select_paths` found no roles; dashboard Kind/Type wrong; classification never recomputed | Replaced with the scoring classifier that only writes `classification` and never touches `type` |
| 3 | `select_paths` filtered `kind` and bucket type `"s3"` | 0 verification paths on sample data | Uses canonical `type`; accepts `s3`/`s3_bucket` |
| 4 | `main.py` called `verify_access(..., use_simulator=, session=)`; real signature takes `iam_client`; passed bucket dict instead of ARN; principal type lost (Federated treated as AWS) | `TypeError` swallowed by fallback, simulator never used | Calls with `iam_client`, resource ARN string and `{"type","value"}` principal |
| 5 | `policy_utils.identity_statements` and `app.py` read `identity["policies"]` | Empty policy view in dashboard | Read attached/inline/group lists |
| 6 | Dashboard type filter excluded `uncertain` identities; `get_identity_kind` hard-coded sample identity names | Uncertain identities invisible; wrong labels for real data | Added `uncertain`; kind derived from trust policy/path |

## Remaining issues (not fixed here)
- Duplicate code: root-level `access_verifier.py`, `aws_collector.py`, `classifier.py`, `sample_data.json`, `test_verifier.py`, plus whole copies in `aws-identity-risk-analyzer/` and `iam_risk_member2/`. Pick `analyzer/` + `collector/` as the single source and delete the rest.
- Offline mode (no simulator) can never reach `allowed`/`blocked` for permissions, hence all `inconclusive`. Addressed by the local evaluator in `analyzer/iam_graph.py`.
- Verifier supports only 5 condition operators; unsupported ones yield `inconclusive`.
- No tests for `main.py`, schema, classifier or collector.
