"""Evaluation harness. Usage: python scripts/evaluate.py [--seeds 30] [--out docs/EVALUATION.md]

A. Anomaly detection: Node2Vec+LOF vs baselines on synthetic IAM environments with injected anomalies.
B. Consistency: graph trust logic vs the independent access_verifier.check_trust_policy.
C. Scaling: wall-clock time of the pipeline stages as the environment grows.
"""
import argparse
import random
import statistics as st
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import synthetic as S                                          # noqa: E402
from analyzer.access_verifier import check_trust_policy                      # noqa: E402
from analyzer.anomaly import FEATURE_NAMES, adaptive_k, detect_anomalies, hybrid_matrix, node2vec_embeddings, structural_features  # noqa: E402
from analyzer.iam_graph import build_graph, detect_role_chains, find_access_paths  # noqa: E402


def lof_scores(X, k=5):
    k = adaptive_k(X, k)
    return -LocalOutlierFactor(n_neighbors=k).fit(X).negative_outlier_factor_


def precision_at_k(y, s, k):
    top = np.argsort(-np.asarray(s))[:k]
    return float(np.mean(np.asarray(y)[top]))


def part_a(n_seeds):
    methods = {"random": [], "structural-only LOF": [], "Node2Vec+LOF": [], "Node2Vec+structural LOF": []}
    methods_paired = []
    for seed in range(n_seeds):
        rnd = random.Random(seed)
        data, injected = S.generate_environment(seed=seed, n_teams=rnd.randint(5, 9),
                                                users_per_team=rnd.randint(3, 5))
        G = build_graph(data)
        ids = [n for n, d in G.nodes(data=True) if d.get("kind") in ("user", "role")]
        y = [int(n in injected) for n in ids]
        feats = structural_features(G)
        F = StandardScaler().fit_transform(np.array([feats[n] for n in ids], dtype=float))
        emb = node2vec_embeddings(G, seed=seed)
        E = np.array([emb[n] for n in ids])
        scores = {"random": np.random.default_rng(seed).random(len(ids)),
                  "structural-only LOF": lof_scores(F),
                  "Node2Vec+LOF": lof_scores(E),
                  "Node2Vec+structural LOF": lof_scores(hybrid_matrix(E, np.array([feats[n] for n in ids], dtype=float)))}
        for m, sc in scores.items():
            methods[m].append((roc_auc_score(y, sc), precision_at_k(y, sc, sum(y))))
    d = np.array([h[0] - s_[0] for h, s_ in zip(methods["Node2Vec+structural LOF"], methods["structural-only LOF"])])
    boot = np.random.default_rng(0).choice(d, (5000, len(d))).mean(axis=1)
    paired = (d.mean(), np.percentile(boot, 2.5), np.percentile(boot, 97.5), float((d > 0).mean()))
    return paired, {m: (np.mean([a for a, _ in v]), np.std([a for a, _ in v]),
                np.mean([p for _, p in v]), np.std([p for _, p in v])) for m, v in methods.items()}


def part_b(n_seeds=10):
    agree = total = 0
    mismatches = []
    for seed in range(n_seeds):
        data, _ = S.generate_environment(seed=seed)
        G = build_graph(data)
        ids = {i["arn"]: i for i in data["identities"]}
        for r_arn, r in ids.items():
            if r["type"] != "role":
                continue
            for p_arn in ids:
                if p_arn == r_arn:
                    continue
                legacy = check_trust_policy(r["trust_policy"], p_arn)["status"] == "allowed"
                new = G.has_edge(p_arn, r_arn) or (not legacy and False)
                # graph edges for explicit principals depend on trust only (same account) -> must agree
                total += 1
                agree += (legacy == new)
                if legacy != new and len(mismatches) < 3:
                    mismatches.append((p_arn, r_arn, legacy, new))
    return agree, total, mismatches


def part_c(sizes=(5, 20, 50, 100)):
    rows = []
    for n in sizes:
        data, _ = S.generate_environment(seed=1, n_teams=n, users_per_team=4)
        t0 = time.perf_counter(); G = build_graph(data); t1 = time.perf_counter()
        chains = detect_role_chains(G); t2 = time.perf_counter()
        paths = find_access_paths(G); t3 = time.perf_counter()
        detect_anomalies(G); t4 = time.perf_counter()
        rows.append((n, len(data["identities"]), G.number_of_edges(), t1 - t0, t2 - t1, t3 - t2, t4 - t3,
                     len(chains), len(paths)))
    return rows


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--out")
    a = ap.parse_args()
    (paired, A), (ag, tot, mm), C = part_a(a.seeds), part_b(), part_c()
    lines = ["| Method | ROC-AUC | Precision@k |", "|---|---|---|"]
    lines += [f"| {m} | {x[0]:.3f} ± {x[1]:.3f} | {x[2]:.3f} ± {x[3]:.3f} |" for m, x in A.items()]
    lines.append("")
    lines.append(f"Paired AUC difference, hybrid minus structural-only: {paired[0]:+.3f} "
                 f"(bootstrap 95% CI {paired[1]:+.3f} to {paired[2]:+.3f}); hybrid wins on {100*paired[3]:.0f}% of seeds")
    t = ["| Teams | Identities | Edges | build_graph | role chains | access paths | Node2Vec+LOF | chain findings | paths |",
         "|---|---|---|---|---|---|---|---|---|"]
    t += [f"| {r[0]} | {r[1]} | {r[2]} | {r[3]:.2f}s | {r[4]:.2f}s | {r[5]:.2f}s | {r[6]:.2f}s | {r[7]} | {r[8]} |" for r in C]
    out = "\n".join(["A. Anomaly detection (%d seeded synthetic environments)" % a.seeds, *lines, "",
                     f"B. Trust-evaluation agreement with independent verifier: {ag}/{tot} pairs "
                     f"({100*ag/tot:.1f}%) {mm if mm else ''}", "", "C. Scaling", *t])
    print(out)
    if a.out:
        Path(a.out).write_text(out)
