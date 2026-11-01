"""Graph-embedding anomaly detection: Node2Vec (biased walks + skip-gram) -> Local Outlier Factor.

Idea: identities whose *position in the IAM graph* differs from their peers (unusual neighbourhood,
hub-like reach, odd privilege/connectivity mix) land far from the dense cluster in embedding space and
get a high LOF score. This highlights identities worth a human look; it is NOT a proof of risk.

Walks run on the undirected view of the graph (so sinks like buckets get context); edge weights bias
the walks (assume edges stronger than access edges). Everything is seeded and uses a stable hash, so
results are reproducible across runs/processes.
"""
from __future__ import annotations

import zlib
from typing import Dict, List, Optional

import networkx as nx
import numpy as np
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

WEIGHTS = {"assume": 2.0, "access": 1.0}


def _stable_hash(s: str) -> int:
    return zlib.crc32(str(s).encode())


def _weighted_undirected(G) -> nx.Graph:
    U = nx.Graph()
    U.add_nodes_from(G.nodes())
    for u, v, d in G.edges(data=True):
        w = WEIGHTS.get(d.get("etype"), 1.0)
        if U.has_edge(u, v):
            U[u][v]["weight"] += w
        else:
            U.add_edge(u, v, weight=w)
    return U


def _walks(U: nx.Graph, num_walks: int, walk_length: int, p: float, q: float, seed: int) -> List[List[str]]:
    """Node2Vec second-order biased random walks."""
    rng = np.random.default_rng(seed)
    nodes = sorted(U.nodes())
    out = []
    for _ in range(num_walks):
        order = list(rng.permutation(nodes))
        for start in order:
            walk = [start]
            while len(walk) < walk_length:
                cur = walk[-1]
                nbrs = sorted(U.neighbors(cur))
                if not nbrs:
                    break
                if len(walk) == 1:
                    probs = np.array([U[cur][n]["weight"] for n in nbrs], dtype=float)
                else:
                    prev = walk[-2]
                    probs = np.array([
                        U[cur][n]["weight"] * (1 / p if n == prev else 1.0 if U.has_edge(n, prev) else 1 / q)
                        for n in nbrs], dtype=float)
                walk.append(nbrs[int(rng.choice(len(nbrs), p=probs / probs.sum()))])
            out.append(walk)
    return out


def node2vec_embeddings(G, dim: int = 32, num_walks: int = 30, walk_length: int = 12, p: float = 1.0,
                        q: float = 2.0, window: int = 4, seed: int = 42) -> Dict[str, np.ndarray]:
    """Return {node_id: vector}. Falls back to a spectral embedding if gensim is unavailable."""
    U = _weighted_undirected(G)
    try:
        from gensim.models import Word2Vec
        walks = _walks(U, num_walks, walk_length, p, q, seed)
        model = Word2Vec(walks, vector_size=dim, window=window, min_count=1, sg=1, workers=1,
                         epochs=20, seed=seed, hashfxn=_stable_hash)
        return {n: model.wv[n] for n in U.nodes()}
    except ImportError:                                     # pragma: no cover
        nodes = sorted(U.nodes())
        A = nx.to_numpy_array(U, nodelist=nodes, weight="weight")
        u, s, _ = np.linalg.svd(A)
        k = min(dim, len(nodes))
        emb = u[:, :k] * np.sqrt(s[:k])
        return {n: emb[i] for i, n in enumerate(nodes)}


def structural_features(G) -> Dict[str, List[float]]:
    """Interpretable features used both for explanation and (optionally) concatenated to embeddings."""
    feats = {}
    for n, d in G.nodes(data=True):
        assume_in = sum(1 for _, _, e in G.in_edges(n, data=True) if e.get("etype") == "assume")
        assume_out = sum(1 for _, _, e in G.out_edges(n, data=True) if e.get("etype") == "assume")
        access_out = sum(1 for _, _, e in G.out_edges(n, data=True) if e.get("etype") == "access")
        feats[n] = [assume_in, assume_out, access_out, d.get("privilege", 0),
                    len(nx.descendants(G, n))]
    return feats


FEATURE_NAMES = ["assume_in", "assume_out", "access_out", "privilege", "reachable_nodes"]


def hybrid_matrix(E, F):
    """Concatenate standardised embeddings and structural features with *balanced* block weight
    (each block contributes equal total variance). Evaluated best: see docs/EVALUATION.md."""
    E, F = StandardScaler().fit_transform(E), StandardScaler().fit_transform(F)
    return np.hstack([E / np.sqrt(E.shape[1] / F.shape[1]), F])


def adaptive_k(X, base_k: int = 5) -> int:
    """LOF degenerates when more than k points are identical (many IAM identities share a shape).
    Use k larger than the biggest duplicate group so density is measured against *other* shapes."""
    _, counts = np.unique(np.round(X, 6), axis=0, return_counts=True)
    return int(max(2, min(len(X) - 1, max(base_k, counts.max() + 1))))


def detect_anomalies(G, n_neighbors: int = 5, contamination: float = 0.15, use_structural: bool = True,
                     seed: int = 42, **n2v_kwargs) -> List[dict]:
    """LOF over identity nodes. Returns [{id,label,score(0-1),is_anomaly,lof,reasons}] sorted by score."""
    ids = [n for n, d in G.nodes(data=True) if d.get("kind") in ("user", "role")]
    if len(ids) < 4:
        return []
    emb = node2vec_embeddings(G, seed=seed, **n2v_kwargs)
    X = np.array([emb[n] for n in ids])
    feats = structural_features(G)
    if use_structural:
        X = hybrid_matrix(X, np.array([feats[n] for n in ids], dtype=float))
    k = adaptive_k(X, n_neighbors)
    lof = LocalOutlierFactor(n_neighbors=k, contamination=min(max(contamination, 0.01), 0.5))
    flags = lof.fit_predict(X)
    raw = -lof.negative_outlier_factor_                    # ~1 for inliers, >1 for outliers
    lo, hi = raw.min(), raw.max()
    norm = (raw - lo) / (hi - lo) if hi > lo else np.zeros_like(raw)

    F_all = np.array([feats[n] for n in ids], dtype=float)
    med = np.median(F_all, axis=0)
    std = F_all.std(axis=0) + 1e-9
    out = []
    for i, n in enumerate(ids):
        z = (F_all[i] - med) / std
        reasons = [f"{FEATURE_NAMES[j]}={F_all[i][j]:g} (peer median {med[j]:g})"
                   for j in np.argsort(-np.abs(z))[:2] if abs(z[j]) >= 0.75]
        out.append({"id": n, "label": G.nodes[n]["label"], "score": round(float(norm[i]), 3),
                    "lof": round(float(raw[i]), 3), "is_anomaly": bool(flags[i] == -1),
                    "reasons": reasons or ["embedding neighbourhood differs from peers"]})
    return sorted(out, key=lambda r: -r["score"])


def anomaly_findings(G, anomalies: List[dict]) -> List[dict]:
    res = []
    for a in anomalies:
        if not a["is_anomaly"]:
            continue
        res.append({"rule": "GRAPH_ANOMALY", "severity": "medium" if a["score"] >= 0.6 else "low",
                    "risk": "Medium" if a["score"] >= 0.6 else "Low",
                    "title": "Structurally unusual identity (Node2Vec+LOF)",
                    "identity": a["label"], "identity_arn": a["id"] if a["id"].startswith("arn:") else None,
                    "resource": None,
                    "reason": f"Graph position differs from peers (LOF={a['lof']}, score={a['score']}): "
                              + "; ".join(a["reasons"]),
                    "evidence": {"lof": a["lof"], "score": a["score"]},
                    "remediation": "Review why this identity is connected differently from its peers; "
                                   "confirm the access is intended."})
    return res
