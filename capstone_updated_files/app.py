"""Streamlit dashboard.  Run:  streamlit run app.py"""
import json
import tempfile

import pandas as pd
import streamlit as st

from analyzer.iam_graph import to_dot
from main import SEVERITIES, STATUSES, run_analysis, summarize

st.set_page_config(page_title="AWS Identity Risk Analyzer", page_icon="🛡️", layout="wide")

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
STATUS_ICON = {"allowed": "✅", "blocked": "⛔", "inconclusive": "⚠️"}

def get_identity_category(identity):
    classification = identity.get("classification", {})
    category = classification.get("category")

    return category or "uncertain"

def get_identity_kind(identity):
    """Derive a readable kind from data (no hard-coded identity names)."""
    t = (identity.get("type") or "").lower()
    if t == "user":
        return "IAM User"
    if t != "role":
        return "Unknown"
    path = (identity.get("path") or "").lower()
    kinds = {k for st in ((identity.get("trust_policy") or {}).get("Statement") or [])
             for k in ((st.get("Principal") or {}) if isinstance(st.get("Principal"), dict) else {"AWS": "*"})}
    if "aws-reserved/sso" in path or "AWSReservedSSO_" in identity.get("name", ""):
        return "SSO Role"
    if "Service" in kinds:
        return "Service Role"
    if "Federated" in kinds:
        return "Federated Role"
    if "AWS" in kinds:
        return "Cross-account / Assumable Role"
    return "IAM Role"


def get_policy_names(identity):
    policies = []

    for p in identity.get("attached_policies", []):
        if p.get("name"):
            policies.append(p["name"])

    for p in identity.get("inline_policies", []):
        if p.get("name"):
            policies.append(p["name"])

    for p in identity.get("group_policies", []):
        if p.get("name"):
            policies.append(p["name"])

    return policies


def get_mfa_status(identity):
    if identity.get("type") != "user":
        return "N/A"

    if identity.get("mfa_enabled") is True:
        return "Enabled"

    return "Disabled"


# ---------------------------------------------------------------- data loading
def load(use_sample, profile, simulator, cloudtrail=None):
    with st.spinner("Running analysis..."):
        try:
            st.session_state["results"] = run_analysis(use_sample=use_sample, profile=profile or None,
                                                       use_simulator=simulator, cloudtrail=cloudtrail)
        except Exception as exc:  # last line of defence
            st.session_state["results"] = {"identities": [], "resources": [], "findings": [],
                                           "verifications": [], "source": "none",
                                           "warnings": [f"Unexpected error: {exc}"]}


with st.sidebar:
    st.title("🛡️ Controls")
    use_sample = st.toggle("Use sample data", value=True,
                           help="Works offline. Turn off to scan your AWS account.")
    profile = st.text_input("AWS profile (optional)", disabled=use_sample)
    simulator = st.checkbox("Cross-check with IAM Policy Simulator", disabled=use_sample)
    ct_mode = st.selectbox("CloudTrail evidence", ["None", "Sample events", "Upload JSON", "Live (AWS)"],
                           help="Adds observed-usage evidence: unused permissions, unexpected assumptions, "
                                "denied-attempt probing, console logins without MFA.")
    ct_arg = None
    if ct_mode == "Sample events":
        ct_arg = "data/sample_cloudtrail.json"
    elif ct_mode == "Upload JSON":
        up = st.file_uploader("CloudTrail log (.json)", type="json")
        if up is not None:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
            tmp.write(up.getvalue())
            tmp.close()
            ct_arg = tmp.name
    elif ct_mode == "Live (AWS)":
        ct_arg = "live"
    if st.button("▶ Run analysis", type="primary", use_container_width=True):
        load(use_sample, profile, simulator, ct_arg)
    st.caption("Credentials come from your local AWS config / environment, never from this app.")

if "results" not in st.session_state:
    load(True, "", False, "data/sample_cloudtrail.json")

R = st.session_state["results"]
S = summarize(R)
identities, findings, verifs = R.get("identities", []), R.get("findings", []), R.get("verifications", [])

st.title("AWS Identity-Centric Risk Analysis & Verification")
if R.get("source") == "sample":
    st.info("📁 Showing **sample data** (no live AWS account queried).")
elif R.get("source") == "aws":
    st.success("☁️ Showing **live AWS data**.")
for w in R.get("warnings", []):
    st.warning(w)

tabs = st.tabs(["📊 Overview", "👤 Identity Inventory", "🚨 Risk Findings",
                "🔍 Verification Results", "🛠️ Recommendations", "🕸️ Graph & Attack Paths",
                "🧪 Anomalies & CloudTrail"])

# -------------------------------------------------------------------- overview
with tabs[0]:
    c = st.columns(4)
    c[0].metric("Total identities", S["total_identities"])
    c[1].metric("Human", S["human"])
    c[2].metric("Non-human", S["non_human"])
    c[3].metric("Risk findings", S["total_findings"])
    st.subheader("Findings by severity")
    c = st.columns(4)
    for col, sev in zip(c, SEVERITIES):
        col.metric(f"{SEV_ICON[sev]} {sev.title()}", S["by_severity"][sev])
    st.bar_chart(pd.DataFrame({"count": S["by_severity"]}).loc[SEVERITIES])
    st.subheader("Verification outcomes")
    c = st.columns(3)
    for col, s in zip(c, STATUSES):
        col.metric(f"{STATUS_ICON[s]} {s.title()}", S["by_status"][s])
    scored = [f for f in findings if "score" in f]
    if scored:
        st.subheader("Top risks by context-aware score")
        st.dataframe(pd.DataFrame([{"Score": f["score"], "Priority": f.get("priority"),
                                    "Severity": f.get("severity"), "Identity": f.get("identity"),
                                    "Finding": f.get("title")} for f in scored[:8]]),
                     use_container_width=True, hide_index=True)
    st.download_button("⬇ Download full report (JSON)", json.dumps(R, indent=2, default=str),
                       file_name="risk_report.json", mime="application/json")

# ------------------------------------------------------------------- inventory
with tabs[1]:
    if not identities:
        st.info("No identities collected.")
    else:
        c1, c2 = st.columns([2, 1])
        q = c1.text_input("🔎 Search by name or ARN")
        t = c2.multiselect("Type", ["human", "non-human", "uncertain"], default=["human", "non-human", "uncertain"])
        rows = []
        for i in identities:
                rows.append({
                    "Name": i.get("name", "?"),
                    "Kind": get_identity_kind(i),
                    "Type": get_identity_category(i).replace("_", "-"),
                    "Why": ", ".join(
                        i.get("classification", {}).get("signals", [])
                    ) or "No classification signal",
                    "Policies": ", ".join(get_policy_names(i)) or "—",
                    "MFA": get_mfa_status(i),
                    "ARN": i.get("arn", "")
                })
        df = pd.DataFrame(rows)
        df = df[df["Type"].isin(t)]
        if q:
            df = df[df["Name"].str.contains(q, case=False) | df["ARN"].str.contains(q, case=False)]
        st.dataframe(df, use_container_width=True, hide_index=True)
        names = df["Name"].tolist()
        if names:
            pick = st.selectbox("Inspect identity", names)
            ident = next(i for i in identities if i.get("name") == pick)
            a, b = st.columns(2)
            a.markdown("**Policies**")
            for p in (ident.get("attached_policies", []) + ident.get("inline_policies", []) + ident.get("group_policies", [])):
                with a.expander(f"{p.get('name')}"):
                    st.json(p.get("document", {}))
            b.markdown("**Trust policy**")
            b.json(ident.get("trust_policy") or {"info": "N/A (IAM user)"})

def verification_label(v):
    status = v.get("status")

    if status == "allowed":
        return "🔴 RISK CONFIRMED"

    if status == "blocked":
        return "🟢 NOT CONFIRMED"

    return "🟡 PENDING"

# -------------------------------------------------------------------- findings
with tabs[2]:
    if not findings:
        st.success("No risk findings detected.")
    else:
        c1, c2 = st.columns([2, 1])
        q = c1.text_input("🔎 Search findings")
        sevs = c2.multiselect("Severity", SEVERITIES, default=SEVERITIES)
        flt = sorted([f for f in findings if f.get("severity") in sevs and
                      (not q or q.lower() in json.dumps(f, default=str).lower())],
                     key=lambda f: -(f.get("score") or 0))
        st.dataframe(
                        pd.DataFrame([
                            {
                                "ID": f.get("id"),
                                "Score": f.get("score"),
                                "Priority": f.get("priority"),
                                "Severity": f"{SEV_ICON.get(f.get('severity'), '')} {f.get('severity')}",
                                "Identity": f.get("identity"),
                                "Kind": get_identity_kind(
                                    next(
                                        (i for i in identities if i.get("name") == f.get("identity")),
                                        {}
                                    )
                                ),
                                "Title": f.get("title"),
                                "Resource": f.get("resource")
                            }
                            for f in flt
                        ]),
                        use_container_width=True,
                        hide_index=True
                    )
        if flt:
            sel = st.selectbox("Select a finding for details", [f"{f.get('id')} - {f.get('title')} ({f.get('identity')})" for f in flt])
            f = flt[[f"{x.get('id')} - {x.get('title')} ({x.get('identity')})" for x in flt].index(sel)]
            st.markdown(f"### {SEV_ICON.get(f.get('severity'), '')} {f.get('title')}")
            st.write(f"**Severity:** {f.get('severity')}  \n**Identity:** {f.get('identity')}  \n"
                     f"**Identity ARN:** `{f.get('identity_arn') or 'n/a'}`  \n**Resource:** `{f.get('resource')}`")
            st.write(f"**Reason:** {f.get('reason')}")
            if f.get("score_factors"):
                st.write(f"**Risk score:** {f['score']} / 100 — {f['priority']}")
                with st.expander("How the score was calculated"):
                    st.caption("Rows marked ✓ add up to the score; the others are raw signals compressed into the context total.")
                    st.dataframe(pd.DataFrame([{"Factor": x["factor"], "Points": x["points"], "Counts toward total": "✓" if x["applied"] else ""}
                                               for x in f["score_factors"]]), hide_index=True, use_container_width=True)
            st.info(f"**Remediation:** {f.get('remediation')}")
            ident = next((i for i in identities if i.get("name") == f.get("identity")), None)
            if ident:
                with st.expander("Identity policies (raw)"):
                    st.json({"policies": ident.get("attached_policies", []) + ident.get("inline_policies", []) + ident.get("group_policies", []), "trust_policy": ident.get("trust_policy")})

# ---------------------------------------------------------------- verification
with tabs[3]:
    if not verifs:
        st.info("No access-path checks were run.")
    else:
        st.caption("✅ allowed = feasible path · ⛔ blocked = denied · ⚠️ inconclusive = depends on conditions not evaluated")
        sel = st.multiselect("Show statuses", STATUSES, default=STATUSES)
        shown = [v for v in verifs if v.get("status", "inconclusive") in sel]
        st.dataframe(pd.DataFrame([{"Status": f"{STATUS_ICON.get(v.get('status'), '⚠️')} {v.get('status')}",
                                    "Principal": v.get("principal"), "Role": v.get("role"),
                                    "Hops": v.get("hops"), "Path": " → ".join(v.get("path") or []),
                                    "Resource": v.get("resource"), "Action": v.get("action", "n/a")}
                                   for v in shown]), use_container_width=True, hide_index=True)
        st.subheader("Evidence")
        for v in shown[:50]:
            icon = STATUS_ICON.get(v.get("status"), "⚠️")
            st.markdown(f"### {verification_label(v)}")

            with st.expander(
                f"{icon} {v.get('principal')} → {v.get('role')} → "
                f"{v.get('resource')} [{v.get('action', 'n/a')}]"
            ):
                for e in v.get("evidence", []) or ["No evidence supplied by verifier."]:
                    st.write(f"- {e}")

# -------------------------------------------------------------- recommendations
with tabs[4]:
    if not findings:
        st.success("Nothing to remediate.")
    else:
        groups = {}
        for f in findings:
            groups.setdefault((f.get("title"), f.get("severity"), f.get("remediation")), []).append(f.get("identity"))
        order = {s: n for n, s in enumerate(SEVERITIES)}
        for (title, sev, fix), who in sorted(groups.items(), key=lambda kv: order.get(kv[0][1], 9)):
            safe_sev = str(sev or "unknown").upper()
            with st.expander(f"{SEV_ICON.get(sev, '')} {safe_sev} - {title} ({len(who)} affected)"):
                st.write(f"**Fix:** {fix}")
                st.write("**Affected:** " + ", ".join(sorted(set(map(str, who)))))
        csv = pd.DataFrame(findings).to_csv(index=False)
        st.download_button("⬇ Download findings (CSV)", csv, file_name="findings.csv", mime="text/csv")


# ------------------------------------------------------- graph & attack paths
with tabs[5]:
    graph, paths = R.get("graph"), R.get("paths", [])
    if not graph:
        st.info("Graph analysis did not run (see warnings).")
    else:
        chains = [f for f in findings if f.get("rule") in ("ROLE_CHAIN", "ROLE_CYCLE")]
        m = st.columns(4)
        m[0].metric("Graph nodes", len(graph["nodes"]))
        m[1].metric("Graph edges", len(graph["edges"]))
        m[2].metric("Multi-hop paths", sum(1 for p in paths if p["hops"] >= 2))
        m[3].metric("Role-chain findings", len(chains))
        st.subheader("Access paths (principal → assume* → bucket)")
        min_hops = st.slider("Minimum assume hops", 0, 4, 1)
        only_sens = st.checkbox("Only paths to sensitive buckets")
        shown = [p for p in paths if p["hops"] >= min_hops and (p["sensitive"] or not only_sens)]
        if not shown:
            st.info("No paths match the filters.")
        else:
            labels = [f"{' → '.join(p['path_labels'])} → {p['target_label']}  [{p['status']}]" for p in shown]
            pick = st.selectbox("Highlight a path", labels)
            sel = shown[labels.index(pick)]
            st.graphviz_chart(to_dot(graph, sel["path"] + [sel["target"]]), use_container_width=True)
            st.write(f"**Actions:** {', '.join(sel['actions'])} · **Granted via:** {sel['via']} · "
                     f"**Hops:** {sel['hops']}" + (f" · **Conditions:** {', '.join(sel['conditions'])}" if sel["conditions"] else ""))
            with st.expander("Evidence"):
                for e in sel["evidence"]:
                    st.write(f"- {e}")
            st.dataframe(pd.DataFrame([{"Source": p["source_label"], "Hops": p["hops"],
                                        "Path": " → ".join(p["path_labels"]), "Target": p["target_label"],
                                        "Actions": ", ".join(p["actions"]), "Sensitive": p["sensitive"],
                                        "Status": p["status"]} for p in shown]),
                         use_container_width=True, hide_index=True)
        st.subheader("Role chains & cycles")
        if not chains:
            st.success("No multi-hop role chains detected.")
        for f in chains:
            with st.expander(f"{SEV_ICON.get(f['severity'], '')} {f['title']} — {f['identity']} (score {f.get('score', 'n/a')})"):
                st.write(f["reason"])
                st.info(f["remediation"])
        with st.expander("Full graph"):
            st.graphviz_chart(to_dot(graph), use_container_width=True)

# ------------------------------------------------------ anomalies & cloudtrail
with tabs[6]:
    st.subheader("Graph-embedding anomalies (Node2Vec + LOF)")
    an = R.get("anomalies", [])
    if not an:
        st.info("Not enough identities for anomaly detection (needs ≥ 4).")
    else:
        st.caption("Higher score = graph position differs more from peer identities. A lead for review, not proof of risk.")
        st.bar_chart(pd.DataFrame({"anomaly score": {a["label"]: a["score"] for a in an}}))
        st.dataframe(pd.DataFrame([{"Identity": a["label"], "Score": a["score"], "LOF": a["lof"],
                                    "Flagged": a["is_anomaly"], "Why": "; ".join(a["reasons"])} for a in an]),
                     use_container_width=True, hide_index=True)
    st.subheader("CloudTrail evidence")
    ct = [f for f in findings if str(f.get("rule", "")).startswith("CT_")]
    if not R.get("cloudtrail"):
        st.info("No CloudTrail data loaded. Choose a source in the sidebar and re-run the analysis.")
    elif not ct:
        st.success("CloudTrail shows no unused, unexpected or suspicious activity.")
    for f in ct:
        with st.expander(f"{SEV_ICON.get(f['severity'], '')} {f['title']} — {f['identity']}"):
            st.write(f["reason"])
            st.info(f["remediation"])
