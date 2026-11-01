"""Member 1 - human vs non-human classification (rule based, explainable)."""

BOT_PREFIXES = ("svc-", "svc_", "bot-", "ci-", "app-", "automation-", "pipeline-")


def _trust_kinds(trust):
    kinds = set()
    for st in (trust or {}).get("Statement", []):
        p = st.get("Principal", {})
        if isinstance(p, dict):
            kinds.update(p.keys())
    return kinds


def classify_one(identity):
    name = identity.get("name", "").lower()
    if identity.get("kind") == "user":
        if identity.get("has_console_access"):
            return "human", "IAM user with console password"
        if name.startswith(BOT_PREFIXES):
            return "non-human", "IAM user with service-style name"
        if identity.get("access_key_count", 0):
            return "non-human", "IAM user with access keys but no console access"
        return "human", "IAM user (default)"
    kinds = _trust_kinds(identity.get("trust_policy"))
    if "Service" in kinds:
        return "non-human", "Role trusted by an AWS service"
    if "Federated" in kinds or "/aws-reserved/sso.amazonaws.com" in identity.get("path", ""):
        return "human", "Role assumed through federation / SSO"
    if "AWS" in kinds:
        return "non-human", "Role assumed by IAM principals (workload/cross-account default)"
    return "non-human", "Role (default)"


def classify_identities(identities):
    for ident in identities:
        ident["type"], ident["classification_reason"] = classify_one(ident)
    return identities
