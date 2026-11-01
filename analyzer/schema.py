"""Normalise collector output (either legacy or canonical schema) into the canonical schema.

Canonical: identity.type in {user, role}; policies split into attached_policies / inline_policies /
group_policies; resource.type == "s3_bucket"; access_keys is a list.
Legacy collector emitted: kind=user|role, type=human|non-human|unknown, flat `policies`
(each with type managed|inline), `access_key_count`, resource type "s3".
"""
import copy


def normalize_identity(i):
    i = dict(i)
    kind = i.get("kind")
    if i.get("type") not in ("user", "role"):
        i["type"] = kind if kind in ("user", "role") else ("role" if i.get("trust_policy") else "user")
    i["kind"] = i["type"]
    if "policies" in i:
        att, inl = list(i.get("attached_policies") or []), list(i.get("inline_policies") or [])
        for p in i["policies"]:
            if p.get("type") == "error":
                continue
            (inl if p.get("type") == "inline" else att).append(p)
        i["attached_policies"], i["inline_policies"] = att, inl
    for k in ("attached_policies", "inline_policies", "group_policies"):
        i.setdefault(k, [])
    if "access_keys" not in i:
        i["access_keys"] = [{}] * int(i.get("access_key_count", 0))
    i.setdefault("tags", {})
    i.setdefault("path", "/")
    return i


def normalize_resource(r):
    r = dict(r)
    if r.get("type") in (None, "s3"):
        r["type"] = "s3_bucket"
    if not r.get("arn") and r.get("name"):
        r["arn"] = f"arn:aws:s3:::{r['name']}"
    r.setdefault("id", r.get("arn"))
    return r


def normalize_data(data):
    data = copy.copy(data)
    data["identities"] = [normalize_identity(i) for i in data.get("identities", [])]
    data["resources"] = [normalize_resource(r) for r in data.get("resources", [])]
    return data
