"""Member 1 - AWS data collection (IAM users/roles + S3 buckets).

Needs READ-ONLY credentials. Never hard-code or commit keys; use
`aws configure`, an AWS profile, or environment variables.
"""
import json

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:  # lets sample mode / tests run without boto3 installed
    boto3 = None

    class ClientError(Exception):
        pass

KEY = {"user": "UserName", "role": "RoleName", "group": "GroupName"}


def _iso(value):
    return value.isoformat() if value else None


def _policies(iam, kind, name):
    """Inline + attached managed policy documents for a user/role/group."""
    out = []
    k = KEY[kind]
    try:
        for pol in getattr(iam, f"list_attached_{kind}_policies")(**{k: name})["AttachedPolicies"]:
            arn = pol["PolicyArn"]
            ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]
            out.append({"name": pol["PolicyName"], "type": "managed", "document": doc})
        for pname in getattr(iam, f"list_{kind}_policies")(**{k: name})["PolicyNames"]:
            doc = getattr(iam, f"get_{kind}_policy")(**{k: name, "PolicyName": pname})["PolicyDocument"]
            out.append({"name": pname, "type": "inline", "document": doc})
    except ClientError as exc:
        out.append({"name": "ERROR", "type": "error", "document": {}, "error": str(exc)})
    return out


def _collect_users(iam):
    users = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            policies = _policies(iam, "user", name)
            for g in iam.list_groups_for_user(UserName=name)["Groups"]:
                for p in _policies(iam, "group", g["GroupName"]):
                    p["name"] = f"{p['name']} (group:{g['GroupName']})"
                    policies.append(p)
            try:
                iam.get_login_profile(UserName=name)
                console = True
            except ClientError:
                console = False
            keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
            users.append({
                "name": name, "arn": u["Arn"], "kind": "user", "type": "unknown",
                "policies": policies, "trust_policy": {},
                "mfa_enabled": bool(iam.list_mfa_devices(UserName=name)["MFADevices"]),
                "has_console_access": console, "access_key_count": len(keys),
                "last_used": _iso(u.get("PasswordLastUsed")),
            })
    return users


def _collect_roles(iam):
    roles = []
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            if r.get("Path", "").startswith("/aws-service-role/"):
                continue  # skip service-linked roles (noise)
            name = r["RoleName"]
            try:
                used = iam.get_role(RoleName=name)["Role"].get("RoleLastUsed", {}).get("LastUsedDate")
            except ClientError:
                used = None
            roles.append({
                "name": name, "arn": r["Arn"], "kind": "role", "path": r.get("Path", "/"),
                "type": "unknown", "policies": _policies(iam, "role", name),
                "trust_policy": r.get("AssumeRolePolicyDocument", {}),
                "last_used": _iso(used),
            })
    return roles


def _collect_buckets(s3):
    buckets = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
        except ClientError:
            policy = {}
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            blocked = all(cfg.values())
        except ClientError:
            blocked = False
        buckets.append({"name": name, "type": "s3", "arn": f"arn:aws:s3:::{name}",
                        "policy": policy, "public_access_block": blocked})
    return buckets


def collect_aws_data(profile=None, region=None):
    """Return {"identities": [...], "resources": [...]}. Raises on connection/auth failure."""
    if boto3 is None:
        raise RuntimeError("boto3 is not installed (pip install boto3)")
    session = boto3.Session(profile_name=profile, region_name=region)
    iam, s3 = session.client("iam"), session.client("s3")
    iam.get_account_summary()  # fail fast if credentials are bad
    return {"identities": _collect_users(iam) + _collect_roles(iam),
            "resources": _collect_buckets(s3)}
