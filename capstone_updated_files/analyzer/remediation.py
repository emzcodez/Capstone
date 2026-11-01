"""Fill in `title`, `remediation` and `identity_arn` for findings that do not carry them
(the Member-2 risk detector emits rule/reason/evidence only)."""

CATALOG = {
    "WILDCARD_ACTION": ("Wildcard action permission",
        "Replace '*' / 'service:*' with the specific actions the identity needs; scope Resource to exact ARNs."),
    "ALLOW_NOT_ACTION": ("Allow with NotAction",
        "Rewrite the statement as an explicit allow-list of actions; NotAction grants everything not listed."),
    "UNRESTRICTED_RESOURCE": ("Actions allowed on all resources",
        "Restrict Resource to the specific ARNs required, or add conditions (tags, source IP, org ID)."),
    "TRUST_PUBLIC_PRINCIPAL": ("Role assumable by anyone",
        "Replace Principal '*' with specific accounts/roles and add aws:PrincipalOrgID or sts:ExternalId conditions."),
    "TRUST_EXTERNAL_ACCOUNT": ("Trust to an external AWS account",
        "Require sts:ExternalId or aws:PrincipalOrgID, trust a specific role instead of the account root, "
        "and confirm the external account is intended."),
    "TRUST_SAME_ACCOUNT_ROOT": ("Trust delegated to whole account root",
        "Name the specific roles/users allowed to assume this role instead of the account root."),
    "TRUST_FEDERATED_NO_AUDIENCE": ("Federated trust without audience condition",
        "Add an 'aud' condition on the identity provider so only the intended application can assume the role."),
    "TRUST_FEDERATED_NO_SUBJECT": ("Federated trust without subject condition",
        "Add a 'sub' condition (repo/branch, user or group) so only specific subjects can assume the role."),
    "SENSITIVE_RESOURCE_ACCESS": ("Access to sensitive resource",
        "Limit access to the minimum actions, require MFA/conditions, and review whether the identity needs it."),
    "PRIVILEGE_ESCALATION": ("Privilege-escalation capable permissions",
        "Remove the dangerous action combination or constrain it (specific role ARNs for iam:PassRole, "
        "permission boundaries, no policy-write permissions)."),
    "ATTACH_OR_PUT_POLICY": ("Can attach or write IAM policies",
        "Remove iam:Attach*/Put* policy actions, or bound them with a permission boundary."),
    "CREATE_POLICY_VERSION": ("Can create IAM policy versions",
        "Remove iam:CreatePolicyVersion/SetDefaultPolicyVersion from non-admin identities."),
    "SET_DEFAULT_POLICY_VERSION": ("Can change default policy version",
        "Remove iam:SetDefaultPolicyVersion from non-admin identities."),
    "UPDATE_ASSUME_ROLE_POLICY": ("Can rewrite role trust policies",
        "Remove iam:UpdateAssumeRolePolicy; trust-policy changes should go through reviewed IaC."),
    "PASSROLE_LAMBDA": ("PassRole + Lambda code execution",
        "Scope iam:PassRole to specific role ARNs and restrict lambda:CreateFunction/UpdateFunctionCode."),
    "CREDENTIAL_TAKEOVER": ("Can create credentials for other identities",
        "Remove iam:CreateAccessKey/UpdateLoginProfile on other users (or scope to self with ${aws:username})."),
    "POLICY_PARSE_ERROR": ("Policy could not be parsed",
        "Fix the malformed policy document so it can be analysed."),
}


def enrich_findings(findings, identities):
    by_name = {i["name"]: i["arn"] for i in identities}
    for f in findings:
        title, fix = CATALOG.get(f.get("rule"), (None, None))
        f.setdefault("title", title or str(f.get("rule", "Finding")).replace("_", " ").title())
        if not f.get("remediation"):
            f["remediation"] = fix or "Review the finding and apply least privilege."
        if not f.get("identity_arn"):
            f["identity_arn"] = by_name.get(f.get("identity"))
    return findings
