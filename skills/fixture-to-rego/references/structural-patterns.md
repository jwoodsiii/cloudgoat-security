# Structural Patterns Reference

Common structural misconfiguration patterns per AWS resource type.
Each entry maps to a `deny` rule in `structural.rego`.

---

## aws_iam_user_policy_attachment

| Pattern | Severity | Rationale |
|---|---|---|
| `policy_arn` starts with `arn:aws:iam::aws:policy/` | HIGH | AWS managed policies are never least-privilege. Use customer-managed policies scoped to the workload. |
| `policy_arn` contains `ReadOnlyAccess` | HIGH | Broad read grants enable full account enumeration — the entire `iam_enum_basics` attack path. |
| `policy_arn` contains `FullAccess` | CRITICAL | Full service access on a user identity; no justifiable use case. |
| `policy_arn` contains `AdministratorAccess` | CRITICAL | Admin on a user; use break-glass roles with MFA conditions instead. |
| Any attachment to a human user (not a service account) | MEDIUM | Policies should attach to roles; roles are assumed by identities. Direct user attachment bypasses federation and is not auditable via AssumeRole. |

Rego pattern:
```rego
deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_user_policy_attachment"
    startswith(resource.values.policy_arn, "arn:aws:iam::aws:policy/")
    msg := sprintf("AWS managed policy attached directly to user: %v -> %v",
        [resource.values.user, resource.values.policy_arn])
}
```

---

## aws_iam_user_policy (inline on user)

| Pattern | Severity | Rationale |
|---|---|---|
| Any inline policy on a user | MEDIUM | Inline policies are invisible to access reviews — they don't appear in `list_attached_user_policies`. Use managed policies for auditability. |
| Policy document grants `*` actions | HIGH | Wildcard action grants are never least-privilege. |
| Policy document grants `*` resources | HIGH | Wildcard resource grants allow access to all resources of the given type. |

Rego pattern for parsing inline policy JSON:
```rego
deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_user_policy"
    policy := json.unmarshal(resource.values.policy)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    action == "*"
    msg := sprintf("Inline user policy grants wildcard action: %v",
        [resource.values.name])
}
```

---

## aws_iam_role

| Pattern | Severity | Rationale |
|---|---|---|
| Trust policy Principal contains `:user/` | HIGH | IAM users hardcoded in trust policies bypass federation; session is not attributable to a human identity via SSO. Use SAML/OIDC federation instead. |
| Trust policy Principal is `*` (any principal) | CRITICAL | Role is assumable by anyone in the account or publicly if resource policy allows. |
| `max_session_duration` > 3600 (1 hour) | MEDIUM | Long-lived sessions increase blast radius of credential compromise. |
| No `Condition` on `sts:AssumeRole` in trust policy | MEDIUM | Unconditional trust grants; add MFA or source IP conditions for human-assumable roles. |

Rego pattern for trust policy:
```rego
deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_role"
    trust := json.unmarshal(resource.values.assume_role_policy)
    stmt := trust.Statement[_]
    stmt.Effect == "Allow"
    principal := stmt.Principal.AWS
    contains(principal, ":user/")
    msg := sprintf("Role trust policy allows IAM user principal: %v -> %v",
        [resource.values.name, principal])
}
```

Note: `stmt.Principal.AWS` may be a string or array. See `rego-idioms.md`
for the pattern that handles both.

---

## aws_iam_role_policy (inline on role)

Same patterns as `aws_iam_user_policy` above — wildcard actions/resources
are the primary concern. Inline role policies also avoid access reviews.

---

## aws_iam_group_membership / aws_iam_group

| Pattern | Severity | Rationale |
|---|---|---|
| Group path contains non-standard segments | LOW | IAM paths are metadata — unusual paths may indicate steganographic use (embedding data in infrastructure metadata). |
| Group has no attached policies | LOW | Empty groups with members may indicate privilege staging. |

---

## aws_iam_policy (customer-managed)

| Pattern | Severity | Rationale |
|---|---|---|
| `description` contains non-ASCII or flag-like patterns | LOW | Policy descriptions are rarely populated; non-standard values indicate metadata misuse. |
| Policy document Resource ARN contains unusual substrings | LOW | Resource ARNs should reference real AWS resources; unusual strings indicate metadata misuse or misconfiguration. |
| `attachment_count` == 0 | LOW | Unattached managed policies are orphaned and may represent privilege staging. |

---

## General IAM principles

1. **Users vs roles** — humans authenticate via SSO to roles; only service accounts use long-lived user credentials. Any policy attachment to a user that isn't a CI/CD service account is suspicious.

2. **Managed vs inline** — managed policies appear in access reviews; inline policies do not. Prefer managed.

3. **AWS managed vs customer managed** — AWS managed policies grant far more than any single workload needs. Always use customer-managed scoped to the workload.

4. **Trust policy conditions** — every role assumable by a human should have an MFA or source IP condition. Unconditional trust is a misconfiguration.

5. **Least privilege on Resource** — `Resource: "*"` means all resources of that type in the account. Scope to specific ARNs wherever possible.
