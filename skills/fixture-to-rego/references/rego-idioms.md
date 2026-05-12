# Rego Idioms Reference

OPA/Rego patterns for AWS policy analysis. Read before writing any rule
that parses nested JSON strings, walks trust policies, or checks tags.

---

## Parsing embedded JSON strings

Terraform stores IAM policy documents as JSON strings inside the state.
Always use `json.unmarshal()` — never string matching against raw JSON.

```rego
# WRONG — fragile string matching
contains(resource.values.policy, "\"Effect\": \"Allow\"")

# RIGHT — parse then navigate
policy := json.unmarshal(resource.values.policy)
stmt := policy.Statement[_]
stmt.Effect == "Allow"
```

---

## Principal — string vs array

IAM trust policy Principals can be a string or an array depending on how
many principals are listed. Always handle both:

```rego
# Handles both string and array Principal.AWS
principal_allows_user(stmt) {
    principal := stmt.Principal.AWS
    is_string(principal)
    contains(principal, ":user/")
}

principal_allows_user(stmt) {
    principal := stmt.Principal.AWS[_]
    contains(principal, ":user/")
}

deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_role"
    trust := json.unmarshal(resource.values.assume_role_policy)
    stmt := trust.Statement[_]
    stmt.Effect == "Allow"
    principal_allows_user(stmt)
    msg := sprintf("Role %v trust policy allows IAM user principal",
        [resource.values.name])
}
```

---

## Action — string vs array

Same pattern as Principal — `Action` can be a string or array:

```rego
action_is_wildcard(stmt) {
    stmt.Action == "*"
}

action_is_wildcard(stmt) {
    stmt.Action[_] == "*"
}
```

---

## Resource ARN — string vs array

```rego
resource_contains_flag(stmt) {
    r := stmt.Resource
    is_string(r)
    regex.match(`HSM[{_-]`, r)
}

resource_contains_flag(stmt) {
    r := stmt.Resource[_]
    regex.match(`HSM[{_-]`, r)
}
```

---

## Walking all statements in a policy

```rego
# Iterate over all statements, check each for a condition
deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_user_policy"
    policy := json.unmarshal(resource.values.policy)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    action_is_wildcard(stmt)
    msg := sprintf("Inline policy %v grants wildcard action",
        [resource.values.name])
}
```

---

## Checking tags

Tags in tfstate are a flat object `{"Key": "Value"}` not an array.
Access directly:

```rego
# Check if a specific tag key exists
has_tag(resource, key) {
    _ = resource.values.tags[key]
}

# Check tag value
tag_value(resource, key) = val {
    val := resource.values.tags[key]
}

# Detect flag-like values in any tag
deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_role"
    tag_key := resource.values.tags[key]
    regex.match(`HSM[{_-]`, tag_key)
    msg := sprintf("Role %v has flag-like value in tag %v",
        [resource.values.name, key])
}
```

Note: in the CloudGoat scenario the flag IS the tag value — the detective
rule should catch this. The structural rule catches the pattern of embedding
data in tags at all.

---

## Checking IAM path

IAM paths default to `/`. Non-default paths are unusual and worth flagging:

```rego
warn[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_group"
    resource.values.path != "/"
    msg := sprintf("IAM group %v has non-default path: %v",
        [resource.values.name, resource.values.path])
}
```

---

## Checking policy description

Policy descriptions are rarely populated. Non-empty descriptions containing
non-standard patterns are a signal:

```rego
warn[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_policy"
    desc := resource.values.description
    desc != ""
    regex.match(`HSM[{_-]`, desc)
    msg := sprintf("Policy %v description contains flag-like value: %v",
        [resource.values.name, desc])
}
```

---

## Filtering AWS managed vs customer managed policies

```rego
is_aws_managed(policy_arn) {
    startswith(policy_arn, "arn:aws:iam::aws:policy/")
}

is_customer_managed(policy_arn) {
    not is_aws_managed(policy_arn)
}
```

---

## Iterating resources by type — helper pattern

When multiple rules need resources of the same type, define a helper:

```rego
iam_roles[role] {
    role := input.resources[_]
    role.type == "aws_iam_role"
}

iam_user_attachments[att] {
    att := input.resources[_]
    att.type == "aws_iam_user_policy_attachment"
}
```

Then rules become:
```rego
deny[msg] {
    role := iam_roles[_]
    # ... condition
}
```

---

## OPA test conventions

```rego
package policy.scenario_name.structural_test

import rego.v1

# Minimal fixture that triggers the rule
test_rule_name_violation if {
    deny[_] with input as {"resources": [{
        "type": "aws_iam_user_policy_attachment",
        "name": "test",
        "address": "aws_iam_user_policy_attachment.test",
        "values": {
            "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "user": "test-user"
        }
    }]}
}

# Minimal fixture that should NOT trigger the rule
test_rule_name_pass if {
    not deny[_] with input as {"resources": [{
        "type": "aws_iam_user_policy_attachment",
        "name": "test",
        "address": "aws_iam_user_policy_attachment.test",
        "values": {
            "policy_arn": "arn:aws:iam::123456789012:policy/my-scoped-policy",
            "user": "test-user"
        }
    }]}
}
```

## Package naming — tests must share the package with the rules they test

Test files use the SAME package name as the rules file, not a separate
`_test` package. This allows `deny[_]` and `warn[_]` to be referenced
directly without cross-package imports.

# structural_test.rego
package policy.iam_enum_basics.structural   ← same as structural.rego

# detective_test.rego  
package policy.iam_enum_basics.detective    ← same as detective.rego

Use `import rego.v1` in all new files — it enables the modern Rego syntax
and avoids deprecation warnings in OPA 0.60+.

---

## conftest namespace convention

Conftest requires the `--namespace` flag to match the package name:

```bash
# structural rules
conftest test fixtures/scenario_normalized.json \
  --policy policy/scenario/ \
  --namespace policy.scenario.structural

# detective rules
conftest test fixtures/scenario_normalized.json \
  --policy policy/scenario/ \
  --namespace policy.scenario.detective
```

Or test both at once by omitting `--namespace` and using `--all-namespaces`:

```bash
conftest test fixtures/scenario_normalized.json \
  --policy policy/scenario/ \
  --all-namespaces
```

---

## Policy Variable Severity Pattern

Some rule definitions will detect similar behavior with varying levels of severity. Instead of generating duplicate functions to handle higher/lower severity cases, write a single rule that uses a helper to derive severity.

```rego
# Severity is interpolated into the message so conftest output carries it.
# Consumers (SARIF, CI gates) parse the prefix to set alert level.

_managed_policy_severity(policy_arn) = "CRITICAL" {
    contains(policy_arn, "AdministratorAccess")
}

_managed_policy_severity(policy_arn) = "HIGH" {
    contains(policy_arn, "ReadOnlyAccess")
}

_managed_policy_severity(policy_arn) = "HIGH" {
    contains(policy_arn, "FullAccess")
}

_managed_policy_severity(policy_arn) = "MEDIUM" {
    startswith(policy_arn, "arn:aws:iam::aws:policy/")
    not contains(policy_arn, "AdministratorAccess")
    not contains(policy_arn, "ReadOnlyAccess")
    not contains(policy_arn, "FullAccess")
}

deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_iam_user_policy_attachment"
    startswith(resource.values.policy_arn, "arn:aws:iam::aws:policy/")
    severity := _managed_policy_severity(resource.values.policy_arn)
    msg := sprintf("[%v] AWS managed policy attached directly to user %v: %v",
        [severity, resource.values.user, resource.values.policy_arn])
}
```
