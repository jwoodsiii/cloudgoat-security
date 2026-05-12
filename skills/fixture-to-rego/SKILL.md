---
name: fixture-to-rego
description: >
  Converts a CloudGoat Terraform state fixture and scenario README into OPA
  Rego policy files with tests. Use this skill whenever the user wants to
  write OPA policies, Rego rules, or conftest tests from a CloudGoat scenario.
  Also triggers when the user says "write the rego policies", "generate the
  OPA rules", "build the conftest tests", or "convert the fixture to policies".
  Always use this skill when working in the cloudgoat-security repo — it
  encodes the normalization step, two-file split (structural vs detective),
  and test harness conventions for this repo.
---

# fixture-to-rego

Converts a CloudGoat Terraform state fixture + scenario README into four files:

```
policy/<scenario>/
  structural.rego        ← config that should never have been deployed
  structural_test.rego
  detective.rego         ← signals worth alerting on post-deploy
  detective_test.rego
```

Tests run against a normalized fixture JSON that flattens the tfstate resource
tree into a consistent input shape for all policies.

---

## Inputs

The user provides:
1. Path to the raw fixture JSON (e.g. `fixtures/iam_enum_basics.json`)
2. Path to the scenario README (e.g. `scenarios/iam_enum_basics/README.md` in
   the playbooks repo, or paste inline)
3. Scenario name (e.g. `iam_enum_basics`)

---

## Step 0 — Normalize the fixture

Before writing any policy, normalize the raw tfstate fixture to the flat
resource shape all policies expect.

Run:
```bash
jq '{resources: [.values.root_module.resources[] | {
  type: .type,
  name: .name,
  address: .address,
  values: .values
}]}' fixtures/<scenario>.json > fixtures/<scenario>_normalized.json
```

Verify output contains a top-level `resources` array. If the fixture is
already normalized (has `resources` at root), skip this step.

The normalized shape every policy uses:
```json
{
  "resources": [
    {
      "type": "aws_iam_user_policy_attachment",
      "name": "bob_base_permissions",
      "address": "aws_iam_user_policy_attachment.bob_base_permissions",
      "values": { "policy_arn": "...", "user": "..." }
    }
  ]
}
```

---

## Step 1 — Analyze the fixture

Read the normalized fixture. For each resource, extract:

| Field | What to look for |
|---|---|
| `type` | Resource type — drives which structural rules apply |
| `values.policy_arn` | AWS managed vs customer managed (prefix `arn:aws:iam::aws:`) |
| `values.policy` | Inline JSON policy documents — check actions, resources, principals |
| `values.assume_role_policy` | Trust policy — check Principal type (user vs service vs federated) |
| `values.description` | Non-empty descriptions on policies/roles |
| `values.tags` | Tag presence and values |
| `values.path` | Non-default IAM paths |

Build a mental inventory:
- What resource types are present?
- What permissions are granted, and to whom?
- What trust relationships exist?
- What metadata fields contain unusual values?

---

## Step 2 — Identify structural misconfigs

Structural misconfigs are things Terraform should have prevented at plan time.
They represent policy violations — configurations that are objectively wrong
regardless of intent.

For each resource in the inventory, ask:
- Is this the right principal type? (users vs roles for programmatic access)
- Is this the least-privilege grant? (AWS managed `*Access` policies are almost
  never least-privilege)
- Does any trust relationship allow human IAM users to assume roles directly?
- Are there policy documents granting wildcarded actions or resources?

Read `references/structural-patterns.md` for common patterns per resource type.

Each finding becomes one `deny` rule in `structural.rego`.

---

## Step 3 — Identify detective signals

Detective signals come from the attack narrative in the README. They represent
things that are technically valid configurations but indicate reconnaissance,
overprivileged identities, or patterns an attacker exploited.

For each attack step in the README, ask:
- What configuration made this step possible?
- Would an attacker need this to exist to proceed?
- Is this something a legitimate workload would also need, or is it unusual?

Examples from `iam_enum_basics`:
- A role whose trust policy allows a named IAM user (not a service) to assume it
- A policy description containing non-alphanumeric characters (flag smuggling)
- An IAM user with both a managed policy and an inline policy attached

Each finding becomes one `warn` rule in `detective.rego`.

Use `warn` not `deny` for detective rules — they're signals, not hard blocks.

---

## Step 4 — Generate `structural.rego`

### Package naming
```rego
package policy.<scenario>.structural
```

### Rule template
```rego
# <one-line description of what this catches>
# Severity: HIGH | MEDIUM | LOW
# Resource: <aws_resource_type>
deny[msg] {
    resource := input.resources[_]
    resource.type == "<aws_resource_type>"
    <condition using resource.values>
    msg := sprintf("<human-readable violation message: %v>", [<interpolated_value>])
}
```

### Rules to generate per resource type

Read `references/structural-patterns.md` for the full list. At minimum for
IAM scenarios, generate rules for:

- `aws_iam_user_policy_attachment` where `policy_arn` starts with
  `arn:aws:iam::aws:policy/` — AWS managed policies on users are overly broad
- `aws_iam_user_policy_attachment` where `policy_arn` contains `ReadOnlyAccess`
  — broad read grants enable full account enumeration
- `aws_iam_role` where `assume_role_policy` Principal is an IAM user ARN
  (contains `:user/`) — human users should not directly assume roles via
  hardcoded trust; use identity federation instead
- Any inline policy (`aws_iam_user_policy`, `aws_iam_role_policy`) granting
  wildcard actions (`*`) or wildcard resources (`*`)

---

## Step 5 — Generate `structural_test.rego`

### Package naming
```rego
package policy.<scenario>.structural_test
```

### Test structure — one passing and one failing test per rule

```rego
# test_<rule_name>_violation — input that SHOULD trigger the deny
test_aws_managed_policy_on_user_violation {
    deny[_] with input as {
        "resources": [{
            "type": "aws_iam_user_policy_attachment",
            "name": "test",
            "address": "aws_iam_user_policy_attachment.test",
            "values": {
                "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "user": "test-user"
            }
        }]
    }
}

# test_<rule_name>_pass — input that should NOT trigger the deny
test_aws_managed_policy_on_user_pass {
    not deny[_] with input as {
        "resources": [{
            "type": "aws_iam_user_policy_attachment",
            "name": "test",
            "address": "aws_iam_user_policy_attachment.test",
            "values": {
                "policy_arn": "arn:aws:iam::123456789012:policy/my-custom-policy",
                "user": "test-user"
            }
        }]
    }
}
```

Every `deny` rule in `structural.rego` must have both a violation test and a
pass test. No untested rules.

---

## Step 6 — Generate `detective.rego`

### Package naming
```rego
package policy.<scenario>.detective
```

### Rule template — use `warn` not `deny`
```rego
# <one-line description of what this signals>
# Attack step: <step number and heading from README>
warn[msg] {
    resource := input.resources[_]
    resource.type == "<aws_resource_type>"
    <condition derived from attack narrative>
    msg := sprintf("<signal description: %v>", [<interpolated_value>])
}
```

---

## Step 7 — Generate `detective_test.rego`

Same pattern as structural tests — one violation test and one pass test per
`warn` rule.

```rego
package policy.<scenario>.detective_test
```

---

## Step 8 — Validate

Run in order. Fix any failures before presenting output to the user.

```bash
# Unit tests
opa test policy/<scenario>/ -v

# Conftest against normalized fixture
conftest test fixtures/<scenario>_normalized.json \
  --policy policy/<scenario>/ \
  --namespace policy.<scenario>.structural

conftest test fixtures/<scenario>_normalized.json \
  --policy policy/<scenario>/ \
  --namespace policy.<scenario>.detective
```

Expected: all `opa test` pass, conftest shows violations against the CloudGoat
fixture (the fixture IS the misconfigured infra — violations are correct).

If conftest shows zero violations against the fixture, the rules are not
catching the misconfigs — revisit Step 2/3.

---

## Step 9 — Output files

Write four files:
```
policy/<scenario>/structural.rego
policy/<scenario>/structural_test.rego
policy/<scenario>/detective.rego
policy/<scenario>/detective_test.rego
```

Do not modify `fixtures/` (except creating the normalized file in Step 0).
Do not touch `infra/` or any other directory.

---

## Reference files

- `references/structural-patterns.md` — common structural misconfig patterns
  per AWS resource type. Read in Step 2 before identifying misconfigs.
- `references/rego-idioms.md` — OPA/Rego patterns for AWS policy analysis
  (parsing JSON policy documents, walking trust policies, tag checks). Read
  before writing any rule that parses nested JSON strings.
