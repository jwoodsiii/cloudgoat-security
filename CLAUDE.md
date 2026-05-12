# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Security policy layer for CloudGoat scenarios. It takes Terraform state dumps from CloudGoat's intentionally vulnerable infrastructure, normalizes them into a flat JSON shape, and runs OPA/Rego policies against them to detect misconfigurations (structural) and attack-enabling signals (detective).

## Commands

### OPA / Rego

```bash
# Run all unit tests
opa test policy/ -v

# Run unit tests for a single scenario
opa test policy/<scenario>/ -v

# Run conftest against a normalized fixture (structural rules)
conftest test fixtures/<scenario>_normalized.json \
  --policy policy/<scenario>/ \
  --namespace policy.<scenario>.structural

# Run conftest against a normalized fixture (detective rules)
conftest test fixtures/<scenario>_normalized.json \
  --policy policy/<scenario>/ \
  --namespace policy.<scenario>.detective

# Run both namespaces at once
conftest test fixtures/<scenario>_normalized.json \
  --policy policy/<scenario>/ \
  --all-namespaces
```

### Normalizing fixtures

Raw CloudGoat tfstate files (`fixtures/*_raw.json`) must be normalized before policies can run against them:

```bash
jq '{resources: [.values.root_module.resources[] | {
  type: .type,
  name: .name,
  address: .address,
  values: .values
}]}' fixtures/<scenario>_raw.json > fixtures/<scenario>_normalized.json
```

Normalized files (`*_normalized.json`) are gitignored. Raw files (`*_raw.json`) are also gitignored — only committed fixtures are the normalized forms checked into `fixtures/`.

### Bootstrap infra (one-time)

```bash
cd infra/bootstrap
terraform init
terraform apply
```

State is in S3 (`tfstate-cloudgoat-bucket`). See `versions.tf` for the bootstrap sequence comment if you need to re-bootstrap from scratch.

## Architecture

### Policy structure

Every CloudGoat scenario gets its own subdirectory under `policy/` with exactly four files:

```
policy/<scenario>/
  structural.rego        # deny rules — config that should never have been deployed
  structural_test.rego
  detective.rego         # warn rules — post-deploy signals tied to the attack path
  detective_test.rego
```

- **Structural** rules use `deny[msg]` and catch objective misconfigurations (AWS managed policies on users, wildcard grants, IAM users in trust policies).
- **Detective** rules use `warn[msg]` (never `deny`) and flag configurations that enabled specific attack steps in the scenario README.

Policy packages follow the naming convention `policy.<scenario>.structural` and `policy.<scenario>.structural_test`.

### Fixture shape

All policies read from a normalized `input.resources` array. Each element:

```json
{
  "type": "aws_iam_user_policy_attachment",
  "name": "bob_base_permissions",
  "address": "aws_iam_user_policy_attachment.bob_base_permissions",
  "values": { ... }
}
```

IAM policy documents inside `values.policy` and `values.assume_role_policy` are JSON-encoded strings — always use `json.unmarshal()` before navigating them.

### CI

`.github/workflows/policy.yml` runs on changes to `policy/` or `fixtures/`. It installs conftest v0.55.0 and OPA, loops over all `fixtures/*.json` with conftest, then runs `opa test policy/ -v`. Violations against CloudGoat fixtures are **expected** — the fixture IS the misconfigured infra.

### Bootstrap infra

`infra/bootstrap/` is a one-time Terraform stack that provisions:
- S3 + DynamoDB for remote state (`jwoodsiii/state-backend/aws` module)
- GitHub OIDC roles for CI (`jwoodsiii/github-oidc/aws` module) — scan role gets `ReadOnlyAccess`, apply role gets `AdministratorAccess`

## Skills

`/fixture-to-rego` — use this whenever writing OPA policies from a CloudGoat scenario. It encodes the normalization step, the structural/detective split, test harness conventions, and validates output before writing files. Trigger it with "write the rego policies", "generate the OPA rules", or "convert the fixture to policies".

Reference files the skill reads:
- `skills/fixture-to-rego/references/structural-patterns.md` — common misconfig patterns per AWS resource type
- `skills/fixture-to-rego/references/rego-idioms.md` — Rego patterns for parsing IAM JSON, handling string-vs-array Principal/Action/Resource fields, tag checks

## Key conventions

- `import rego.v1` in all new Rego files (required for OPA 0.60+ modern syntax)
- Every `deny` or `warn` rule must have both a `_violation` test and a `_pass` test — no untested rules
- Principal/Action/Resource fields in IAM JSON can be a string or array; always handle both (see `rego-idioms.md`)
- `policy/` subdirectories follow the CloudGoat scenario name exactly (e.g., `iam_enum_basics`)
