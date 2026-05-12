package policy.iam_enum_basics.structural

import rego.v1

_managed_policy_severity(policy_arn) := "CRITICAL" if {
	contains(policy_arn, "AdministratorAccess")
}

_managed_policy_severity(policy_arn) := "HIGH" if {
	contains(policy_arn, "ReadOnlyAccess")
}

_managed_policy_severity(policy_arn) := "HIGH" if {
	contains(policy_arn, "FullAccess")
}

_managed_policy_severity(policy_arn) := "MEDIUM" if {
	startswith(policy_arn, "arn:aws:iam::aws:policy/")
	not contains(policy_arn, "AdministratorAccess")
	not contains(policy_arn, "ReadOnlyAccess")
	not contains(policy_arn, "FullAccess")
}

# Deny: AWS managed policy attached directly to user
# Severity: interpolated into msg based on policy
# Resource: aws_iam_user_policy_attachment
deny contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_user_policy_attachment"
	startswith(resource.values.policy_arn, "arn:aws:iam::aws:policy/")
	severity := _managed_policy_severity(resource.values.policy_arn)
	msg := sprintf(
		"[%v] AWS managed policy attached directly to user %v: %v",
		[severity, resource.values.user, resource.values.policy_arn],
	)
}

# Deny: IAM user principal in role trust policy bypasses federation
# Severity: HIGH
# Resource: aws_iam_role
principal_allows_iam_user(stmt) if {
	principal := stmt.Principal.AWS
	is_string(principal)
	contains(principal, ":user/")
}

principal_allows_iam_user(stmt) if {
	principal := stmt.Principal.AWS[_]
	contains(principal, ":user/")
}

deny contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_role"
	trust := json.unmarshal(resource.values.assume_role_policy)
	stmt := trust.Statement[_]
	stmt.Effect == "Allow"
	principal_allows_iam_user(stmt)
	msg := sprintf(
		"Role trust policy allows named IAM user principal (bypasses federation): %v",
		[resource.values.name],
	)
}

# Deny: Any inline policy on a user bypasses managed access reviews
# Severity: MEDIUM
# Resource: aws_iam_user_policy
deny contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_user_policy"
	msg := sprintf(
		"Inline policy on IAM user is invisible to list-attached-user-policies: %v (user: %v)",
		[resource.values.name, resource.values.user],
	)
}

# Deny: Wildcard Resource in inline user policy
# Severity: HIGH
# Resource: aws_iam_user_policy
resource_is_wildcard(stmt) if {
	stmt.Resource == "*"
}

resource_is_wildcard(stmt) if {
	stmt.Resource[_] == "*"
}

deny contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_user_policy"
	policy := json.unmarshal(resource.values.policy)
	stmt := policy.Statement[_]
	stmt.Effect == "Allow"
	resource_is_wildcard(stmt)
	msg := sprintf(
		"Inline user policy grants wildcard Resource (*) access: %v",
		[resource.values.name],
	)
}

# Deny: Wildcard Resource in inline role policy
# Severity: HIGH
# Resource: aws_iam_role_policy
deny contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_role_policy"
	policy := json.unmarshal(resource.values.policy)
	stmt := policy.Statement[_]
	stmt.Effect == "Allow"
	resource_is_wildcard(stmt)
	msg := sprintf(
		"Inline role policy grants wildcard Resource (*) access: %v",
		[resource.values.name],
	)
}
