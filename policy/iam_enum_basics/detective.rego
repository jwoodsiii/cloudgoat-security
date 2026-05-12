package policy.iam_enum_basics.detective

import rego.v1

# Warn: Customer-managed policy has a non-empty description
# Descriptions are almost never populated; any value is an anomaly worth reviewing.
# Attack step 1: flag embedded in policy Description field
warn contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_policy"
	desc := resource.values.description
	desc != ""
	desc != null
	msg := sprintf(
		"IAM policy has a non-empty description (rare; review for embedded data): %v — %q",
		[resource.values.name, desc],
	)
}

# Warn: User has both inline and managed policies — full access requires multiple API calls
# Inline policies are not returned by list-attached-user-policies; a second
# list-user-policies call is needed, making access enumeration harder to audit.
# Attack step 2: flag embedded in inline policy body, discoverable only via separate call
warn contains msg if {
	inline := input.resources[_]
	inline.type == "aws_iam_user_policy"
	managed := input.resources[_]
	managed.type == "aws_iam_user_policy_attachment"
	inline.values.user == managed.values.user
	msg := sprintf(
		"User %v has both inline and managed policies — permissions span two separate API calls",
		[inline.values.user],
	)
}

# Warn: IAM group has a non-default path
# IAM paths default to /; any other value is unusual and may indicate
# metadata steganography (flag embedded in infrastructure metadata).
# Attack step 3: flag embedded in group path field
warn contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_group"
	resource.values.path != "/"
	msg := sprintf(
		"IAM group has non-default path (possible metadata misuse): %v — path: %v",
		[resource.values.name, resource.values.path],
	)
}

# Warn: Role trust policy allows a named IAM user to assume the role directly
# Human users should authenticate via SSO/federation; hardcoded user ARNs
# in trust policies enable direct lateral movement without MFA or federation.
# Attack step 4: flag in role tags, role reachable via direct AssumeRole from user
principal_is_iam_user(stmt) if {
	principal := stmt.Principal.AWS
	is_string(principal)
	contains(principal, ":user/")
}

principal_is_iam_user(stmt) if {
	principal := stmt.Principal.AWS[_]
	contains(principal, ":user/")
}

warn contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_role"
	trust := json.unmarshal(resource.values.assume_role_policy)
	stmt := trust.Statement[_]
	stmt.Effect == "Allow"
	principal_is_iam_user(stmt)
	msg := sprintf(
		"Role is directly assumable by a named IAM user (enables identity hopping without federation): %v",
		[resource.values.name],
	)
}

# Warn: Policy Resource ARN contains non-standard characters
# Valid AWS ARNs use alphanumeric characters, hyphens, colons, slashes, and wildcards.
# A curly brace or other special character indicates embedded data in the ARN.
# Attack step 5: flag embedded in policy version document Resource field
resource_arn_non_standard(stmt) if {
	r := stmt.Resource
	is_string(r)
	contains(r, "{")
}

resource_arn_non_standard(stmt) if {
	r := stmt.Resource[_]
	contains(r, "{")
}

warn contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_policy"
	policy := json.unmarshal(resource.values.policy)
	stmt := policy.Statement[_]
	stmt.Effect == "Allow"
	resource_arn_non_standard(stmt)
	msg := sprintf(
		"Policy %v contains non-standard characters in a Resource ARN (possible embedded data)",
		[resource.values.name],
	)
}

# Role tag contains non-standard value pattern
# Attack step: Step 4 (this is strictly for the CTF)
warn contains msg if {
	resource := input.resources[_]
	resource.type == "aws_iam_role"
	val := resource.values.tags[key]
	regex.match(`HSM[{_\-]`, val)
	msg := sprintf(
		"Role %v has flag-like value in tag %v: %v",
		[resource.values.name, key, val],
	)
}
