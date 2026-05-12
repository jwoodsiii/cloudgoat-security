package policy.iam_enum_basics.structural

import rego.v1

# ── Rule: AWS managed policy on user ────────────────────────────────────────

test_aws_managed_policy_on_user_violation if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_iam_user_policy_attachment",
		"name": "test",
		"address": "aws_iam_user_policy_attachment.test",
		"values": {
			"policy_arn": "arn:aws:iam::aws:policy/IAMReadOnlyAccess",
			"user": "test-user",
		},
	}]}
}

test_aws_managed_policy_on_user_pass if {
	count(deny) == 0 with input as {"resources": [{
		"type": "aws_iam_user_policy_attachment",
		"name": "test",
		"address": "aws_iam_user_policy_attachment.test",
		"values": {
			"policy_arn": "arn:aws:iam::123456789012:policy/my-scoped-policy",
			"user": "test-user",
		},
	}]}
}

# ── Rule: ReadOnlyAccess on user ─────────────────────────────────────────────

test_readonly_access_on_user_violation if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_iam_user_policy_attachment",
		"name": "test",
		"address": "aws_iam_user_policy_attachment.test",
		"values": {
			"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
			"user": "test-user",
		},
	}]}
}

test_readonly_access_on_user_pass if {
	# Customer-managed policy with no ReadOnlyAccess in name — enumeration rule should not fire
	msgs := {msg | deny[msg] with input as {"resources": [{
		"type": "aws_iam_user_policy_attachment",
		"name": "test",
		"address": "aws_iam_user_policy_attachment.test",
		"values": {
			"policy_arn": "arn:aws:iam::123456789012:policy/my-read-policy",
			"user": "test-user",
		},
	}]}}
	count({m | m := msgs[_]; contains(m, "enumeration")}) == 0
}

# ── Rule: IAM user in role trust policy ─────────────────────────────────────

test_iam_user_in_role_trust_violation if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_iam_role",
		"name": "test-role",
		"address": "aws_iam_role.test-role",
		"values": {
			"name": "test-role",
			"assume_role_policy": `{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/alice"}}],"Version":"2012-10-17"}`,
			"max_session_duration": 3600,
		},
	}]}
}

test_iam_user_in_role_trust_pass if {
	count(deny) == 0 with input as {"resources": [{
		"type": "aws_iam_role",
		"name": "test-role",
		"address": "aws_iam_role.test-role",
		"values": {
			"name": "test-role",
			"assume_role_policy": `{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"}}],"Version":"2012-10-17"}`,
			"max_session_duration": 3600,
		},
	}]}
}

# ── Rule: Inline policy on user ──────────────────────────────────────────────

test_inline_policy_on_user_violation if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_iam_user_policy",
		"name": "test-inline",
		"address": "aws_iam_user_policy.test-inline",
		"values": {
			"name": "test-inline",
			"user": "test-user",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"ec2:DescribeInstances","Effect":"Allow","Resource":"arn:aws:ec2:us-east-1:123:instance/i-1"}]}`,
		},
	}]}
}

test_inline_policy_on_user_pass if {
	# No aws_iam_user_policy resources — rule does not fire
	count(deny) == 0 with input as {"resources": [{
		"type": "aws_iam_user_policy_attachment",
		"name": "test",
		"address": "aws_iam_user_policy_attachment.test",
		"values": {
			"policy_arn": "arn:aws:iam::123456789012:policy/my-scoped-policy",
			"user": "test-user",
		},
	}]}
}

# ── Rule: Wildcard Resource in inline user policy ────────────────────────────

test_wildcard_resource_inline_user_violation if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_iam_user_policy",
		"name": "test-inline",
		"address": "aws_iam_user_policy.test-inline",
		"values": {
			"name": "test-inline",
			"user": "test-user",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"ec2:DescribeInstances","Effect":"Allow","Resource":"*"}]}`,
		},
	}]}
}

test_wildcard_resource_inline_user_pass if {
	# Inline policy present (triggers inline-on-user rule) but Resource is scoped — wildcard rule must not fire
	msgs := {msg | deny[msg] with input as {"resources": [{
		"type": "aws_iam_user_policy",
		"name": "test-inline",
		"address": "aws_iam_user_policy.test-inline",
		"values": {
			"name": "test-inline",
			"user": "test-user",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"ec2:DescribeInstances","Effect":"Allow","Resource":"arn:aws:ec2:us-east-1:123:instance/i-1"}]}`,
		},
	}]}}
	count({m | m := msgs[_]; contains(m, "wildcard Resource")}) == 0
}

# ── Rule: Wildcard Resource in inline role policy ────────────────────────────

test_wildcard_resource_inline_role_violation if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_iam_role_policy",
		"name": "test-role-policy",
		"address": "aws_iam_role_policy.test-role-policy",
		"values": {
			"name": "test-role-policy",
			"role": "test-role",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"iam:ListUsers","Effect":"Allow","Resource":"*"}]}`,
		},
	}]}
}

test_wildcard_resource_inline_role_pass if {
	count(deny) == 0 with input as {"resources": [{
		"type": "aws_iam_role_policy",
		"name": "test-role-policy",
		"address": "aws_iam_role_policy.test-role-policy",
		"values": {
			"name": "test-role-policy",
			"role": "test-role",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"iam:ListUsers","Effect":"Allow","Resource":"arn:aws:iam::123456789012:user/*"}]}`,
		},
	}]}
}
