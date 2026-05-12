package policy.iam_enum_basics.detective

import rego.v1

# ── Rule: Non-empty policy description ──────────────────────────────────────

test_policy_description_non_empty_violation if {
	count(warn) > 0 with input as {"resources": [{
		"type": "aws_iam_policy",
		"name": "test-policy",
		"address": "aws_iam_policy.test-policy",
		"values": {
			"name": "test-policy",
			"description": "HSM{m4n4g3d_p0l1cy_m4st3r}",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"s3:GetObject","Effect":"Allow","Resource":"arn:aws:s3:::my-bucket/*"}]}`,
		},
	}]}
}

test_policy_description_non_empty_pass if {
	count(warn) == 0 with input as {"resources": [{
		"type": "aws_iam_policy",
		"name": "test-policy",
		"address": "aws_iam_policy.test-policy",
		"values": {
			"name": "test-policy",
			"description": "",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"s3:GetObject","Effect":"Allow","Resource":"arn:aws:s3:::my-bucket/*"}]}`,
		},
	}]}
}

# ── Rule: User has inline + managed policies ─────────────────────────────────

test_inline_and_managed_on_user_violation if {
	count(warn) > 0 with input as {"resources": [
		{
			"type": "aws_iam_user_policy",
			"name": "my-inline",
			"address": "aws_iam_user_policy.my-inline",
			"values": {
				"name": "my-inline",
				"user": "test-user",
				"policy": `{"Version":"2012-10-17","Statement":[{"Action":"ec2:Describe*","Effect":"Allow","Resource":"*"}]}`,
			},
		},
		{
			"type": "aws_iam_user_policy_attachment",
			"name": "my-attach",
			"address": "aws_iam_user_policy_attachment.my-attach",
			"values": {
				"policy_arn": "arn:aws:iam::123456789012:policy/my-policy",
				"user": "test-user",
			},
		},
	]}
}

test_inline_and_managed_on_user_pass if {
	# Only managed policy, no inline — rule does not fire
	count(warn) == 0 with input as {"resources": [{
		"type": "aws_iam_user_policy_attachment",
		"name": "my-attach",
		"address": "aws_iam_user_policy_attachment.my-attach",
		"values": {
			"policy_arn": "arn:aws:iam::123456789012:policy/my-policy",
			"user": "test-user",
		},
	}]}
}

# ── Rule: Group has non-default IAM path ─────────────────────────────────────

test_group_non_default_path_violation if {
	count(warn) > 0 with input as {"resources": [{
		"type": "aws_iam_group",
		"name": "test-group",
		"address": "aws_iam_group.test-group",
		"values": {
			"name": "test-group",
			"path": "/hidden-flag-path/",
		},
	}]}
}

test_group_non_default_path_pass if {
	count(warn) == 0 with input as {"resources": [{
		"type": "aws_iam_group",
		"name": "test-group",
		"address": "aws_iam_group.test-group",
		"values": {
			"name": "test-group",
			"path": "/",
		},
	}]}
}

# ── Rule: Role trust allows named IAM user ───────────────────────────────────

test_role_trust_allows_iam_user_violation if {
	count(warn) > 0 with input as {"resources": [{
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

test_role_trust_allows_iam_user_pass if {
	count(warn) == 0 with input as {"resources": [{
		"type": "aws_iam_role",
		"name": "test-role",
		"address": "aws_iam_role.test-role",
		"values": {
			"name": "test-role",
			"assume_role_policy": `{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/MySAML"}}],"Version":"2012-10-17"}`,
			"max_session_duration": 3600,
		},
	}]}
}

# ── Rule: Policy Resource ARN contains non-standard characters ────────────────

test_policy_resource_arn_non_standard_violation if {
	count(warn) > 0 with input as {"resources": [{
		"type": "aws_iam_policy",
		"name": "test-policy",
		"address": "aws_iam_policy.test-policy",
		"values": {
			"name": "test-policy",
			"description": "",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"s3:GetObject","Effect":"Allow","Resource":"arn:aws:s3:::HSM{s3cr3t_js0n_str1ng}"}]}`,
		},
	}]}
}

test_policy_resource_arn_non_standard_pass if {
	count(warn) == 0 with input as {"resources": [{
		"type": "aws_iam_policy",
		"name": "test-policy",
		"address": "aws_iam_policy.test-policy",
		"values": {
			"name": "test-policy",
			"description": "",
			"policy": `{"Version":"2012-10-17","Statement":[{"Action":"s3:GetObject","Effect":"Allow","Resource":"arn:aws:s3:::my-real-bucket/*"}]}`,
		},
	}]}
}
