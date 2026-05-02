variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project name - applied as a tag to all resources"
  type        = string
  default     = "cloudgoat"
}

variable "tf_state_bucket" {
  description = "S3 bucket name for Terraform state. Must match the bucket name in the backend block in versions.tf."
  type        = string
  default     = "tfstate-cloudgoat-bucket"
}

variable "tf_lock_table" {
  description = "DynamoDB table name for state locking. Must match the table name in the backend block in versions.tf."
  type        = string
  default     = "tfstate-cloudgoat-locks"
}

variable "github_org" {
  description = "GitHub org or username"
  type        = string
  default     = "jwoodsiii"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "cloudgoat"
}
