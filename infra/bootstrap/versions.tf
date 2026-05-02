terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # BOOTSTRAP SEQUENCE:
  # 1. Comment out this backend block on first run - state lives locally
  # 2. terraform init && terraform apply (creates bucket, table, OIDC, roles)
  # 3. Uncomment this block
  # 4. terraform init -migrate-state (uploads local state into the new bucket)
  # 5. Add terraform.tfstate* to .gitignore, commit everything
  #
  # TEARDOWN (if you ever need to destroy these resources):
  # Reverse the process: comment out the backend, migrate state back to local,
  # remove prevent_destroy from the module, then terraform destroy.
  backend "s3" {
    bucket         = "tfstate-cloudgoat-bucket"
    key            = "bootstrap/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tfstate-cloudgoat-locks"
    encrypt        = true
  }
}
