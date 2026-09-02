# Terraform ≥ 1.10 for S3-native state locking (use_lockfile) — no DynamoDB
# lock table needed. The state bucket is created once by hand; see README.md.

terraform {
  required_version = ">= 1.10"

  backend "s3" {
    bucket       = "jcuffney-iam-tfstate" # globally unique; change if taken (must match README bootstrap)
    key          = "iam/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "iam"
      ManagedBy = "terraform"
    }
  }
}

# Scoped token: Zone → DNS → Edit on cuffney.com only. cuffney.com's DNS stays
# in Cloudflare; Terraform only manages the two records this stack needs.
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
