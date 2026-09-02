# Execution roles (least privilege) and the GitHub OIDC deploy role.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# --- Serving function ------------------------------------------------------

resource "aws_iam_role" "lambda_api" {
  name               = "${var.name_prefix}-api"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Logs + ENI management for VPC attachment.
resource "aws_iam_role_policy_attachment" "api_vpc" {
  role       = aws_iam_role.lambda_api.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Data-plane only, on exactly the two tables. The app never needs
# Describe/CreateTable in the cloud: IAM_BOOTSTRAP=false skips ensure_tables,
# and the code's access pattern is Put/Get/(conditional)Delete by key.
data "aws_iam_policy_document" "api_dynamo" {
  statement {
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
    ]
    resources = [
      aws_dynamodb_table.challenges.arn,
      aws_dynamodb_table.sessions.arn,
    ]
  }
}

resource "aws_iam_role_policy" "api_dynamo" {
  name   = "dynamo-data-plane"
  role   = aws_iam_role.lambda_api.id
  policy = data.aws_iam_policy_document.api_dynamo.json
}

# --- Admin function --------------------------------------------------------
# Talks only to Postgres; needs nothing beyond logs + VPC networking.

resource "aws_iam_role" "lambda_admin" {
  name               = "${var.name_prefix}-admin"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "admin_vpc" {
  role       = aws_iam_role.lambda_admin.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# --- GitHub Actions deploy role (OIDC, no long-lived keys) -----------------

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS validates GitHub's cert against trusted CAs; the thumbprint is required
  # by the API but no longer load-bearing.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "deploy_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Only this repo's main branch (push + workflow_dispatch on main).
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name               = "${var.name_prefix}-deploy"
  assume_role_policy = data.aws_iam_policy_document.deploy_trust.json
}

# Terraform manages IAM roles, RDS, VPC, Lambda, API GW, DynamoDB, ACM, logs
# and budgets — a tight custom policy would be long and brittle. Admin on a
# role assumable only by this repo's main branch is the pragmatic solo-account
# tradeoff; tighten later if the account grows other workloads.
resource "aws_iam_role_policy_attachment" "deploy_admin" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
