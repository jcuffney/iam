# Two functions from the same build pipeline (cargo lambda, arm64, `lambda`
# feature): the serving API and the admin (migrate/seed) function. Only the
# admin function receives owner-role (DDL) database URLs — a compromised
# serving function cannot touch schema or the audit table's protections.

resource "aws_lambda_function" "api" {
  function_name = "${var.name_prefix}-api"
  role          = aws_iam_role.lambda_api.arn

  runtime       = "provided.al2023"
  architectures = ["arm64"]
  handler       = "bootstrap"

  # try(): lets validate/plan run before a `cargo lambda build` has produced
  # the zip; an actual apply still fails clearly if it is missing.
  filename         = local.api_zip_path
  source_code_hash = try(filebase64sha256(local.api_zip_path), null)

  # argon2 is CPU-bound and Lambda CPU scales with memory; 1024MB ≈ 0.6 vCPU.
  # If /recover or /register/finish latency disappoints, 1769MB = 1 full vCPU
  # (still inside the always-free compute tier at hobby volume).
  memory_size = 1024
  timeout     = 30 # matches API Gateway's hard 30s integration cap

  reserved_concurrent_executions = var.api_reserved_concurrency

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      # Bootstrap off: IaC owns the Dynamo tables, the admin fn owns migrations.
      IAM_BOOTSTRAP = "false"

      DATABASE_URL             = local.database_url # iam_app: least privilege
      CONNECTIONS_DATABASE_URL = local.connections_database_url

      IAM_DYNAMO_CHALLENGES_TABLE = aws_dynamodb_table.challenges.name
      IAM_DYNAMO_SESSIONS_TABLE   = aws_dynamodb_table.sessions.name

      # One request per sandbox; keep per-sandbox connections tiny.
      IAM_DB_POOL_MAX          = "2"
      IAM_CONNECTIONS_POOL_MAX = "1"

      IAM_RP_ID     = var.rp_id
      IAM_RP_ORIGIN = var.rp_origin
      IAM_RP_NAME   = "iam"

      IAM_SIGNING_KEYS        = var.iam_signing_keys
      IAM_CONNECTIONS_ENC_KEY = var.iam_connections_enc_key

      IAM_ISSUER   = var.issuer
      IAM_AUDIENCE = var.audience

      IAM_METRICS_TOKEN = var.metrics_token

      # 0 always behind API Gateway: the Lambda entry point surfaces the
      # gateway's authoritative sourceIp; X-Forwarded-For is never trusted.
      IAM_TRUSTED_PROXY_HOPS = "0"

      RUST_LOG = "info"
    }
  }

  depends_on = [aws_cloudwatch_log_group.api]
}

resource "aws_lambda_function" "admin" {
  function_name = "${var.name_prefix}-admin"
  role          = aws_iam_role.lambda_admin.arn

  runtime       = "provided.al2023"
  architectures = ["arm64"]
  handler       = "bootstrap"

  filename         = local.admin_zip_path
  source_code_hash = try(filebase64sha256(local.admin_zip_path), null)

  memory_size = 512
  timeout     = 300 # migrations may ride out an Aurora resume

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      # Owner-role URLs: DDL credentials live ONLY here.
      IAM_MIGRATION_DATABASE_URL         = local.migration_database_url
      CONNECTIONS_MIGRATION_DATABASE_URL = local.connections_database_url

      # App-role URL for {"task":"seed"} (writes via the identity store only).
      DATABASE_URL = local.database_url

      RUST_LOG = "info"
    }
  }

  depends_on = [aws_cloudwatch_log_group.admin]
}
