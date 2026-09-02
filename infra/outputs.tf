output "api_url" {
  description = "Public base URL of the API."
  value       = "https://${var.api_domain}"
}

output "apigw_target_domain" {
  description = "Regional API Gateway hostname the Cloudflare CNAME points at."
  value       = aws_apigatewayv2_domain_name.api.domain_name_configuration[0].target_domain_name
}

output "aurora_cluster_arn" {
  description = "For `aws rds-data execute-statement` (role bootstrap, ad-hoc SQL)."
  value       = aws_rds_cluster.this.arn
}

output "aurora_master_secret_arn" {
  description = "Secrets Manager ARN of the managed master credential (Data API auth)."
  value       = aws_rds_cluster.this.master_user_secret[0].secret_arn
}

output "aurora_endpoint" {
  value = aws_rds_cluster.this.endpoint
}

output "dynamo_tables" {
  value = [aws_dynamodb_table.challenges.name, aws_dynamodb_table.sessions.name]
}

output "deploy_role_arn" {
  description = "Set as the AWS_DEPLOY_ROLE_ARN repository variable for CI."
  value       = aws_iam_role.deploy.arn
}

output "admin_function_name" {
  description = "Invoke with {\"task\":\"migrate\"} or {\"task\":\"seed\"}."
  value       = aws_lambda_function.admin.function_name
}
