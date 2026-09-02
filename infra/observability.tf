# Log groups are created here (not auto-created by Lambda) so retention is
# bounded — auto-created groups keep logs forever, which is both a cost leak
# and more retained auth telemetry than a hobby deployment wants.

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/lambda/${var.name_prefix}-api"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "admin" {
  name              = "/aws/lambda/${var.name_prefix}-admin"
  retention_in_days = 14
}

# The whole architecture should cost ~$1.50-4/mo; a $5 budget flags anything
# drifting (a stuck-awake Aurora, runaway logs) before it matters.
resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = "5"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}
