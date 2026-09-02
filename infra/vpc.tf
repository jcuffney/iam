# Private-only VPC: no internet gateway, no NAT ($0). The Lambdas reach
# DynamoDB through a free Gateway endpoint and Aurora over the local network;
# nothing in the service needs public egress today (no outbound HTTP clients,
# JWKS is served not fetched, Lambda credentials come from env).
#
# Future landmine, on purpose: implementing real OAuth refresh in
# iam-connections will need outbound internet — either add a NAT Gateway
# (~$32/mo) or make Aurora publicly accessible and take the Lambdas out of the
# VPC. Both are small, reversible changes here.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "this" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name_prefix }
}

# Two subnets because an Aurora subnet group requires two AZs.
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(aws_vpc.this.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${var.name_prefix}-private-${count.index}" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-private" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Free (Gateway) endpoint — all DynamoDB traffic stays on the AWS network.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${var.name_prefix}-dynamodb" }
}

resource "aws_security_group" "lambda" {
  name        = "${var.name_prefix}-lambda"
  description = "iam Lambda functions"
  vpc_id      = aws_vpc.this.id

  egress {
    description = "Aurora + the DynamoDB gateway endpoint"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "aurora" {
  name        = "${var.name_prefix}-aurora"
  description = "Aurora, reachable only from the iam Lambdas"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "Postgres from the Lambda functions"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }
}
