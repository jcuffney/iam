# Aurora Serverless v2 with scale-to-zero: compute is $0 while paused (after 5
# idle minutes); the first connection after a pause takes ~15s to resume. The
# app's pools are lazy, so that cost lands on the first DB-touching request —
# never on a Lambda cold start or /health.
#
# Always-warm later is a one-line change: min_capacity = 0.5 (~$44/mo).

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-db"
  subnet_ids = aws_subnet.private[*].id
}

# rds.force_ssl is a static parameter — applied at the next instance reboot
# (immediately on first creation).
resource "aws_rds_cluster_parameter_group" "this" {
  name   = "${var.name_prefix}-pg16"
  family = "aurora-postgresql16"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_rds_cluster" "this" {
  cluster_identifier = "${var.name_prefix}-db"
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned" # Serverless v2 runs in provisioned mode
  engine_version     = var.aurora_engine_version

  master_username = "postgres"
  # Master credential lives in Secrets Manager ($0.40/mo) — required anyway to
  # authenticate Data API calls for the one-time role bootstrap and ad-hoc
  # admin SQL, so the database never needs to be publicly reachable.
  manage_master_user_password = true
  enable_http_endpoint        = true # Data API

  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [aws_security_group.aurora.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.this.name

  storage_encrypted       = true
  backup_retention_period = 7
  deletion_protection     = true
  # Identity data: never skip the final snapshot on teardown.
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name_prefix}-db-final"

  serverlessv2_scaling_configuration {
    min_capacity             = 0 # scale-to-zero (needs aurora-postgresql 16.3+)
    max_capacity             = 1
    seconds_until_auto_pause = 300
  }
}

resource "aws_rds_cluster_instance" "this" {
  identifier          = "${var.name_prefix}-db-1"
  cluster_identifier  = aws_rds_cluster.this.id
  instance_class      = "db.serverless"
  engine              = aws_rds_cluster.this.engine
  engine_version      = aws_rds_cluster.this.engine_version
  publicly_accessible = false
}
