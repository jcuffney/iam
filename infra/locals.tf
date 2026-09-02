locals {
  # cargo lambda build --output-format zip puts each binary's zip here.
  # CI's build job (and a local `cargo lambda build`) must run before apply.
  api_zip_path   = "${path.module}/../target/lambda/iam/bootstrap.zip"
  admin_zip_path = "${path.module}/../target/lambda/admin/bootstrap.zip"

  # Connection URLs assembled from the cluster endpoint + the role passwords
  # created in the one-time bootstrap SQL (README step 4). sslmode=require:
  # the cluster parameter group also forces SSL server-side.
  db_host = aws_rds_cluster.this.endpoint

  database_url             = "postgres://iam_app:${var.db_app_password}@${local.db_host}:5432/iam?sslmode=require"
  migration_database_url   = "postgres://iam:${var.db_owner_password}@${local.db_host}:5432/iam?sslmode=require"
  connections_database_url = "postgres://iam_connections:${var.db_connections_password}@${local.db_host}:5432/iam_connections?sslmode=require"
}
