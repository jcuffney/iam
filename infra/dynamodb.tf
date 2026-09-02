# Ephemeral WebAuthn challenges + sessions. Pre-created here (IAM_BOOTSTRAP is
# false in the cloud), so the runtime role needs only data-plane access — and
# TTL MUST be declared here: nothing else enables it, and without it expired
# items pile up forever (reads re-check expiry in code, so it is a cost leak,
# not a correctness bug). Key schema mirrors crates/store/src/dynamo.rs.

resource "aws_dynamodb_table" "challenges" {
  name         = "${var.name_prefix}_challenges"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "challenge_id"

  attribute {
    name = "challenge_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_dynamodb_table" "sessions" {
  name         = "${var.name_prefix}_sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}
