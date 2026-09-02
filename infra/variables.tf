variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names. Default keeps DynamoDB table names identical to the code's dev defaults (iam_challenges / iam_sessions)."
  type        = string
  default     = "iam"
}

variable "github_repository" {
  description = "GitHub repo (owner/name) allowed to assume the deploy role via OIDC."
  type        = string
  default     = "jcuffney/iam"
}

# --- Domain / WebAuthn identity -------------------------------------------

variable "api_domain" {
  description = "Public hostname of the API (Cloudflare DNS-only CNAME → API Gateway)."
  type        = string
  default     = "api.jarvis.cuffney.com"
}

variable "rp_id" {
  description = <<-EOT
    WebAuthn relying-party ID — where the BROWSER PAGES that drive passkey
    ceremonies live, not the API hostname. ONE-WAY DOOR: passkeys registered
    under one RP ID are stranded if it ever changes. jarvis.cuffney.com lets a
    future UI at that host (or any *.jarvis.cuffney.com page) register and
    authenticate against this API.
  EOT
  type        = string
  default     = "jarvis.cuffney.com"
}

variable "rp_origin" {
  description = "Browser origin performing WebAuthn ceremonies; must match the page's origin exactly."
  type        = string
  default     = "https://jarvis.cuffney.com"
}

variable "cloudflare_api_token" {
  description = "Cloudflare token scoped to Zone:DNS:Edit on cuffney.com."
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Zone ID of cuffney.com (Cloudflare dashboard → zone overview)."
  type        = string
}

# --- Database credentials --------------------------------------------------
# Role passwords are chosen by you and used twice: once in the one-time
# role-bootstrap SQL (README step 4) and here to build the connection URLs the
# Lambdas receive. Keep them URL-safe (alphanumeric) — they are pasted into
# postgres:// URLs unescaped.

variable "db_owner_password" {
  description = "Password for the `iam` role (identity DB owner; migrations only)."
  type        = string
  sensitive   = true
}

variable "db_app_password" {
  description = "Password for the `iam_app` role (identity DB runtime; least privilege)."
  type        = string
  sensitive   = true
}

variable "db_connections_password" {
  description = "Password for the `iam_connections` role (connections DB owner+runtime)."
  type        = string
  sensitive   = true
}

variable "aurora_engine_version" {
  description = "aurora-postgresql version; scale-to-zero needs 16.3+."
  type        = string
  default     = "16.6"
}

# --- Service secrets -------------------------------------------------------

variable "iam_signing_keys" {
  description = "JSON keyring from `cargo run -p iam-api --bin keygen` (IAM_SIGNING_KEYS)."
  type        = string
  sensitive   = true
}

variable "iam_connections_enc_key" {
  description = "32-byte base64 AES key from keygen (IAM_CONNECTIONS_ENC_KEY). BACK IT UP OUT OF BAND — losing it makes every stored connection secret unrecoverable."
  type        = string
  sensitive   = true
}

variable "metrics_token" {
  description = "Bearer token protecting GET /metrics (any long random string)."
  type        = string
  sensitive   = true
}

# --- Tuning ----------------------------------------------------------------

variable "issuer" {
  description = "JWT `iss` claim. The API's own public origin."
  type        = string
  default     = "https://api.jarvis.cuffney.com"
}

variable "audience" {
  description = "JWT `aud` claim."
  type        = string
  default     = "cuffney-ecosystem"
}

variable "api_reserved_concurrency" {
  description = <<-EOT
    Reserved concurrency for the serving function — the hard ceiling on
    simultaneous sandboxes (and therefore DB connections: N × 3). Null (the
    default) skips reservation entirely, because AWS requires 100 UNRESERVED
    executions account-wide and fresh accounts often have a total limit of only
    10-1000. Set to ~10 once your account's concurrency limit comfortably
    exceeds 110.
  EOT
  type        = number
  default     = null
}

variable "budget_alert_email" {
  description = "Email for the monthly cost-budget alert."
  type        = string
  default     = "josephcuffney@gmail.com"
}
