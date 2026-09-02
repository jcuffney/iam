# iam — cloud deployment

Near-free AWS serverless deployment (~$1.50–4/mo, dominated by Aurora storage):

```
Browser ── https://api.jarvis.cuffney.com
              │  (Cloudflare DNS-only CNAME → API Gateway regional domain)
              ▼
    API Gateway HTTP API ($default route, throttled, execute-api disabled)
              ▼
    Lambda "iam-api" (arm64, private VPC subnets)
      │ lazy Postgres pools          │ DynamoDB client
      ▼                              ▼
   Aurora Serverless v2         DynamoDB iam_challenges / iam_sessions
   (min ACU 0 → pauses when     (on-demand, TTL) via a free Gateway
    idle; Data API enabled)      VPC endpoint — no NAT anywhere
    Lambda "iam-admin" ◄── aws lambda invoke {"task":"migrate"|"seed"}
```

Costs: Lambda/API GW/DynamoDB/ACM/VPC ≈ $0 at hobby volume (always-free tiers;
API GW ~$1/M requests after year one). Aurora: $0 compute while paused,
~$1–3/mo storage/backups, +$0.40/mo for the managed master secret. Wake-up
after ≥5 idle minutes takes ~15s and lands on the first DB-touching request.
Always-warm later = `min_capacity = 0.5` in [aurora.tf](aurora.tf) (~$44/mo),
or pg_dump to an RDS t4g.micro (~$13/mo).

## One-time bootstrap (order matters)

### 0. Decide the WebAuthn identity — a one-way door

`IAM_RP_ID` (default `jarvis.cuffney.com`, see [variables.tf](variables.tf))
binds every passkey permanently. It is where the **browser pages** driving
WebAuthn ceremonies live — not the API hostname. Change it freely until the
first real registration; never after.

### 1. State bucket (by hand, once)

```bash
aws s3api create-bucket --bucket jcuffney-iam-tfstate --region us-east-1
aws s3api put-bucket-versioning --bucket jcuffney-iam-tfstate \
  --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket jcuffney-iam-tfstate \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

(If the name is taken, change it here **and** in [versions.tf](versions.tf).)

### 2. Secrets & variables

- Cloudflare: create an API token scoped to **Zone → DNS → Edit** on
  `cuffney.com`, and note the zone ID from the dashboard.
- Keys: `cargo run -p iam-api --bin keygen` → `IAM_SIGNING_KEYS` and
  `IAM_CONNECTIONS_ENC_KEY`. **Back the enc key up out of band** (password
  manager) — losing it makes every stored connection secret unrecoverable.
- Choose three URL-safe database passwords (owner `iam`, runtime `iam_app`,
  `iam_connections`).
- Locally: `cp terraform.tfvars.example terraform.tfvars` and fill it in.

### 3. First apply (locally, with your own admin credentials)

```bash
cargo build --release -p iam-api --features lambda --bin iam --bin admin
for bin in iam admin; do
  mkdir -p target/lambda/$bin
  cp target/release/$bin target/lambda/$bin/bootstrap
  (cd target/lambda/$bin && zip -j bootstrap.zip bootstrap && rm bootstrap)
done
terraform -chdir=infra init
terraform -chdir=infra apply
```

This creates everything, including the Cloudflare records (ACM validates
automatically, no DNS clicking) and the CI deploy role. Aurora takes ~10 min.

> On x86 machines the local build produces x86 binaries — that first upload
> won't run on the arm64 Lambdas, which is fine: CI replaces it on the first
> push. Alternatively build with `cargo lambda build --release --arm64` locally.

### 4. Database roles — BEFORE the first migration

Migration `0002_least_privilege.sql` silently skips its grants if `iam_app`
doesn't exist yet, leaving a migrated database where every query 500s. Run this
first, via the Data API (no bastion, the DB is never public). Mirrors
[`compose/init-databases.sql`](../compose/init-databases.sql), plus the
`GRANT ... TO postgres` lines RDS needs because the master user isn't a
superuser:

```bash
CLUSTER_ARN=$(terraform -chdir=infra output -raw aurora_cluster_arn)
SECRET_ARN=$(terraform -chdir=infra output -raw aurora_master_secret_arn)
q() { aws rds-data execute-statement --resource-arn "$CLUSTER_ARN" \
      --secret-arn "$SECRET_ARN" --database postgres --sql "$1"; }

q "CREATE ROLE iam LOGIN PASSWORD 'OWNER_PASSWORD'"
q "CREATE ROLE iam_app LOGIN PASSWORD 'APP_PASSWORD'"
q "CREATE ROLE iam_connections LOGIN PASSWORD 'CONNECTIONS_PASSWORD'"
q "GRANT iam TO postgres"
q "GRANT iam_connections TO postgres"
q "CREATE DATABASE iam OWNER iam"
q "CREATE DATABASE iam_connections OWNER iam_connections"
q "REVOKE CONNECT ON DATABASE iam FROM PUBLIC"
q "REVOKE CONNECT ON DATABASE iam_connections FROM PUBLIC"
q "GRANT CONNECT ON DATABASE iam TO iam"
q "GRANT CONNECT ON DATABASE iam TO iam_app"
q "GRANT CONNECT ON DATABASE iam_connections TO iam_connections"
```

Passwords must match `terraform.tfvars` / the GitHub secrets — Terraform pastes
them into the Lambdas' connection URLs. (The first statement wakes a paused
cluster; retry after ~15s if it times out.)

### 5. GitHub repository configuration

Secrets: `CLOUDFLARE_API_TOKEN`, `DB_OWNER_PASSWORD`, `DB_APP_PASSWORD`,
`DB_CONNECTIONS_PASSWORD`, `IAM_SIGNING_KEYS`, `IAM_CONNECTIONS_ENC_KEY`,
`IAM_METRICS_TOKEN`.
Variables: `AWS_DEPLOY_ROLE_ARN` (from `terraform output deploy_role_arn`),
`CLOUDFLARE_ZONE_ID`.

### 6. First CI deploy + migrate + seed

Push to `main`. [deploy.yml](../.github/workflows/deploy.yml) builds arm64
zips, applies Terraform, invokes `iam-admin {"task":"migrate"}`, and smoke
tests. Then seed once — tokens and recovery codes come back in the response
file, not logs:

```bash
aws lambda invoke --function-name iam-admin \
  --payload '{"task":"seed"}' --cli-binary-format raw-in-base64-out \
  --cli-read-timeout 330 seed-output.json
cat seed-output.json   # save the codes, then delete this file
```

### 7. First passkey

Registration needs a browser page at the RP origin
(`https://jarvis.cuffney.com`) calling this API — a one-page static tester on
Cloudflare Pages works. A cross-origin page will also need CORS middleware in
the router (small follow-up; not built yet).

## Day 2

- **Deploys**: push to `main`. One apply updates code + infra, then migrations
  run — so migrations must be expand/contract (additive first, drop later).
- **/metrics**: `curl -H "Authorization: Bearer $IAM_METRICS_TOKEN" https://api.jarvis.cuffney.com/metrics`
- **Ad-hoc SQL**: same `q()` helper as step 4 (add `--database iam`).
- **Make it always-warm**: `min_capacity = 0.5` in [aurora.tf](aurora.tf).
- **Key rotation**: add a kid to `IAM_SIGNING_KEYS`, deploy, flip `active`,
  retire the old kid later. All listed kids verify; only `active` signs.
- **Concurrency cap**: once the account's Lambda concurrency limit comfortably
  exceeds 110, set `api_reserved_concurrency = 10` to hard-cap DB connections.
- **Future OAuth refresh** (iam-connections) needs outbound internet: either a
  NAT Gateway (~$32/mo) or make Aurora publicly accessible and take the
  Lambdas out of the VPC. Both are small changes in [vpc.tf](vpc.tf)/[aurora.tf](aurora.tf).

## Known limits (accepted at this scale)

- First request after ≥5 idle minutes rides the Aurora resume (~15s; fits the
  30s API Gateway cap, barely). Login retries succeed immediately.
- Rate limits, spend/invocation ledgers, and Prometheus counters are
  per-sandbox (README "deployment notes"); fine while concurrency ≈ 1.
- Secrets live in Lambda env + Terraform state (private, encrypted bucket).
  Planned upgrade: an SSM Parameter Store `SigningKeySource` — also needed
  before key rotation grows `IAM_SIGNING_KEYS` toward the 4KB env cap.
