//! One-shot administrative tasks: `migrate` (both databases' embedded
//! migrations) and `seed` (the idempotent fixture from [`iam_api::seed`]).
//!
//! Deployed environments run this as a separate Lambda function, invoked as
//! `{"task": "migrate" | "seed"}`, so that (a) the serving function never
//! holds owner-role (DDL) database credentials — only this one does — and
//! (b) seed secrets return in the invoke response payload instead of landing
//! in logs. Locally it is a plain CLI:
//! `cargo run -p iam-api --bin admin -- migrate` (the default) or `-- seed`.
//!
//! Deliberately does NOT read the full service `Config`: migrations need no
//! signing keys, and requiring them here would force copying every secret into
//! the admin function's environment.

use serde_json::{Value, json};

/// Owner-role URL for the identity database; falls back to `DATABASE_URL` for
/// single-role local setups (mirroring `runtime::build`).
fn identity_migration_url() -> anyhow::Result<String> {
    env_fallback("IAM_MIGRATION_DATABASE_URL", "DATABASE_URL")
}

/// Owner-role URL for the connections database. The dev compose setup has a
/// single owning role there, so the fallback is the status quo.
fn connections_migration_url() -> anyhow::Result<String> {
    env_fallback(
        "CONNECTIONS_MIGRATION_DATABASE_URL",
        "CONNECTIONS_DATABASE_URL",
    )
}

fn env_fallback(primary: &str, fallback: &str) -> anyhow::Result<String> {
    std::env::var(primary)
        .or_else(|_| std::env::var(fallback))
        .map_err(|_| anyhow::anyhow!("neither {primary} nor {fallback} is set"))
}

/// Apply both migration sets. Same embedded migrators the dev startup uses
/// (`sqlx::migrate!`), so there is no CLI-version skew and each database keeps
/// its own `_sqlx_migrations` ledger.
async fn migrate() -> anyhow::Result<Value> {
    let identity_pool = iam_store::connect_postgres(&identity_migration_url()?, 1).await?;
    iam_store::run_identity_migrations(&identity_pool).await?;
    identity_pool.close().await;

    let connections_pool = iam_connections::connect(&connections_migration_url()?, 1).await?;
    iam_connections::run_migrations(&connections_pool).await?;
    connections_pool.close().await;

    tracing::info!("migrations applied to both databases");
    Ok(json!({ "task": "migrate", "status": "ok" }))
}

/// Seed writes only through the identity store as the ordinary app role — no
/// owner credential, and no DynamoDB/WebAuthn/keyring construction needed.
async fn seed() -> anyhow::Result<Value> {
    let url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is not set"))?;
    let pool = iam_store::connect_postgres(&url, 1).await?;
    let store = iam_store::PgStore::new(pool);
    let report = iam_api::seed::run(&store).await?;
    Ok(json!({ "task": "seed", "status": "ok", "report": report }))
}

async fn run_task(task: &str) -> anyhow::Result<Value> {
    match task {
        "migrate" => migrate().await,
        "seed" => seed().await,
        other => anyhow::bail!("unknown task {other:?} (expected \"migrate\" or \"seed\")"),
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

#[cfg(not(feature = "lambda"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();
    let task = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "migrate".to_string());
    let out = run_task(&task).await?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[cfg(feature = "lambda")]
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    init_tracing();
    lambda_runtime::run(lambda_runtime::service_fn(handle)).await
}

#[cfg(feature = "lambda")]
async fn handle(event: lambda_runtime::LambdaEvent<Value>) -> Result<Value, lambda_runtime::Error> {
    let task = event
        .payload
        .get("task")
        .and_then(Value::as_str)
        .unwrap_or("migrate")
        .to_string();
    run_task(&task).await.map_err(Into::into)
}
