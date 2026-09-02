//! The `iam` service binary.
//!
//! Native by default: an axum server on localhost against the docker-compose
//! Postgres and DynamoDB Local — the whole developer loop is `cargo run`. With
//! the `lambda` feature it becomes a Lambda handler instead; the router and all
//! handler logic are identical, only the runtime differs.

use std::sync::Arc;
use std::time::Duration;

use iam_api::runtime::{self, Built};
use iam_api::{Config, build_router};
use iam_connections::{LoggingRefreshProvider, RefreshConfig, run_refresh_loop};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Config::from_env()?;

    // Metrics recorder (global). Installed once here so /metrics can render.
    let prometheus = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("failed to install metrics recorder: {e}"))?;
    iam_api::metrics::describe();

    let Built {
        state,
        connections,
        limiters,
    } = runtime::build(&config, Some(prometheus)).await?;

    // Background: refresh loop (separable, no handler deps) and rate-limiter GC.
    tokio::spawn(run_refresh_loop(
        connections,
        Arc::new(LoggingRefreshProvider),
        RefreshConfig::default(),
    ));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            limiters.retain_recent();
        }
    });

    let app = build_router(state);

    serve(app, &config.listen_addr).await
}

#[cfg(not(feature = "lambda"))]
async fn serve(app: axum::Router, addr: &str) -> anyhow::Result<()> {
    use std::net::SocketAddr;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "iam listening");
    // ConnectInfo so the client IP is available to rate limiting and audit.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(feature = "lambda")]
async fn serve(app: axum::Router, _addr: &str) -> anyhow::Result<()> {
    // Behind API Gateway there is no listener; the router is driven directly.
    // Client IP comes from X-Forwarded-For (see ip::client_ip).
    lambda_http::run(app)
        .await
        .map_err(|e| anyhow::anyhow!("lambda runtime error: {e}"))?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,iam_api=debug"));
    fmt().with_env_filter(filter).init();
}
