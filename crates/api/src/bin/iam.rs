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
    // Behind API Gateway there is no listener; the router is driven directly,
    // so ConnectInfo is absent — and X-Forwarded-For is client-controlled, so
    // it is not a safe substitute. API Gateway terminates the client connection
    // and records the true peer IP in the request context; surface that as
    // ConnectInfo so `ip::client_ip` (and rate limiting / audit) work unchanged
    // with IAM_TRUSTED_PROXY_HOPS=0.
    let app = app.layer(axum::middleware::map_request(shim_connect_info));
    lambda_http::run(app)
        .await
        .map_err(|e| anyhow::anyhow!("lambda runtime error: {e}"))?;
    Ok(())
}

#[cfg(feature = "lambda")]
async fn shim_connect_info(mut req: axum::extract::Request) -> axum::extract::Request {
    use std::net::SocketAddr;

    use axum::extract::ConnectInfo;

    if let Some(ip) = lambda_source_ip(req.extensions()) {
        // Port is not part of the event; 0 is fine — only the IP is ever read.
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 0)));
    }
    req
}

/// The authoritative client IP recorded by API Gateway (HTTP API, payload v2).
/// Any other event shape yields `None`, which degrades to "no client IP"
/// (rate limiting skips, audit records null) rather than an error.
#[cfg(feature = "lambda")]
fn lambda_source_ip(extensions: &axum::http::Extensions) -> Option<std::net::IpAddr> {
    use lambda_http::request::RequestContext;

    match extensions.get::<RequestContext>()? {
        RequestContext::ApiGatewayV2(ctx) => ctx.http.source_ip.as_deref()?.parse().ok(),
        _ => None,
    }
}

#[cfg(all(test, feature = "lambda"))]
mod lambda_tests {
    use super::lambda_source_ip;

    #[test]
    fn source_ip_comes_from_the_v2_request_context() {
        use lambda_http::aws_lambda_events::apigw::ApiGatewayV2httpRequestContext;
        use lambda_http::request::RequestContext;

        // The event structs are #[non_exhaustive]; mutate a default instead.
        let mut ctx = ApiGatewayV2httpRequestContext::default();
        ctx.http.source_ip = Some("203.0.113.9".to_string());

        let mut extensions = axum::http::Extensions::new();
        extensions.insert(RequestContext::ApiGatewayV2(ctx));

        assert_eq!(
            lambda_source_ip(&extensions),
            Some("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn missing_context_yields_none() {
        assert_eq!(lambda_source_ip(&axum::http::Extensions::new()), None);
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,iam_api=debug"));
    fmt().with_env_filter(filter).init();
}
