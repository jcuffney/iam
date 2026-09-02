//! Route table and the small infrastructure endpoints.

mod audit_query;
mod auth;
mod authorize;
mod connections;
mod credentials;
mod grants;
mod principals;
mod recover;
mod register;

use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

use crate::state::AppState;

/// Build the complete router. The same router is mounted by the native server
/// and (behind the `lambda` feature) the Lambda entry point.
pub fn build_router(state: AppState) -> Router {
    // Credential endpoints get per-IP rate limiting before authentication.
    let credential = Router::new()
        .route("/register/start", post(register::start))
        .route("/register/finish", post(register::finish))
        .route("/register/device/start", post(register::device_start))
        .route("/auth/start", post(auth::start))
        .route("/auth/finish", post(auth::finish))
        .route("/recover", post(recover::recover))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::ratelimit::limit_by_ip,
        ));

    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_endpoint))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/authorize", post(authorize::authorize))
        .route("/principals", post(principals::create))
        .route("/principals/{id}", get(principals::get))
        .route(
            "/principals/{id}/roles/{role}",
            put(principals::assign_role).delete(principals::revoke_role),
        )
        .route("/principals/{id}/disable", post(principals::disable))
        .route("/principals/{id}/enable", post(principals::enable))
        .route(
            "/principals/{id}/recovery-codes",
            post(principals::reissue_recovery_codes),
        )
        .route("/credentials/{id}", delete(credentials::delete))
        .route("/audit", get(audit_query::query))
        .route(
            "/connections",
            post(connections::create).get(connections::list),
        )
        .route("/connections/{id}", delete(connections::revoke))
        .route("/grants", post(grants::create))
        .route("/grants/{id}", delete(grants::revoke))
        .merge(credential)
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Prometheus exposition. Open when no token is configured (local dev). When
/// `IAM_METRICS_TOKEN` is set, requires `Authorization: Bearer <token>` — the
/// API edge forwards every path here, so the gate has to live in the app.
async fn metrics_endpoint(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<String, axum::http::StatusCode> {
    if let Some(expected) = state.metrics_token() {
        use subtle::ConstantTimeEq;
        let authorized = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| token.as_bytes().ct_eq(expected.as_bytes()).into());
        if !authorized {
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    }
    match state.metrics() {
        Some(handle) => Ok(handle.render()),
        None => Ok(String::new()),
    }
}

/// Public key ring for ecosystem services to verify tokens locally.
async fn jwks(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<serde_json::Value> {
    Json(state.keyring().jwks())
}
