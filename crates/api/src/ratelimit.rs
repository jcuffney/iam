//! Rate limiting for credential endpoints.
//!
//! Per-IP limiting runs as middleware before authentication; per-principal
//! limiting is a helper handlers call once they know the principal. State is
//! in-process (governor) — documented as per-instance; the real brute-force
//! backstop is argon2 hashing plus single-use codes.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::ip::client_ip;
use crate::metrics;
use crate::state::AppState;

/// Retry-After hint. Quotas are per-minute, so a minute is the right ballpark;
/// we avoid computing an exact instant to keep the clock types out of the
/// handler layer.
const RETRY_AFTER_SECS: u64 = 60;

/// Middleware: limit by client IP. Applied to credential endpoints before the
/// auth extractor runs, so unauthenticated floods are shed early.
pub async fn limit_by_ip(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (parts, body) = req.into_parts();
    if let Some(ip) = client_ip(&parts, state.trusted_proxy_hops())
        && state.limiters().by_ip.check_key(&ip).is_err()
    {
        metrics::rate_limited("ip");
        return Err(ApiError::RateLimited {
            retry_after_secs: RETRY_AFTER_SECS,
        });
    }
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// Handler helper: limit by principal id. Applied ONLY to authenticated actions
/// (e.g. `/register/device/start`). It is deliberately NOT used on pre-auth
/// endpoints keyed by the *target* handle — doing so would let anyone who knows
/// a handle exhaust that principal's bucket and lock the victim out. Pre-auth
/// throttling is per-IP (see `limit_by_ip`), backed by argon2 + single-use
/// codes.
pub fn enforce_principal(state: &AppState, principal_id: Uuid) -> ApiResult<()> {
    if state
        .limiters()
        .by_principal
        .check_key(&principal_id)
        .is_err()
    {
        metrics::rate_limited("principal");
        return Err(ApiError::RateLimited {
            retry_after_secs: RETRY_AFTER_SECS,
        });
    }
    Ok(())
}
