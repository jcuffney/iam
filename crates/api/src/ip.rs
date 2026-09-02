//! Client IP resolution, kept in one place so handlers never touch transport
//! specifics — and so no Lambda/API-Gateway type ever leaks into a handler.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

/// Extractor form of [`client_ip`], usable directly in handler signatures for
/// any state type. Never fails.
pub struct ClientIp(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(parts)))
    }
}

/// Best-effort client IP: the first `X-Forwarded-For` hop when present
/// (API Gateway / reverse proxy), otherwise the peer address from
/// `ConnectInfo` (native server). Returns `None` when neither is available.
pub fn client_ip(parts: &Parts) -> Option<IpAddr> {
    if let Some(xff) = parts.headers.get("x-forwarded-for")
        && let Ok(value) = xff.to_str()
        && let Some(first) = value.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return Some(ip);
    }
    parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip())
}
