//! Client IP resolution, kept in one place so handlers never touch transport
//! specifics — and so no Lambda/API-Gateway type ever leaks into a handler.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::state::AppState;

/// Resolve the client IP, honoring exactly `trusted_hops` reverse proxies.
///
/// `X-Forwarded-For` is client-controlled, so it is only consulted when a proxy
/// count is configured:
/// - `trusted_hops == 0`: ignore `X-Forwarded-For` entirely; use the connection
///   peer (`ConnectInfo`). A client cannot spoof its source this way.
/// - `trusted_hops == N`: the rightmost `N` entries are our own proxies, so the
///   real client is the `(N+1)`th entry from the right. If the header is shorter
///   than that (a spoof attempt or a misconfiguration), fall back to the peer.
pub fn client_ip(parts: &Parts, trusted_hops: usize) -> Option<IpAddr> {
    if trusted_hops > 0
        && let Some(value) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
    {
        let hops: Vec<&str> = value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if hops.len() > trusted_hops
            && let Ok(ip) = hops[hops.len() - 1 - trusted_hops].parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Extractor form of [`client_ip`] that reads the configured trusted-hop count
/// from application state. Never fails.
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(parts, state.trusted_proxy_hops())))
    }
}
