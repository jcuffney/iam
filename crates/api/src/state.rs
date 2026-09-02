//! Shared application state handed to every handler.
//!
//! Everything is behind `Arc` (stores are trait objects) so the concrete
//! implementations can be swapped: Postgres/DynamoDB in production, in-memory in
//! tests, with identical handler code.

use std::sync::Arc;
use std::time::Duration;

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use iam_auth::{KeyRing, WebauthnService};
use iam_connections::ConnectionsStore;
use iam_policy::{InvocationLedger, SpendLedger};
use iam_store::{AuditStore, ChallengeStore, IdentityStore, SessionStore};
use metrics_exporter_prometheus::PrometheusHandle;
use std::net::IpAddr;
use std::num::NonZeroU32;
use uuid::Uuid;

/// Rate limiters for credential endpoints, keyed two ways.
pub struct RateLimiters {
    pub by_ip: DefaultKeyedRateLimiter<IpAddr>,
    pub by_principal: DefaultKeyedRateLimiter<Uuid>,
}

impl RateLimiters {
    /// `per_minute` requests are allowed per key per minute (with a small burst).
    pub fn new(per_minute: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(per_minute.max(1)).unwrap());
        Self {
            by_ip: RateLimiter::keyed(quota),
            by_principal: RateLimiter::keyed(quota),
        }
    }

    /// Drop rate-limiter state for keys that have fully recovered, so memory
    /// does not grow without bound. Called periodically.
    pub fn retain_recent(&self) {
        self.by_ip.retain_recent();
        self.by_principal.retain_recent();
    }
}

struct Inner {
    identity: Arc<dyn IdentityStore>,
    audit: Arc<dyn AuditStore>,
    challenges: Arc<dyn ChallengeStore>,
    sessions: Arc<dyn SessionStore>,
    connections: Arc<dyn ConnectionsStore>,
    webauthn: Arc<WebauthnService>,
    keyring: Arc<KeyRing>,
    spend: Arc<dyn SpendLedger>,
    invocations: Arc<dyn InvocationLedger>,
    token_ttl: Duration,
    session_ttl: Duration,
    limiters: Arc<RateLimiters>,
    metrics: Option<PrometheusHandle>,
}

/// Cheap-to-clone handle to the service's shared state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

/// Constructor arguments, grouped to avoid a very long positional signature.
pub struct AppStateParts {
    pub identity: Arc<dyn IdentityStore>,
    pub audit: Arc<dyn AuditStore>,
    pub challenges: Arc<dyn ChallengeStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub connections: Arc<dyn ConnectionsStore>,
    pub webauthn: Arc<WebauthnService>,
    pub keyring: Arc<KeyRing>,
    pub spend: Arc<dyn SpendLedger>,
    pub invocations: Arc<dyn InvocationLedger>,
    pub token_ttl: Duration,
    pub session_ttl: Duration,
    pub limiters: Arc<RateLimiters>,
    pub metrics: Option<PrometheusHandle>,
}

impl AppState {
    pub fn new(parts: AppStateParts) -> Self {
        Self {
            inner: Arc::new(Inner {
                identity: parts.identity,
                audit: parts.audit,
                challenges: parts.challenges,
                sessions: parts.sessions,
                connections: parts.connections,
                webauthn: parts.webauthn,
                keyring: parts.keyring,
                spend: parts.spend,
                invocations: parts.invocations,
                token_ttl: parts.token_ttl,
                session_ttl: parts.session_ttl,
                limiters: parts.limiters,
                metrics: parts.metrics,
            }),
        }
    }

    pub fn identity(&self) -> &dyn IdentityStore {
        self.inner.identity.as_ref()
    }
    pub fn audit(&self) -> &dyn AuditStore {
        self.inner.audit.as_ref()
    }
    pub fn challenges(&self) -> &dyn ChallengeStore {
        self.inner.challenges.as_ref()
    }
    pub fn sessions(&self) -> &dyn SessionStore {
        self.inner.sessions.as_ref()
    }
    pub fn connections(&self) -> &dyn ConnectionsStore {
        self.inner.connections.as_ref()
    }
    pub fn webauthn(&self) -> &WebauthnService {
        &self.inner.webauthn
    }
    pub fn keyring(&self) -> &KeyRing {
        &self.inner.keyring
    }
    pub fn spend_ledger(&self) -> &dyn SpendLedger {
        self.inner.spend.as_ref()
    }
    pub fn invocation_ledger(&self) -> &dyn InvocationLedger {
        self.inner.invocations.as_ref()
    }
    pub fn token_ttl(&self) -> Duration {
        self.inner.token_ttl
    }
    pub fn session_ttl(&self) -> Duration {
        self.inner.session_ttl
    }
    pub fn limiters(&self) -> &Arc<RateLimiters> {
        &self.inner.limiters
    }
    pub fn metrics(&self) -> Option<&PrometheusHandle> {
        self.inner.metrics.as_ref()
    }
}
