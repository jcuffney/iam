//! Outbound-connection management: create (with declared capabilities), list
//! (metadata only), and revoke (which kills dependent grants immediately).
//!
//! `connection:manage` requires cryptographic assurance, so a voice-asserted
//! identity can never create or revoke a connection.

use axum::Json;
use axum::extract::{Path, State};
use iam_connections::NewConnection;
use iam_core::{
    AuditDecision, Capability, CapabilityOperation, Connection, ConnectionAction, ConnectionId,
    ConnectionKind, Permission, RefreshState,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use time::OffsetDateTime;

use crate::audit::{self, AuditEntry};
use crate::error::{ApiError, ApiResult};
use crate::extract::Authenticated;
use crate::guard::require_permission;
use crate::ip::ClientIp;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateConnectionRequest {
    pub provider: String,
    pub kind: ConnectionKind,
    #[serde(default)]
    pub scopes_held: Vec<String>,
    /// The bearer secret to encrypt at rest. Never returned.
    pub secret: String,
    /// Optional refresh token (OAuth).
    pub refresh_secret: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// Declared capabilities as canonical operation strings (`mcp:fs.read`,
    /// `model:claude-fable-5`, or `*` for an opaque API key).
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Serialize)]
pub struct ConnectionView {
    pub id: ConnectionId,
    pub provider: String,
    pub kind: ConnectionKind,
    pub scopes_held: Vec<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub capabilities: Vec<String>,
}

impl ConnectionView {
    fn from(c: Connection, capabilities: Vec<Capability>) -> Self {
        Self {
            id: c.id,
            provider: c.provider,
            kind: c.kind,
            scopes_held: c.scopes_held,
            expires_at: c.expires_at,
            capabilities: capabilities
                .into_iter()
                .map(|cap| cap.operation.to_string())
                .collect(),
        }
    }
}

/// POST /connections — register an outbound connection (connection:manage).
pub async fn create(
    State(state): State<AppState>,
    auth: Authenticated,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateConnectionRequest>,
) -> ApiResult<Json<ConnectionView>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Connection(ConnectionAction::Manage),
        None,
    )
    .await?;

    // Parse and validate declared capabilities.
    let id = ConnectionId::new();
    let mut capabilities = Vec::new();
    for op in &req.capabilities {
        let operation = CapabilityOperation::from_str(op).map_err(ApiError::BadRequest)?;
        capabilities.push(Capability {
            connection_id: id,
            operation,
        });
    }

    let connection = Connection {
        id,
        principal_id: auth.principal.id,
        org_id: auth.principal.org_id,
        provider: req.provider,
        kind: req.kind,
        scopes_held: req.scopes_held,
        expires_at: req.expires_at,
        refresh: if req.refresh_secret.is_some() {
            RefreshState::Refreshable {
                last_refreshed_at: None,
                status: None,
            }
        } else {
            RefreshState::None
        },
        created_at: OffsetDateTime::now_utc(),
        revoked_at: None,
    };

    // Secrets go to the connections store in the clear and are sealed there
    // with its own key — the api layer never holds the connections key.
    let refresh = req.refresh_secret.as_deref().map(|r| r.as_bytes());
    state
        .connections()
        .create_connection(NewConnection {
            connection: &connection,
            secret: req.secret.as_bytes(),
            refresh,
            capabilities: &capabilities,
        })
        .await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "connection.create".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("connection {id}")),
            ip,
        },
    )
    .await;

    Ok(Json(ConnectionView::from(connection, capabilities)))
}

/// GET /connections — the caller's own connections, metadata only
/// (connection:read).
pub async fn list(
    State(state): State<AppState>,
    auth: Authenticated,
) -> ApiResult<Json<Vec<ConnectionView>>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Connection(ConnectionAction::Read),
        None,
    )
    .await?;

    let connections = state
        .connections()
        .list_connections(auth.principal.id)
        .await?;
    let mut views = Vec::with_capacity(connections.len());
    for c in connections {
        let caps = state.connections().list_capabilities(c.id).await?;
        views.push(ConnectionView::from(c, caps));
    }
    Ok(Json(views))
}

/// DELETE /connections/{id} — revoke a connection (connection:manage). Every
/// grant referencing it becomes non-live at once.
pub async fn revoke(
    State(state): State<AppState>,
    auth: Authenticated,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Connection(ConnectionAction::Manage),
        None,
    )
    .await?;
    let connection_id = ConnectionId(
        id.parse()
            .map_err(|_| ApiError::BadRequest("invalid connection id".into()))?,
    );

    // Only the owner may revoke their connection.
    let connection = state.connections().get_connection(connection_id).await?;
    if connection.principal_id != auth.principal.id {
        return Err(ApiError::Forbidden(
            "not the owner of this connection".into(),
        ));
    }

    state
        .connections()
        .revoke_connection(connection_id, OffsetDateTime::now_utc())
        .await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "connection.revoke".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("connection {connection_id}")),
            ip,
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "revoked": connection_id })))
}
