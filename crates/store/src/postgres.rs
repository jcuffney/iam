//! Postgres implementations of the durable identity stores.
//!
//! Queries use the compile-time-checked `sqlx::query!` macros against the
//! identity database. Domain types are constructed by hand from raw columns so
//! iam-core never has to depend on sqlx.

use std::str::FromStr;

use async_trait::async_trait;
use iam_core::{
    Assurance, AuditDecision, AuditEvent, Credential, CredentialKind, Org, OrgId,
    PasskeyCredential, Permission, PermissionSet, Principal, PrincipalId, PrincipalKind, Role,
    RoleId,
};
use sqlx::PgPool;

use crate::error::{StoreError, StoreResult};
use crate::records::{AuditFilter, CodePurpose, StoredCode};
use crate::traits::{AuditStore, IdentityStore};

/// Postgres-backed identity and audit store. Both traits share one pool because
/// they live in the same (identity) database.
#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn integrity<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> StoreError + '_ {
    move |e| StoreError::DataIntegrity(format!("{what}: {e}"))
}

#[async_trait]
impl IdentityStore for PgStore {
    async fn create_org(&self, org: &Org) -> StoreResult<()> {
        sqlx::query!(
            "INSERT INTO orgs (id, slug, name, created_at) VALUES ($1, $2, $3, $4)",
            org.id.0,
            org.slug,
            org.name,
            org.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(conflict_or_db)?;
        Ok(())
    }

    async fn get_org(&self, id: OrgId) -> StoreResult<Org> {
        let row = sqlx::query!(
            "SELECT id, slug, name, created_at FROM orgs WHERE id = $1",
            id.0
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        Ok(Org {
            id: row.id.into(),
            slug: row.slug,
            name: row.name,
            created_at: row.created_at,
        })
    }

    async fn get_org_by_slug(&self, slug: &str) -> StoreResult<Org> {
        let row = sqlx::query!(
            "SELECT id, slug, name, created_at FROM orgs WHERE slug = $1",
            slug
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        Ok(Org {
            id: row.id.into(),
            slug: row.slug,
            name: row.name,
            created_at: row.created_at,
        })
    }

    async fn create_principal(&self, principal: &Principal) -> StoreResult<()> {
        sqlx::query!(
            "INSERT INTO principals (id, org_id, kind, handle, display_name, created_at, disabled_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            principal.id.0,
            principal.org_id.0,
            principal.kind.to_string(),
            principal.handle,
            principal.display_name,
            principal.created_at,
            principal.disabled_at,
        )
        .execute(&self.pool)
        .await
        .map_err(conflict_or_db)?;
        Ok(())
    }

    async fn get_principal(&self, id: PrincipalId) -> StoreResult<Principal> {
        let row = sqlx::query!(
            "SELECT id, org_id, kind, handle, display_name, created_at, disabled_at FROM principals WHERE id = $1",
            id.0
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        Ok(Principal {
            id: row.id.into(),
            org_id: row.org_id.into(),
            kind: PrincipalKind::from_str(&row.kind).map_err(integrity("principal kind"))?,
            handle: row.handle,
            display_name: row.display_name,
            created_at: row.created_at,
            disabled_at: row.disabled_at,
        })
    }

    async fn get_principal_by_handle(&self, org_id: OrgId, handle: &str) -> StoreResult<Principal> {
        let row = sqlx::query!(
            "SELECT id, org_id, kind, handle, display_name, created_at, disabled_at \
             FROM principals WHERE org_id = $1 AND handle = $2",
            org_id.0,
            handle
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        Ok(Principal {
            id: row.id.into(),
            org_id: row.org_id.into(),
            kind: PrincipalKind::from_str(&row.kind).map_err(integrity("principal kind"))?,
            handle: row.handle,
            display_name: row.display_name,
            created_at: row.created_at,
            disabled_at: row.disabled_at,
        })
    }

    async fn set_principal_disabled(
        &self,
        id: PrincipalId,
        disabled_at: Option<time::OffsetDateTime>,
    ) -> StoreResult<()> {
        let res = sqlx::query!(
            "UPDATE principals SET disabled_at = $2 WHERE id = $1",
            id.0,
            disabled_at
        )
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn insert_credential(&self, credential: &Credential) -> StoreResult<bool> {
        let Credential::Passkey(pk) = credential;
        let sign_count = pk.sign_count as i64;
        let res = sqlx::query!(
            "INSERT INTO credentials \
             (credential_id, principal_id, kind, passkey_data, sign_count, transports, aaguid, nickname, created_at, last_used_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (credential_id) DO NOTHING",
            pk.credential_id,
            pk.principal_id.0,
            CredentialKind::Passkey.to_string(),
            pk.passkey_blob,
            sign_count,
            &pk.transports,
            pk.aaguid,
            pk.nickname,
            pk.created_at,
            pk.last_used_at,
        )
        .execute(&self.pool)
        .await?;

        if res.rows_affected() == 1 {
            return Ok(true);
        }

        // Row already existed: idempotent for the same principal, conflict for
        // a different one.
        let existing = sqlx::query!(
            "SELECT principal_id FROM credentials WHERE credential_id = $1",
            pk.credential_id
        )
        .fetch_one(&self.pool)
        .await?;
        if existing.principal_id == pk.principal_id.0 {
            Ok(false)
        } else {
            Err(StoreError::Conflict(
                "credential id belongs to another principal".into(),
            ))
        }
    }

    async fn get_credential(&self, credential_id: &[u8]) -> StoreResult<Credential> {
        let row = sqlx::query!(
            "SELECT credential_id, principal_id, passkey_data, sign_count, transports, aaguid, nickname, created_at, last_used_at \
             FROM credentials WHERE credential_id = $1",
            credential_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        Ok(Credential::Passkey(PasskeyCredential {
            credential_id: row.credential_id,
            principal_id: row.principal_id.into(),
            passkey_blob: row.passkey_data,
            sign_count: row.sign_count as u32,
            transports: row.transports,
            aaguid: row.aaguid,
            nickname: row.nickname,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        }))
    }

    async fn list_credentials(&self, principal_id: PrincipalId) -> StoreResult<Vec<Credential>> {
        let rows = sqlx::query!(
            "SELECT credential_id, principal_id, passkey_data, sign_count, transports, aaguid, nickname, created_at, last_used_at \
             FROM credentials WHERE principal_id = $1 ORDER BY created_at",
            principal_id.0
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                Credential::Passkey(PasskeyCredential {
                    credential_id: row.credential_id,
                    principal_id: row.principal_id.into(),
                    passkey_blob: row.passkey_data,
                    sign_count: row.sign_count as u32,
                    transports: row.transports,
                    aaguid: row.aaguid,
                    nickname: row.nickname,
                    created_at: row.created_at,
                    last_used_at: row.last_used_at,
                })
            })
            .collect())
    }

    async fn update_credential_after_auth(&self, updated: &PasskeyCredential) -> StoreResult<()> {
        let sign_count = updated.sign_count as i64;
        let res = sqlx::query!(
            "UPDATE credentials SET passkey_data = $2, sign_count = $3, last_used_at = $4 WHERE credential_id = $1",
            updated.credential_id,
            updated.passkey_blob,
            sign_count,
            updated.last_used_at,
        )
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn delete_credential(&self, credential_id: &[u8]) -> StoreResult<()> {
        let res = sqlx::query!(
            "DELETE FROM credentials WHERE credential_id = $1",
            credential_id
        )
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn create_role(&self, role: &Role) -> StoreResult<()> {
        sqlx::query!(
            "INSERT INTO roles (id, org_id, name) VALUES ($1, $2, $3)",
            role.id.0,
            role.org_id.0,
            role.name
        )
        .execute(&self.pool)
        .await
        .map_err(conflict_or_db)?;
        Ok(())
    }

    async fn get_role_by_name(&self, org_id: OrgId, name: &str) -> StoreResult<Role> {
        let row = sqlx::query!(
            "SELECT id, org_id, name FROM roles WHERE org_id = $1 AND name = $2",
            org_id.0,
            name
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        Ok(Role {
            id: row.id.into(),
            org_id: row.org_id.into(),
            name: row.name,
        })
    }

    async fn set_role_permissions(
        &self,
        role_id: RoleId,
        permissions: &[Permission],
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!("DELETE FROM role_permissions WHERE role_id = $1", role_id.0)
            .execute(&mut *tx)
            .await?;
        for perm in permissions {
            sqlx::query!(
                "INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                role_id.0,
                perm.to_string(),
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn assign_role(&self, principal_id: PrincipalId, role_id: RoleId) -> StoreResult<()> {
        // Derive org_id from the principal so the composite FK is satisfied and
        // cross-org assignment is impossible.
        let org = sqlx::query!(
            "SELECT org_id FROM principals WHERE id = $1",
            principal_id.0
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        sqlx::query!(
            "INSERT INTO principal_roles (org_id, principal_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            org.org_id,
            principal_id.0,
            role_id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(conflict_or_db)?;
        Ok(())
    }

    async fn revoke_role(&self, principal_id: PrincipalId, role_id: RoleId) -> StoreResult<()> {
        sqlx::query!(
            "DELETE FROM principal_roles WHERE principal_id = $1 AND role_id = $2",
            principal_id.0,
            role_id.0
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn roles_for_principal(&self, principal_id: PrincipalId) -> StoreResult<Vec<Role>> {
        let rows = sqlx::query!(
            "SELECT r.id, r.org_id, r.name FROM roles r \
             JOIN principal_roles pr ON pr.role_id = r.id \
             WHERE pr.principal_id = $1 ORDER BY r.name",
            principal_id.0
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| Role {
                id: row.id.into(),
                org_id: row.org_id.into(),
                name: row.name,
            })
            .collect())
    }

    async fn permissions_for_principal(
        &self,
        principal_id: PrincipalId,
    ) -> StoreResult<PermissionSet> {
        let rows = sqlx::query!(
            "SELECT DISTINCT rp.permission FROM principal_roles pr \
             JOIN role_permissions rp ON rp.role_id = pr.role_id \
             WHERE pr.principal_id = $1",
            principal_id.0
        )
        .fetch_all(&self.pool)
        .await?;
        let mut perms = PermissionSet::new();
        for row in rows {
            perms.insert(Permission::from_str(&row.permission).map_err(integrity("permission"))?);
        }
        Ok(perms)
    }

    async fn insert_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
        hashes: &[String],
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        for hash in hashes {
            sqlx::query!(
                "INSERT INTO one_time_codes (principal_id, purpose, code_hash) VALUES ($1, $2, $3)",
                principal_id.0,
                purpose.as_str(),
                hash,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn list_unused_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
    ) -> StoreResult<Vec<StoredCode>> {
        let rows = sqlx::query!(
            "SELECT id, code_hash FROM one_time_codes \
             WHERE principal_id = $1 AND purpose = $2 AND used_at IS NULL",
            principal_id.0,
            purpose.as_str(),
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| StoredCode {
                id: r.id,
                code_hash: r.code_hash,
            })
            .collect())
    }

    async fn mark_code_used(&self, code_id: uuid::Uuid) -> StoreResult<bool> {
        // Atomic single-use: only the first caller to flip used_at gets a row.
        let row = sqlx::query!(
            "UPDATE one_time_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL RETURNING id",
            code_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    async fn delete_unused_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
    ) -> StoreResult<()> {
        sqlx::query!(
            "DELETE FROM one_time_codes WHERE principal_id = $1 AND purpose = $2 AND used_at IS NULL",
            principal_id.0,
            purpose.as_str(),
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl AuditStore for PgStore {
    async fn append(&self, event: &AuditEvent) -> StoreResult<()> {
        sqlx::query!(
            "INSERT INTO audit_events (org_id, actor_id, asserted_id, action, decision, assurance, reason, ip, occurred_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            event.org_id.0,
            event.actor_id.0,
            event.asserted_id.map(|p| p.0),
            event.action,
            event.decision.to_string(),
            event.assurance.map(|a| a.to_string()),
            event.reason,
            event.ip.map(|ip| ip.to_string()),
            event.occurred_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn query(&self, filter: &AuditFilter) -> StoreResult<Vec<AuditEvent>> {
        // All filters optional in one compile-checked statement.
        let rows = sqlx::query!(
            "SELECT org_id, actor_id, asserted_id, action, decision, assurance, reason, ip, occurred_at \
             FROM audit_events \
             WHERE ($1::uuid IS NULL OR org_id = $1) \
               AND ($2::uuid IS NULL OR actor_id = $2) \
               AND ($3::text IS NULL OR action = $3) \
               AND ($4::text IS NULL OR decision = $4) \
               AND ($5::timestamptz IS NULL OR occurred_at >= $5) \
               AND ($6::timestamptz IS NULL OR occurred_at <= $6) \
             ORDER BY occurred_at DESC \
             LIMIT $7",
            filter.org_id.map(|o| o.0),
            filter.actor_id.map(|a| a.0),
            filter.action,
            filter.decision.map(|d| d.to_string()),
            filter.from,
            filter.to,
            filter.limit,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let ip = match row.ip {
                    Some(s) => Some(std::net::IpAddr::from_str(&s).map_err(integrity("audit ip"))?),
                    None => None,
                };
                let assurance = match row.assurance {
                    Some(s) => Some(Assurance::from_str(&s).map_err(integrity("assurance"))?),
                    None => None,
                };
                Ok(AuditEvent {
                    org_id: row.org_id.into(),
                    actor_id: row.actor_id.into(),
                    asserted_id: row.asserted_id.map(Into::into),
                    action: row.action,
                    decision: AuditDecision::from_str(&row.decision)
                        .map_err(integrity("decision"))?,
                    assurance,
                    reason: row.reason,
                    ip,
                    occurred_at: row.occurred_at,
                })
            })
            .collect()
    }
}

/// Map a Postgres unique-violation into our `Conflict`, everything else stays a
/// database error.
fn conflict_or_db(e: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(ref db) = e
        && db.is_unique_violation()
    {
        return StoreError::Conflict(db.message().to_string());
    }
    StoreError::Database(e)
}
