//! DynamoDB implementations of the ephemeral stores: WebAuthn challenges and
//! active sessions.
//!
//! Two safety notes baked in here:
//! - Challenges are consumed with a conditional `DeleteItem`, so a challenge can
//!   be taken exactly once — replay is impossible even if two requests race.
//! - TTL is treated as garbage collection only. DynamoDB Local never expires
//!   items and real TTL can lag by up to ~48h, so every read also checks
//!   `expires_at` in code and rejects stale records.

use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType, ReturnValue,
    ScalarAttributeType, TimeToLiveSpecification,
};
use iam_core::{Assurance, OrgId, PrincipalId};
use time::OffsetDateTime;

use crate::error::{StoreError, StoreResult};
use crate::records::{ChallengeMode, ChallengeRecord, SessionRecord, SessionScope};
use crate::traits::{ChallengeStore, SessionStore};

pub const CHALLENGES_TABLE: &str = "iam_challenges";
pub const SESSIONS_TABLE: &str = "iam_sessions";
const TTL_ATTRIBUTE: &str = "expires_at";

/// DynamoDB-backed challenge and session store.
#[derive(Clone)]
pub struct DynamoStore {
    client: Client,
    challenges_table: String,
    sessions_table: String,
}

impl DynamoStore {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            challenges_table: CHALLENGES_TABLE.to_string(),
            sessions_table: SESSIONS_TABLE.to_string(),
        }
    }

    /// Create both tables if absent and enable TTL on `expires_at`. Idempotent;
    /// safe to call on every dev startup.
    pub async fn ensure_tables(&self) -> StoreResult<()> {
        self.ensure_table(&self.challenges_table, "challenge_id")
            .await?;
        self.ensure_table(&self.sessions_table, "session_id")
            .await?;
        Ok(())
    }

    async fn ensure_table(&self, table: &str, pk: &str) -> StoreResult<()> {
        let exists = self.client.describe_table().table_name(table).send().await;
        match exists {
            Ok(_) => return Ok(()),
            Err(e) => {
                let svc = e.into_service_error();
                if !svc.is_resource_not_found_exception() {
                    return Err(StoreError::Dynamo(format!("describe {table}: {svc}")));
                }
            }
        }

        self.client
            .create_table()
            .table_name(table)
            .billing_mode(BillingMode::PayPerRequest)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(pk)
                    .attribute_type(ScalarAttributeType::S)
                    .build()
                    .map_err(|e| StoreError::Dynamo(e.to_string()))?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(pk)
                    .key_type(KeyType::Hash)
                    .build()
                    .map_err(|e| StoreError::Dynamo(e.to_string()))?,
            )
            .send()
            .await
            .map_err(|e| {
                StoreError::Dynamo(format!("create {table}: {}", e.into_service_error()))
            })?;

        // TTL is best-effort GC; not enforced. DynamoDB Local accepts this call
        // but never actually expires items, which is why reads re-check.
        let _ = self
            .client
            .update_time_to_live()
            .table_name(table)
            .time_to_live_specification(
                TimeToLiveSpecification::builder()
                    .attribute_name(TTL_ATTRIBUTE)
                    .enabled(true)
                    .build()
                    .map_err(|e| StoreError::Dynamo(e.to_string()))?,
            )
            .send()
            .await;

        Ok(())
    }
}

fn s(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_string())
}
fn n(v: i64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

fn get_s(item: &HashMap<String, AttributeValue>, key: &str) -> StoreResult<String> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .cloned()
        .ok_or_else(|| StoreError::DataIntegrity(format!("missing string attr {key}")))
}

fn get_n(item: &HashMap<String, AttributeValue>, key: &str) -> StoreResult<i64> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| StoreError::DataIntegrity(format!("missing numeric attr {key}")))
}

#[async_trait]
impl ChallengeStore for DynamoStore {
    async fn put_challenge(&self, record: &ChallengeRecord) -> StoreResult<()> {
        self.client
            .put_item()
            .table_name(&self.challenges_table)
            .item("challenge_id", s(&record.challenge_id))
            .item("mode", s(&serde_plain(&record.mode)?))
            .item("principal_id", s(&record.principal_id.to_string()))
            .item("org_id", s(&record.org_id.to_string()))
            .item(
                "state",
                AttributeValue::B(Blob::new(record.state_blob.clone())),
            )
            .item(TTL_ATTRIBUTE, n(record.expires_at.unix_timestamp()))
            .send()
            .await
            .map_err(|e| {
                StoreError::Dynamo(format!("put challenge: {}", e.into_service_error()))
            })?;
        Ok(())
    }

    async fn take_challenge(
        &self,
        challenge_id: &str,
        now: OffsetDateTime,
    ) -> StoreResult<Option<ChallengeRecord>> {
        // Consume-once: delete conditional on existence, returning the old item.
        let result = self
            .client
            .delete_item()
            .table_name(&self.challenges_table)
            .key("challenge_id", s(challenge_id))
            .condition_expression("attribute_exists(challenge_id)")
            .return_values(ReturnValue::AllOld)
            .send()
            .await;

        let old = match result {
            Ok(out) => out.attributes,
            Err(e) => {
                let svc = e.into_service_error();
                // Condition failed => already consumed or never existed.
                if svc.is_conditional_check_failed_exception() {
                    return Ok(None);
                }
                return Err(StoreError::Dynamo(format!("take challenge: {svc}")));
            }
        };

        let Some(item) = old else { return Ok(None) };

        let expires_at = OffsetDateTime::from_unix_timestamp(get_n(&item, TTL_ATTRIBUTE)?)
            .map_err(|e| StoreError::DataIntegrity(format!("challenge expires_at: {e}")))?;
        // Even though we deleted it, honor expiry in code: an expired challenge
        // must not be usable.
        if expires_at <= now {
            return Ok(None);
        }

        let state_blob = item
            .get("state")
            .and_then(|v| v.as_b().ok())
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| StoreError::DataIntegrity("missing challenge state".into()))?;

        Ok(Some(ChallengeRecord {
            challenge_id: get_s(&item, "challenge_id")?,
            mode: parse_plain(&get_s(&item, "mode")?, "challenge mode")?,
            principal_id: parse_id(&get_s(&item, "principal_id")?, "principal_id")?,
            org_id: OrgId(parse_uuid(&get_s(&item, "org_id")?, "org_id")?),
            state_blob,
            expires_at,
        }))
    }
}

#[async_trait]
impl SessionStore for DynamoStore {
    async fn put_session(&self, record: &SessionRecord) -> StoreResult<()> {
        self.client
            .put_item()
            .table_name(&self.sessions_table)
            .item("session_id", s(&record.session_id))
            .item("principal_id", s(&record.principal_id.to_string()))
            .item("org_id", s(&record.org_id.to_string()))
            .item("assurance", s(&record.assurance.to_string()))
            .item("scope", s(record.scope.as_str()))
            .item("created_at", n(record.created_at.unix_timestamp()))
            .item(TTL_ATTRIBUTE, n(record.expires_at.unix_timestamp()))
            .send()
            .await
            .map_err(|e| StoreError::Dynamo(format!("put session: {}", e.into_service_error())))?;
        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &str,
        now: OffsetDateTime,
    ) -> StoreResult<Option<SessionRecord>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.sessions_table)
            .key("session_id", s(session_id))
            .send()
            .await
            .map_err(|e| StoreError::Dynamo(format!("get session: {}", e.into_service_error())))?;

        let Some(item) = out.item else {
            return Ok(None);
        };

        let expires_at = OffsetDateTime::from_unix_timestamp(get_n(&item, TTL_ATTRIBUTE)?)
            .map_err(|e| StoreError::DataIntegrity(format!("session expires_at: {e}")))?;
        // TTL is not enforcement — reject expired sessions here.
        if expires_at <= now {
            return Ok(None);
        }
        let created_at = OffsetDateTime::from_unix_timestamp(get_n(&item, "created_at")?)
            .map_err(|e| StoreError::DataIntegrity(format!("session created_at: {e}")))?;

        Ok(Some(SessionRecord {
            session_id: get_s(&item, "session_id")?,
            principal_id: parse_id(&get_s(&item, "principal_id")?, "principal_id")?,
            org_id: OrgId(parse_uuid(&get_s(&item, "org_id")?, "org_id")?),
            assurance: parse_assurance(&get_s(&item, "assurance")?)?,
            scope: parse_scope(&get_s(&item, "scope")?)?,
            created_at,
            expires_at,
        }))
    }

    async fn revoke_session(&self, session_id: &str) -> StoreResult<()> {
        self.client
            .delete_item()
            .table_name(&self.sessions_table)
            .key("session_id", s(session_id))
            .send()
            .await
            .map_err(|e| {
                StoreError::Dynamo(format!("revoke session: {}", e.into_service_error()))
            })?;
        Ok(())
    }
}

// --- small serialization helpers for the enum attributes ---

fn serde_plain<T: serde::Serialize>(v: &T) -> StoreResult<String> {
    // ChallengeMode serializes to a bare string via serde; reuse serde_json and
    // strip the quotes.
    let json = serde_json::to_string(v)?;
    Ok(json.trim_matches('"').to_string())
}

fn parse_plain<T: serde::de::DeserializeOwned>(s: &str, what: &str) -> StoreResult<T> {
    serde_json::from_str(&format!("\"{s}\""))
        .map_err(|e| StoreError::DataIntegrity(format!("{what}: {e}")))
}

fn parse_uuid(s: &str, what: &str) -> StoreResult<uuid::Uuid> {
    uuid::Uuid::parse_str(s).map_err(|e| StoreError::DataIntegrity(format!("{what}: {e}")))
}

fn parse_id(s: &str, what: &str) -> StoreResult<PrincipalId> {
    Ok(PrincipalId(parse_uuid(s, what)?))
}

fn parse_assurance(s: &str) -> StoreResult<Assurance> {
    use std::str::FromStr;
    Assurance::from_str(s).map_err(|e| StoreError::DataIntegrity(format!("assurance: {e}")))
}

fn parse_scope(s: &str) -> StoreResult<SessionScope> {
    match s {
        "full" => Ok(SessionScope::Full),
        "credential_registration_only" => Ok(SessionScope::CredentialRegistrationOnly),
        other => Err(StoreError::DataIntegrity(format!("session scope: {other}"))),
    }
}

// Keep the ChallengeMode enum referenced so a future variant is threaded here.
#[allow(dead_code)]
fn _mode_exhaustive(m: ChallengeMode) {
    match m {
        ChallengeMode::RegisterFirst | ChallengeMode::RegisterDevice | ChallengeMode::Auth => {}
    }
}
