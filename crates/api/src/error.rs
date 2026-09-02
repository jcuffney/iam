//! The single error type all handlers return, and its mapping to HTTP.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("too many requests")]
    RateLimited { retry_after_secs: u64 },

    /// A cloned-authenticator signal: the signature counter regressed.
    #[error("credential may be compromised")]
    CredentialCompromise,

    #[error("internal error")]
    Internal(#[source] anyhow::Error),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            // A possible clone is an authentication failure to the client.
            ApiError::CredentialCompromise => StatusCode::UNAUTHORIZED,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        // Internal errors are logged in full but never leak details to clients.
        if let ApiError::Internal(ref e) = self {
            tracing::error!(error = ?e, "internal error");
        }
        let body = json!({ "error": self.to_string() });
        let mut response = (status, Json(body)).into_response();
        if let ApiError::RateLimited { retry_after_secs } = self
            && let Ok(value) = retry_after_secs.to_string().parse()
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        response
    }
}

impl From<iam_store::StoreError> for ApiError {
    fn from(e: iam_store::StoreError) -> Self {
        match e {
            iam_store::StoreError::NotFound => ApiError::NotFound,
            iam_store::StoreError::Conflict(m) => ApiError::Conflict(m),
            other => ApiError::Internal(anyhow::Error::new(other)),
        }
    }
}

impl From<iam_connections::ConnectionsError> for ApiError {
    fn from(e: iam_connections::ConnectionsError) -> Self {
        match e {
            iam_connections::ConnectionsError::NotFound => ApiError::NotFound,
            iam_connections::ConnectionsError::Conflict(m) => ApiError::Conflict(m),
            iam_connections::ConnectionsError::InvalidCapability(m) => ApiError::BadRequest(m),
            other => ApiError::Internal(anyhow::Error::new(other)),
        }
    }
}

impl From<iam_auth::AuthError> for ApiError {
    fn from(e: iam_auth::AuthError) -> Self {
        match e {
            iam_auth::AuthError::CounterRegression => ApiError::CredentialCompromise,
            // A ceremony/verification failure is a client-side auth failure, not
            // a server fault.
            iam_auth::AuthError::Webauthn(_) | iam_auth::AuthError::Token(_) => {
                ApiError::Unauthorized("verification failed".into())
            }
            other => ApiError::Internal(anyhow::Error::new(other)),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
