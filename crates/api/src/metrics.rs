//! Prometheus counter helpers.
//!
//! Thin wrappers over the `metrics` macros so counter names live in one place.
//! When no recorder is installed (e.g. in tests) these are cheap no-ops.

/// Authentication attempts, labeled by outcome (`success` / `failure`).
pub fn auth_attempt(outcome: &'static str) {
    metrics::counter!("iam_auth_attempts_total", "outcome" => outcome).increment(1);
}

/// Authorization decisions, labeled by decision and reason code.
pub fn authorize_decision(decision: &'static str, reason: &'static str) {
    metrics::counter!("iam_authorize_decisions_total", "decision" => decision, "reason" => reason)
        .increment(1);
}

/// A signature-counter regression — a possible cloned authenticator.
pub fn counter_regression() {
    metrics::counter!("iam_counter_regression_total").increment(1);
}

/// A request rejected by a rate limiter, labeled by which key hit the limit.
pub fn rate_limited(key: &'static str) {
    metrics::counter!("iam_rate_limited_total", "key" => key).increment(1);
}

/// Register the counters so they appear at zero before the first event. Called
/// once at startup after the recorder is installed.
pub fn describe() {
    metrics::describe_counter!(
        "iam_auth_attempts_total",
        "WebAuthn authentication attempts by outcome"
    );
    metrics::describe_counter!(
        "iam_authorize_decisions_total",
        "Authorization decisions by decision and reason"
    );
    metrics::describe_counter!(
        "iam_counter_regression_total",
        "Signature-counter regressions (possible cloned authenticators)"
    );
    metrics::describe_counter!(
        "iam_rate_limited_total",
        "Requests rejected by a rate limiter"
    );
    metrics::describe_counter!("iam_refresh_errors_total", "Connection refresh-loop errors");
}
