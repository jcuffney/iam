//! Metering interfaces for capability constraints.
//!
//! These are the seam where IAM meets the (out-of-scope) wallet layer. Policy
//! evaluates spend and rate constraints against these traits; only in-memory
//! implementations are provided. Settlement, escrow, and any real wallet
//! integration plug in here later by supplying a different implementation — the
//! trait boundary is the deliverable.

use std::collections::HashMap;
use std::sync::Mutex;

use iam_core::{CapabilityRef, PrincipalId, SpendPeriod};
use time::OffsetDateTime;

/// Reports how much a principal has already spent against a capability within
/// the constraint's period.
pub trait SpendLedger: Send + Sync {
    /// Amount spent in minor currency units for `principal` on `capability`
    /// within `period` as of `now`.
    fn spent_minor(&self, principal: PrincipalId, capability: &CapabilityRef, period: SpendPeriod, now: OffsetDateTime) -> u64;
}

/// Reports how many times a principal has invoked a capability within a
/// trailing window.
pub trait InvocationLedger: Send + Sync {
    /// Invocations by `principal` on `capability` in the last `window_secs`
    /// seconds as of `now`.
    fn invocations_in(&self, principal: PrincipalId, capability: &CapabilityRef, window_secs: u64, now: OffsetDateTime) -> u32;
}

type Key = (PrincipalId, CapabilityRef);

/// In-memory spend ledger for tests and local development. Records each spend
/// with a timestamp and sums those falling inside the requested period.
#[derive(Default)]
pub struct InMemorySpendLedger {
    entries: Mutex<HashMap<Key, Vec<(OffsetDateTime, u64)>>>,
}

impl InMemorySpendLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a spend. Callers do this after a metered invocation settles.
    pub fn record(&self, principal: PrincipalId, capability: &CapabilityRef, amount_minor: u64, at: OffsetDateTime) {
        self.entries
            .lock()
            .unwrap()
            .entry((principal, capability.clone()))
            .or_default()
            .push((at, amount_minor));
    }
}

fn period_start(period: SpendPeriod, now: OffsetDateTime) -> OffsetDateTime {
    let date = now.date();
    match period {
        SpendPeriod::Day => date.with_hms(0, 0, 0).unwrap().assume_offset(now.offset()),
        SpendPeriod::Month => date
            .replace_day(1)
            .unwrap()
            .with_hms(0, 0, 0)
            .unwrap()
            .assume_offset(now.offset()),
    }
}

impl SpendLedger for InMemorySpendLedger {
    fn spent_minor(&self, principal: PrincipalId, capability: &CapabilityRef, period: SpendPeriod, now: OffsetDateTime) -> u64 {
        let start = period_start(period, now);
        self.entries
            .lock()
            .unwrap()
            .get(&(principal, capability.clone()))
            .map(|v| v.iter().filter(|(at, _)| *at >= start && *at <= now).map(|(_, amt)| *amt).sum())
            .unwrap_or(0)
    }
}

/// In-memory invocation ledger for tests and local development.
#[derive(Default)]
pub struct InMemoryInvocationLedger {
    entries: Mutex<HashMap<Key, Vec<OffsetDateTime>>>,
}

impl InMemoryInvocationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, principal: PrincipalId, capability: &CapabilityRef, at: OffsetDateTime) {
        self.entries
            .lock()
            .unwrap()
            .entry((principal, capability.clone()))
            .or_default()
            .push(at);
    }
}

impl InvocationLedger for InMemoryInvocationLedger {
    fn invocations_in(&self, principal: PrincipalId, capability: &CapabilityRef, window_secs: u64, now: OffsetDateTime) -> u32 {
        let cutoff = now - time::Duration::seconds(window_secs as i64);
        self.entries
            .lock()
            .unwrap()
            .get(&(principal, capability.clone()))
            .map(|v| v.iter().filter(|at| **at > cutoff && **at <= now).count() as u32)
            .unwrap_or(0)
    }
}

/// A ledger pair that reports zero for everything — the default when a grant
/// carries no spend or rate constraints.
pub struct NullLedger;

impl SpendLedger for NullLedger {
    fn spent_minor(&self, _: PrincipalId, _: &CapabilityRef, _: SpendPeriod, _: OffsetDateTime) -> u64 {
        0
    }
}

impl InvocationLedger for NullLedger {
    fn invocations_in(&self, _: PrincipalId, _: &CapabilityRef, _: u64, _: OffsetDateTime) -> u32 {
        0
    }
}
