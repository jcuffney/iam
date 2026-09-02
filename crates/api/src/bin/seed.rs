//! Seed a development fixture: one org, two adult humans (one admin, one
//! ordinary user), one device, and one agent, with the five standard roles.
//!
//! Idempotent: existing orgs/roles/principals are left in place. Newly created
//! principals get fresh recovery codes and a registration token, printed once.
//! The fixture itself lives in [`iam_api::seed`], shared with the `admin` bin.

use iam_api::runtime;
use iam_api::{Config, seed};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;
    let built = runtime::build(&config, None).await?;

    let report = seed::run(built.state.identity()).await?;

    println!("Seeded org '{}' ({})", report.org_slug, report.org_id);
    println!();

    for p in &report.principals {
        if !p.created {
            println!("principal '{}' already exists — skipping", p.handle);
            continue;
        }
        println!(
            "principal '{}' ({}) [{}] id={}",
            p.handle, p.kind, p.role, p.id
        );
        if let Some(token) = &p.registration_token {
            println!("    registration_token: {token}");
        }
        if let Some(codes) = &p.recovery_codes {
            println!("    recovery_codes: {}", codes.join(", "));
        }
    }

    println!();
    println!("Done. Recovery codes and registration tokens above are shown ONCE.");
    Ok(())
}
