//! Running the coordination server.
//!
//! Two loops. One accepts connections and gives each its own task, so a slow or
//! hostile node cannot hold up anyone else. The other does housekeeping on a
//! timer: discarding introductions nobody answered, forgetting rate-limit
//! records for addresses that have behaved, and trimming the audit log.
//!
//! Neither loop ever blocks on a node. That is the single property that keeps
//! one broken machine from taking the company's remote access down with it.

use crate::db::AuditEntry;
use crate::session::{handle_connection, ServerState};
use bark_core::Result;
use std::sync::Arc;
use std::time::Duration;

/// How often housekeeping runs.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// How long audit entries are kept.
///
/// Long enough to investigate something noticed weeks later, short enough that
/// the file stays small on a server running for years. Configurable later if an
/// operator needs a different retention period.
pub const AUDIT_RETENTION_DAYS: u32 = 180;

// Checked when the crate is built rather than when tests run: a retention
// period too short to investigate something noticed weeks later should stop
// the build, not wait for someone to run the suite.
const _: () = assert!(AUDIT_RETENTION_DAYS >= 90);

/// Accepts connections until the endpoint is closed.
pub async fn accept_loop(state: Arc<ServerState>, endpoint: quinn::Endpoint) {
    tracing::info!(
        address = ?endpoint.local_addr().ok(),
        "BARK coordination server accepting connections"
    );

    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => handle_connection(state, conn).await,
                Err(e) => {
                    // A failed handshake is routine: a port scanner, a stale
                    // retry, a client with the wrong certificate pinned.
                    tracing::debug!("an incoming connection did not complete: {e}");
                }
            }
        });
    }

    tracing::info!("BARK coordination server stopped accepting connections");
}

/// Periodic housekeeping. Runs until cancelled.
pub async fn maintenance_loop(state: Arc<ServerState>) {
    let mut ticks: u64 = 0;
    loop {
        tokio::time::sleep(MAINTENANCE_INTERVAL).await;
        ticks += 1;

        let expired = state.registry.expire_exchanges();
        if !expired.is_empty() {
            tracing::debug!(count = expired.len(), "discarded unanswered introductions");
        }

        state.registry.prune_limiters();

        // Once an hour, trim the audit log.
        if ticks % (3600 / MAINTENANCE_INTERVAL.as_secs().max(1)) == 0 {
            match state.db.prune_audit(AUDIT_RETENTION_DAYS) {
                Ok(0) => {}
                Ok(n) => tracing::info!(removed = n, "trimmed the audit log"),
                Err(e) => tracing::warn!("could not trim the audit log: {e}"),
            }
        }
    }
}

/// Starts both loops on the current runtime and returns their handles.
pub fn spawn(
    state: Arc<ServerState>,
    endpoint: quinn::Endpoint,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let accept = tokio::spawn(accept_loop(state.clone(), endpoint));
    let maintenance = tokio::spawn(maintenance_loop(state));
    (accept, maintenance)
}

/// Records that the server started, so the audit log shows restarts.
pub fn note_start(state: &ServerState, address: std::net::SocketAddr) -> Result<()> {
    state.db.audit(
        &AuditEntry::new("server-start", true)
            .detail(format!("version {} listening on {address}", state.version)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_trimming_runs_about_once_an_hour() {
        let per_hour = 3600 / MAINTENANCE_INTERVAL.as_secs();
        assert!(per_hour > 1, "the interval must divide into an hour");
        assert_eq!(3600 % MAINTENANCE_INTERVAL.as_secs(), 0, "and divide evenly");
    }
}
