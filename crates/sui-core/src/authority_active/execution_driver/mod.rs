// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use async_trait::async_trait;
use prometheus::{
    register_int_counter_with_registry, register_int_gauge_with_registry, IntCounter, IntGauge,
    Registry,
};
use sui_metrics::spawn_monitored_task;
use sui_types::{error::SuiResult, messages::VerifiedCertificate};
use tokio::{sync::Semaphore, time::sleep};
use tracing::{debug, error, info, warn};

use super::ActiveAuthority;
use crate::authority::AuthorityState;
use crate::authority_client::AuthorityAPI;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone)]
pub struct ExecutionDriverMetrics {
    executing_transactions: IntGauge,
    executed_transactions: IntCounter,
}

impl ExecutionDriverMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            executing_transactions: register_int_gauge_with_registry!(
                "execution_driver_executing_transactions",
                "Number of currently executing transactions in execution driver",
                registry,
            )
            .unwrap(),
            executed_transactions: register_int_counter_with_registry!(
                "execution_driver_executed_transactions",
                "Cumulative number of transaction executed by execution driver",
                registry,
            )
            .unwrap(),
        }
    }

    pub fn new_for_tests() -> Self {
        let registry = Registry::new();
        Self::new(&registry)
    }
}

#[async_trait]
pub trait PendCertificateForExecution {
    async fn add_pending_certificates(&self, certs: Vec<VerifiedCertificate>) -> SuiResult<()>;
}

#[async_trait]
impl PendCertificateForExecution for &AuthorityState {
    async fn add_pending_certificates(&self, certs: Vec<VerifiedCertificate>) -> SuiResult<()> {
        AuthorityState::add_pending_certificates(self, certs).await
    }
}

/// A no-op PendCertificateForExecution that we use for testing, when
/// we do not care about certificates actually being executed.
pub struct PendCertificateForExecutionNoop;

#[async_trait]
impl PendCertificateForExecution for PendCertificateForExecutionNoop {
    async fn add_pending_certificates(&self, _certs: Vec<VerifiedCertificate>) -> SuiResult<()> {
        Ok(())
    }
}

/// When a notification that a new pending transaction is received we activate
/// processing the transaction in a loop.
pub async fn execution_process<A>(active_authority: Arc<ActiveAuthority<A>>)
where
    A: AuthorityAPI + Send + Sync + 'static + Clone,
{
    info!("Starting pending certificates execution process.");

    // Rate limit concurrent executions to # of cpus.
    let limit = Arc::new(Semaphore::new(num_cpus::get()));

    let mut ready_certificates_stream = active_authority
        .state
        .ready_certificates_stream()
        .await
        .expect(
            "Initialization failed: only the executiion driver should receive ready certificates!",
        );

    // Loop whenever there is a signal that a new transactions is ready to process.
    loop {
        let certificate = if let Some(cert) = ready_certificates_stream.recv().await {
            cert
        } else {
            // Should not happen. Only possible if the AuthorityState has shut down.
            warn!("Ready digest stream from authority state is broken. Retrying in 10s ...");
            sleep(std::time::Duration::from_secs(10)).await;
            continue;
        };
        let digest = *certificate.digest();
        debug!(?digest, "Pending certificate execution activated.");

        // Process any tx that failed to commit.
        if let Err(err) = active_authority.state.process_tx_recovery_log(None).await {
            tracing::error!("Error processing tx recovery log: {:?}", err);
        }

        let limit = limit.clone();
        // hold semaphore permit until task completes. unwrap ok because we never close
        // the semaphore in this context.
        let permit = limit.acquire_owned().await.unwrap();
        let authority = active_authority.clone();

        authority
            .execution_driver_metrics
            .executing_transactions
            .inc();

        spawn_monitored_task!(async move {
            let _guard = permit;
            let res = authority.state.handle_certificate(&certificate).await;
            if let Err(e) = res {
                error!(?digest, "Failed to execute certified transaction! {e}");
            }

            // Remove the pending certificate regardless of execution status. It can be retried
            // from a higher level.
            let _ = authority
                .state
                .database
                .cleanup_pending_certificate(certificate.epoch(), &digest);

            authority
                .execution_driver_metrics
                .executed_transactions
                .inc();
            authority
                .execution_driver_metrics
                .executing_transactions
                .dec();
        });
    }
}
