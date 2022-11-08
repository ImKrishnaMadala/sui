// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::primary::PayloadToken;
use arc_swap::{ArcSwap, Guard};
use config::{Committee, Epoch, SharedCommittee, SharedWorkerCache, WorkerId};
use consensus::dag::Dag;
use crypto::PublicKey;
use fastcrypto::hash::Hash as _;
use network::{anemo_ext::NetworkExt, P2pNetwork, ReliableNetwork, RetryConfig};
use std::{
    cmp::Ordering,
    collections::HashMap,
    f32::consts::E,
    sync::{Arc, RwLock},
};
use storage::CertificateStore;
use store::Store;
use tokio::sync::Mutex;
use tracing::{debug, trace};
use types::{
    error::{DagError, DagResult},
    metered_channel::Sender,
    BatchDigest, Certificate, CertificateDigest, Header, PrimaryToPrimaryClient,
    PrimaryToWorkerClient, WorkerSynchronizeMessage,
};

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

/// The `Synchronizer` provides functions for retrieving missing certificates and batches.
#[derive(Clone)]
pub struct Synchronizer {
    /// The public key of this primary.
    name: PublicKey,
    // The committee information.
    committee: SharedCommittee,
    /// The worker information cache.
    worker_cache: SharedWorkerCache,
    /// The persistent storage.
    certificate_store: CertificateStore,
    payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,
    /// Send commands to the `CertificateWaiter`.
    tx_certificate_waiter: Sender<Certificate>,
    /// The genesis and its digests.
    genesis: Arc<ArcSwap<(Epoch, Vec<(CertificateDigest, Certificate)>)>>,
    /// The dag used for the external consensus
    dag: Option<Arc<Dag>>,
}

impl Synchronizer {
    pub fn new(
        name: PublicKey,
        committee: SharedCommittee,
        worker_cache: SharedWorkerCache,
        certificate_store: CertificateStore,
        payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,
        tx_certificate_waiter: Sender<Certificate>,
        dag: Option<Arc<Dag>>,
    ) -> Self {
        let genesis = Self::make_genesis(&committee.load());
        Self {
            name,
            committee,
            worker_cache,
            certificate_store,
            payload_store,
            tx_certificate_waiter,
            genesis: Arc::new(ArcSwap::from_pointee(genesis)),
            dag,
        }
    }

    fn make_genesis(committee: &Committee) -> (Epoch, Vec<(CertificateDigest, Certificate)>) {
        (
            committee.epoch(),
            Certificate::genesis(committee)
                .into_iter()
                .map(|x| (x.digest(), x))
                .collect(),
        )
    }

    /// Returns genesis certificates for the given Epoch, or returns error if
    /// the Epoch is not current.
    fn genesis_for_epoch(
        &self,
        epoch: Epoch,
    ) -> DagResult<Guard<Arc<(Epoch, Vec<(CertificateDigest, Certificate)>)>>> {
        let genesis_guard = self.genesis.load();
        match genesis_guard.0.cmp(&epoch) {
            Ordering::Less => {
                // Attempt to update cached genesis certs.
                let committee = self.committee.load();
                if committee.epoch() != epoch {
                    debug!(
                        "synchronizer unable to load a new enough committee: needed {epoch} but got {}",
                        committee.epoch()
                    );
                    return Err(DagError::InvalidEpoch {
                        expected: committee.epoch(),
                        received: epoch,
                    });
                }
                self.genesis.store(Arc::new(Self::make_genesis(&committee)));
                return self.genesis_for_epoch(epoch);
            }
            Ordering::Equal => return Ok(genesis_guard),
            Ordering::Greater => {
                return Err(DagError::InvalidEpoch {
                    expected: genesis_guard.0,
                    received: epoch,
                })
            }
        }
    }

    /// Synchronizes batches in the given header with other nodes (through our workers).
    /// Blocks until synchronization is complete.
    pub async fn sync_batches(&self, header: &Header, network: anemo::Network) -> DagResult<()> {
        if header.author == self.name {
            debug!("skipping sync_batches for header {header}: no need to store payload of our own workers");
            return Ok(());
        }

        let mut missing = HashMap::new();
        for (digest, worker_id) in header.payload.iter() {
            // Check whether we have the batch. If one of our worker has the batch, the primary stores the pair
            // (digest, worker_id) in its own storage. It is important to verify that we received the batch
            // from the correct worker id to prevent the following attack:
            //      1. A Bad node sends a batch X to 2f good nodes through their worker #0.
            //      2. The bad node proposes a malformed block containing the batch X and claiming it comes
            //         from worker #1.
            //      3. The 2f good nodes do not need to sync and thus don't notice that the header is malformed.
            //         The bad node together with the 2f good nodes thus certify a block containing the batch X.
            //      4. The last good node will never be able to sync as it will keep sending its sync requests
            //         to workers #1 (rather than workers #0). Also, clients will never be able to retrieve batch
            //         X as they will be querying worker #1.
            if self
                .payload_store
                .read((*digest, *worker_id))
                .await?
                .is_none()
            {
                missing
                    .entry(*worker_id)
                    .or_insert_with(Vec::new)
                    .push(*digest);
            }
        }

        let mut synchronize_handles = Vec::new();
        for (worker_id, digests) in missing {
            let worker_name = self
                .worker_cache
                .load()
                .worker(&self.name, &worker_id)
                .expect("Author of valid header is not in the worker cache")
                .name;

            let network = network.clone();
            let retry_config = RetryConfig {
                retrying_max_elapsed_time: None, // Retry forever.
                ..Default::default()
            };
            let handle = retry_config.retry(move || {
                let network = network.clone();
                let digests = digests.clone();
                let message = WorkerSynchronizeMessage {
                    digests: digests.clone(),
                    target: header.author.clone(),
                };
                let peer = network.waiting_peer(anemo::PeerId(worker_name.0.to_bytes()));
                let mut client = PrimaryToWorkerClient::new(peer);
                async move {
                    let result = client.synchronize(message).await.map_err(|e| {
                        backoff::Error::transient(DagError::NetworkError(format!("{e:?}")))
                    });
                    if result.is_ok() {
                        for digest in digests.clone() {
                            self.payload_store
                                .async_write((digest, worker_id), 0u8)
                                .await;
                        }
                    }
                    result
                }
            });
            synchronize_handles.push(handle);
        }

        // TODO-DNS: handle cancellation in case of round advancing past gc threshold here.
        futures::future::try_join_all(synchronize_handles)
            .await
            .map(|_| ())
            .map_err(|e| DagError::NetworkError(format!("error synchronizing batches: {e:?}")))
    }

    /// Returns the parent certificates of the given header, and a list of digests for any
    /// that are missing.
    pub fn get_parents(
        &self,
        header: &Header,
    ) -> DagResult<(Vec<Certificate>, Vec<CertificateDigest>)> {
        let genesis = self.genesis_for_epoch(header.epoch)?;
        let mut missing = Vec::new();
        let mut parents = Vec::new();
        for digest in &header.parents {
            if let Some(genesis) = genesis.1.iter().find(|(x, _)| x == digest).map(|(_, x)| x) {
                parents.push(genesis.clone());
                continue;
            }

            match self.certificate_store.read(*digest)? {
                Some(certificate) => parents.push(certificate),
                None => missing.push(*digest),
            };
        }

        Ok((parents, missing))
    }

    /// Checks whether we have seen all the ancestors of the certificate. If we don't, send the
    /// certificate to the `CertificateWaiter` which will trigger range fetching of missing
    /// certificates.
    pub async fn check_parents(&self, certificate: &Certificate) -> DagResult<bool> {
        let genesis = self.genesis_for_epoch(certificate.epoch())?;
        for digest in &certificate.header.parents {
            if genesis.1.iter().any(|(x, _)| x == digest) {
                continue;
            }

            if !self.has_processed_certificate(*digest).await? {
                self.tx_certificate_waiter
                    .send(certificate.clone())
                    .await
                    .expect("Failed to send sync certificate request");
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// This method answers to the question of whether the certificate with the
    /// provided digest has ever been successfully processed (seen) by this
    /// node. Depending on the mode of running the node (internal Vs external
    /// consensus) either the dag will be used to confirm that or the
    /// certificate_store.
    async fn has_processed_certificate(&self, digest: CertificateDigest) -> DagResult<bool> {
        if let Some(dag) = &self.dag {
            return Ok(dag.has_ever_contained(digest).await);
        }
        Ok(self.certificate_store.read(digest)?.is_some())
    }
}
