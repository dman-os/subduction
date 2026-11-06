//! Keyhive sync protocol handler.
//!
//! This module implements the keyhive synchronization protocol, which enables
//! peers to reconcile their keyhive operations (delegations, revocations,
//! prekey operations, CGKA operations).
//!
//! ## Full sync exchange
//!
//! 1. **Sync Request**: The initiator sends hashes of operations accessible to
//!    both peers, plus any pending operation hashes.
//! 2. **Sync Response**: The responder computes set differences and sends back
//!    operations the initiator is missing, along with hashes it wants from the
//!    initiator. Includes metadata totals for both sides.
//! 3. **Sync Ops**: The initiator sends the requested operations (if any).
//! 4. **Sync Confirmation**: Whichever side finishes last sends a confirmation
//!    with its total, establishing a syncpoint for future lightweight checks.
//!
//! ## Lightweight sync check
//!
//! When we have an established syncpoint for a peer, we can send
//! a **Sync Check** instead of a full request. The check carries the sender's
//! total and its syncpoint for the target. If both sides' totals match their
//! respective syncpoints, no full sync is needed. Otherwise the protocol falls
//! back to a full sync request.
//!
//! ## Contact card exchange
//!
//! When peers don't yet know each other's identity, the protocol handles
//! requesting and sending contact cards before initiating sync.

use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    string::ToString,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};

use async_lock::Mutex;
use dupe::Dupe;
use keyhive_core::{
    contact_card::ContactCard,
    event::{Event, static_event::StaticEvent},
    keyhive::Keyhive,
    listener::membership::MembershipListener,
    principal::{
        agent::Agent,
        group::membership_operation::MembershipOperation,
        identifier::Identifier,
        individual::op::{AllReachablePrekeyOps, KeyOp},
        public::Public,
    },
    store::ciphertext::{CiphertextStore, CiphertextStoreExt},
};
use keyhive_crypto::{
    content::reference::ContentRef, digest::Digest, signed::Signed,
    signer::async_signer::AsyncSigner,
};
use std::collections::{HashMap, HashSet};

use crate::{
    cache::{PeerPairProjection, PeriodicEventCache},
    collections::{Map, Set},
    connection::KeyhiveConnection,
    error::{ProtocolError, SigningError, StorageError, VerificationError},
    message::{AgentHashMap, EventHash, Message, RequestId},
    peer_id::KeyhivePeerId,
    signed_message::SignedMessage,
    storage::{KeyhiveStorage, StorageHash},
    storage_ops,
    storage_ops::{bincode_deserialize, bincode_serialize},
    syncpoints::SyncpointMap,
};

/// `SyncStatus` indicating whether a protocol exchange has fully completed (`Done`)
/// or is still pending further messages (Pending).
///
/// `Done` means the local protocol instance has completed its part of the
/// exchange and established the relevant syncpoint for the peer. Callers can
/// use this to observe completed sync rounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Sync is not yet complete --- more messages expected.
    Pending,
    /// Sync exchange is done and identifies the exchange that completed.
    Done {
        /// The exchange that reached its terminal state.
        request_id: RequestId,
        /// Whether this side ingested new operations during the exchange.
        changed: bool,
    },
}

/// Shared keyhive instance.
type SharedKeyhive<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng> =
    Arc<Keyhive<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>>;

/// XOR a set of 32-byte op hashes into a single 32-byte digest.
///
/// An empty set yields all zeros, matching a peer that has not yet sent a
/// digest.
fn pair_set_digest<'a>(hashes: impl IntoIterator<Item = &'a EventHash>) -> EventHash {
    let mut out = [0u8; 32];
    for h in hashes {
        for (o, c) in out.iter_mut().zip(h.iter()) {
            *o ^= *c;
        }
    }
    out
}
struct OutboundRequest {
    peer: KeyhivePeerId,
    advertised_events: Arc<AgentHashMap>,
}

/// Keyhive sync protocol handler.
///
/// Manages peer connections and implements the keyhive sync protocol for
/// reconciling operations between peers. All keyhive access goes through a
/// shared `Arc<Keyhive>`.
/// A batch of changed event hashes to classify against the connected peer set.
///
/// `connected` is the set of peers that can receive a notification; `changed`
/// is the set of event hashes that were newly incorporated (or are pending).
#[derive(Debug)]
pub struct VisibilityBatch<'a> {
    /// Peers that can receive a notification (the dispatcher's active
    /// subscription set).
    pub connected: &'a BTreeSet<KeyhivePeerId>,
    /// Event hashes that were newly incorporated (or are pending).
    pub changed: &'a BTreeSet<EventHash>,
}

/// The result of classifying a [`VisibilityBatch`] against a published cache
/// snapshot.
#[derive(Debug)]
pub struct VisibilityTargets {
    /// The cache generation the classification was performed against. Callers
    /// pin this generation through their debounce window; a later revocation
    /// does not require mutating the pending batch because the eventual sync
    /// applies current authorization state.
    pub published_generation: u64,
    /// Connected peers that can observe at least one changed event.
    pub peers: BTreeSet<KeyhivePeerId>,
    /// Changed hashes absent from the visible projection — pending (awaiting
    /// dependencies) or lagged. Callers must treat these conservatively
    /// (notify all connected peers except the known source) rather than
    /// silently dropping them.
    pub unclassified: BTreeSet<EventHash>,
}
/// WAL events that lack an admission entry, paired with the serialized
/// event bytes and the original source attribution.
pub type UnadmittedWalEvents = Vec<(EventHash, Vec<u8>, Option<KeyhivePeerId>)>;

/// Durable post-ingestion incorporation hook.
///
/// The sink is awaited before the protocol acknowledges the exchange, so the
/// caller can durably record the projection boundary without coupling this
/// crate to a particular async runtime.
///
/// [`Self::unadmitted_wal_events`] closes the persistence-to-admission crash
/// window at boot: an event that was persisted into the raw WAL and applied to
/// the projection but whose admission had not committed at crash time replays
/// from the WAL on restart yet was never admitted. Implementations answer with
/// ONE set-diff query over their own tables (WAL rows lacking an admission
/// entry); the common boot returns an empty vector and the protocol then skips
/// all recovery work. Each candidate includes its serialized event bytes so the
/// protocol can probe only that event in the projection. Compaction may only
/// delete WAL rows whose admission already completed, so archive-only state
/// never appears here and original source attribution survives in the WAL row.
pub trait DurableIncorporationSink<Async: future_form::FutureForm>: Send + Sync {
    /// Durably record that these hashes were incorporated into the local
    /// projection. Idempotent per event hash.
    fn admit(
        self: Arc<Self>,
        hashes: Vec<EventHash>,
        source: Option<KeyhivePeerId>,
    ) -> <Async as future_form::FutureForm>::Future<'static, Result<(), StorageError>>;

    /// Return WAL events that have no admission entry, with their original
    /// source attribution. Must use one set-diff query and is typically empty.
    fn unadmitted_wal_events(
        self: Arc<Self>,
    ) -> <Async as future_form::FutureForm>::Future<
        'static,
        Result<UnadmittedWalEvents, StorageError>,
    >;
}

/// The Keyhive sync protocol: cache-busted event exchange, syncpoint
/// tracking, and change reporting to connected consumers.
pub struct KeyhiveProtocol<Signer, CRef, Plaintext, CipherStore, Listener, Rng, Conn, Store, Async>
where
    Signer: AsyncSigner<Async> + Clone,
    CRef: ContentRef,
    Plaintext: for<'de> serde::Deserialize<'de>,
    CipherStore: CiphertextStore<Async, CRef, Plaintext>
        + CiphertextStoreExt<Async, CRef, Plaintext>
        + Clone,
    Listener: MembershipListener<Async, Signer, CRef>,
    Rng: rand::CryptoRng + rand::RngCore,
    Conn: KeyhiveConnection<Async>,
    Store: KeyhiveStorage<Async>,
    Async: future_form::FutureForm,
{
    keyhive: SharedKeyhive<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>,
    storage: Store,
    peer_id: KeyhivePeerId,
    peers: Mutex<Map<KeyhivePeerId, Conn>>,
    contact_card: ContactCard,
    /// Whether to reload and re-ingest the store when events remain pending
    /// after ingestion.
    ///
    /// False by default. Enable it with [`Self::with_storage_recovery`].
    attempt_storage_recovery: bool,
    /// Durable incorporation sink invoked once per sync exchange with the
    /// hashes newly incorporated into the keyhive projection and the peer they
    /// were learned from (`None` for locally created events). Set with
    /// [`Self::with_durable_incorporation_sink`].
    on_durable_incorporation: Option<Arc<dyn DurableIncorporationSink<Async>>>,
    /// Incorporations whose durable hook failed and must be retried even when
    /// raw event storage deduplicates the next arrival. The source is retained
    /// so retries preserve remote attribution.
    unreported_incorporations: Mutex<BTreeMap<EventHash, Option<KeyhivePeerId>>>,
    /// Events this protocol wrote into the retained event log *while they were
    /// still dependency-pending*. They carry no admission row yet, and they are
    /// not necessarily pending when a later exchange resolves them — that
    /// exchange may have snapshotted its pending set before this event was even
    /// written. Tracking them here keeps the admission independent of which
    /// exchange happens to observe the resolution, so no delivered event can be
    /// left permanently without an admission row.
    unadmitted_inserted: Mutex<BTreeMap<EventHash, Option<KeyhivePeerId>>>,
    /// The durable storage backend serializes writes; admission reconciliation
    /// uses the retained event log and therefore does not need a protocol-wide lock.
    /// The keyhive projection's pending event set as of the last ingestion.
    /// The reporter boundary is "newly admitted to the projection", so the
    /// pending set is tracked to attribute resolutions (previously-pending
    /// events that a later ingestion resolves) to the exchange that resolved
    /// them. `None` until the first ingestion through this protocol.
    pending_hashes: Mutex<Option<BTreeSet<EventHash>>>,
    syncpoints: Mutex<SyncpointMap>,
    cache: Mutex<PeriodicEventCache>,
    /// Serializes on-demand cache rebuilds; concurrent callers join the same rebuild.
    cache_refresh_lock: Mutex<()>,
    /// Keyhive projection generation captured at the last successful cache
    /// refresh. The cache is stale whenever the hive's own generation has
    /// moved past this value — no external change signal required.
    snapshot_state_generation: AtomicU64,
    /// Principal-store counter total observed at the last refresh, for the
    /// two-sample staleness check in `ensure_cache_current`.
    snapshot_nested_generation: AtomicU64,
    next_request_nonce: AtomicU64,
    outbound_requests: Mutex<Map<RequestId, OutboundRequest>>,
    _marker: core::marker::PhantomData<Async>,
}

impl<Signer, CRef, Plaintext, CipherStore, Listener, Rng, Conn, Store, Async> core::fmt::Debug
    for KeyhiveProtocol<Signer, CRef, Plaintext, CipherStore, Listener, Rng, Conn, Store, Async>
where
    Signer: AsyncSigner<Async> + Clone,
    CRef: ContentRef,
    Plaintext: for<'de> serde::Deserialize<'de>,
    CipherStore: CiphertextStore<Async, CRef, Plaintext>
        + CiphertextStoreExt<Async, CRef, Plaintext>
        + Clone,
    Listener: MembershipListener<Async, Signer, CRef>,
    Rng: rand::CryptoRng + rand::RngCore,
    Conn: KeyhiveConnection<Async>,
    Store: KeyhiveStorage<Async>,
    Async: future_form::FutureForm,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyhiveProtocol")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl<Signer, CRef, Plaintext, CipherStore, Listener, Rng, Conn, Store, Async>
    KeyhiveProtocol<Signer, CRef, Plaintext, CipherStore, Listener, Rng, Conn, Store, Async>
where
    Signer: AsyncSigner<Async> + Clone,
    CRef: ContentRef + serde::de::DeserializeOwned,
    Plaintext: for<'de> serde::Deserialize<'de>,
    CipherStore: CiphertextStore<Async, CRef, Plaintext>
        + CiphertextStoreExt<Async, CRef, Plaintext>
        + Clone,
    Listener: MembershipListener<Async, Signer, CRef>,
    Rng: rand::CryptoRng + rand::RngCore,
    Conn: KeyhiveConnection<Async>,
    Conn::SendError: 'static,
    Conn::DisconnectError: 'static,
    Store: KeyhiveStorage<Async>,
    Async: future_form::FutureForm,
{
    /// Create a new protocol handler.
    pub fn new(
        keyhive: SharedKeyhive<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>,
        storage: Store,
        peer_id: KeyhivePeerId,
        contact_card: ContactCard,
    ) -> Self {
        Self {
            keyhive,
            storage,
            peer_id,
            peers: Mutex::new(Map::new()),
            contact_card,
            attempt_storage_recovery: false,
            on_durable_incorporation: None,
            unreported_incorporations: Mutex::new(BTreeMap::new()),
            unadmitted_inserted: Mutex::new(BTreeMap::new()),
            pending_hashes: Mutex::new(None),
            syncpoints: Mutex::new(SyncpointMap::new()),
            cache: Mutex::new(PeriodicEventCache::new()),
            cache_refresh_lock: Mutex::new(()),
            snapshot_state_generation: AtomicU64::new(0),
            snapshot_nested_generation: AtomicU64::new(0),
            next_request_nonce: AtomicU64::new(0),
            outbound_requests: Mutex::new(Map::new()),
            _marker: core::marker::PhantomData,
        }
    }

    /// Enable storage recovery when events remain pending after ingestion.
    #[must_use]
    pub const fn with_storage_recovery(mut self) -> Self {
        self.attempt_storage_recovery = true;
        self
    }

    /// Register the durable post-ingestion incorporation hook.
    ///
    /// The sink is invoked once per sync exchange with hashes newly
    /// incorporated into the keyhive projection. Ingestion does not complete
    /// until [`DurableIncorporationSink::admit`] succeeds.
    #[must_use]
    pub fn with_durable_incorporation_sink(
        mut self,
        sink: Arc<dyn DurableIncorporationSink<Async>>,
    ) -> Self {
        self.on_durable_incorporation = Some(sink);
        self
    }

    fn next_request_id(&self) -> RequestId {
        RequestId {
            requestor: self.peer_id.clone(),
            nonce: self.next_request_nonce.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Register a peer connection.
    pub async fn add_peer(&self, peer_id: KeyhivePeerId, conn: Conn) {
        self.peers.lock().await.insert(peer_id, conn);
    }

    /// Unregister a peer connection, drop its syncpoint, and discard request snapshots.
    pub async fn remove_peer(&self, peer_id: &KeyhivePeerId) {
        self.syncpoints.lock().await.remove(peer_id);
        self.peers.lock().await.remove(peer_id);
        self.outbound_requests
            .lock()
            .await
            .retain(|_, request| &request.peer != peer_id);
    }

    /// Connected peer IDs.
    pub async fn peer_ids(&self) -> Vec<KeyhivePeerId> {
        self.peers.lock().await.keys().cloned().collect()
    }

    /// The local peer's keyhive ID.
    #[must_use]
    pub fn peer_id(&self) -> KeyhivePeerId {
        self.peer_id.clone()
    }

    /// Whether the provided peer is registered.
    pub async fn has_peer(&self, peer_id: &KeyhivePeerId) -> bool {
        self.peers.lock().await.contains_key(peer_id)
    }

    /// Sum of all keyhive op counters.
    pub async fn total_ops(&self) -> u64 {
        let stats = self.keyhive.stats().await;
        stats.delegations
            + stats.revocations
            + stats.prekeys_expanded
            + stats.prekey_rotations
            + stats.cgka_operations
    }

    /// Last confirmed operation total recorded for `peer_id`.
    ///
    /// A value exists after a sync exchange reaches `SyncConfirmation`.
    pub async fn syncpoint_for_peer(&self, peer_id: &KeyhivePeerId) -> Option<u64> {
        self.syncpoints.lock().await.get(peer_id)
    }

    /// Forget the last confirmed syncpoint for `peer_id`.
    ///
    /// This forces the next sync with that peer through the full request path.
    pub async fn clear_syncpoint_for_peer(&self, peer_id: &KeyhivePeerId) {
        self.syncpoints.lock().await.remove(peer_id);
    }

    /// Serialized events reachable by `peer_id`.
    ///
    /// Values are [`Arc`]-shared.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] on serialization failure.
    pub async fn get_events_for_agent(
        &self,
        peer_id: &KeyhivePeerId,
    ) -> Result<Option<AgentHashMap>, ProtocolError<Conn::SendError>> {
        let id = peer_id
            .to_identifier()
            .map_err(ProtocolError::InvalidIdentifier)?;
        let events = {
            let keyhive = Arc::clone(&self.keyhive);
            let Some(agent) = keyhive.get_agent(id).await else {
                return Ok(None);
            };
            sync_events_for_agent(&keyhive, &agent).await
        };

        collect_serialized_events(events).map(Some)
    }

    /// Bulk snapshot of every agent's reachable events, deduplicated.
    ///
    /// Hashes in `skip_serialization` are still recorded in the per-agent
    /// hash sets but their bytes are not serialized (the caller already
    /// has them cached).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] on serialization failure.
    #[allow(clippy::too_many_lines)]
    pub async fn all_agent_events(
        &self,
        skip_serialization: &BTreeSet<EventHash>,
    ) -> Result<crate::all_agent_events::AllAgentEvents, ProtocolError<Conn::SendError>> {
        let keyhive = Arc::clone(&self.keyhive);

        let (all_membership, all_prekey, all_cgka) = {
            let all_membership = keyhive.membership_ops_for_all_agents().await;
            let all_prekey = keyhive.reachable_prekey_ops_for_all_agents().await;
            let all_cgka = keyhive.cgka_ops_for_all_agents().await;
            (all_membership, all_prekey, all_cgka)
        };

        let mut event_data: BTreeMap<EventHash, Arc<[u8]>> = BTreeMap::new();

        // Phase 1: serialize every distinct op once, skipping hashes
        // the caller already has cached.
        let mut membership_source_hashes: BTreeMap<Identifier, Vec<EventHash>> = BTreeMap::new();
        let mut named_delegates_per_source: BTreeMap<Identifier, Vec<(EventHash, Identifier)>> =
            BTreeMap::new();
        for (source_id, source_ops) in &all_membership.ops {
            let mut hashes = Vec::with_capacity(source_ops.len());
            let mut delegates = Vec::new();
            for (digest, op) in source_ops {
                let h = digest_to_bytes(digest);
                hashes.push(h);
                if let MembershipOperation::Delegation(dlg) = op {
                    delegates.push((h, dlg.payload.delegate().id()));
                }
                if !skip_serialization.contains(&h)
                    && let Entry::Vacant(e) = event_data.entry(h)
                {
                    let event: Event<Async, Signer, CRef, Listener> = op.clone().into();
                    let static_event = StaticEvent::from(event);
                    e.insert(serialize_event(&static_event)?);
                }
            }
            membership_source_hashes.insert(*source_id, hashes);
            if !delegates.is_empty() {
                named_delegates_per_source.insert(*source_id, delegates);
            }
        }

        let mut prekey_source_hashes: BTreeMap<Identifier, Vec<EventHash>> = BTreeMap::new();
        for (source_id, key_ops) in &all_prekey.ops {
            let events = key_ops
                .iter()
                .map(|op| -> Event<Async, Signer, CRef, Listener> {
                    Event::from(op.as_ref().clone())
                });
            prekey_source_hashes.insert(
                *source_id,
                hash_and_insert_events(&mut event_data, events, skip_serialization)?,
            );
        }

        let mut cgka_source_hashes: BTreeMap<Identifier, Vec<EventHash>> = BTreeMap::new();
        for (source_id, cgka_ops) in &all_cgka.ops {
            let events = cgka_ops
                .iter()
                .map(|op| -> Event<Async, Signer, CRef, Listener> { Event::from(op.clone()) });
            let hashes = hash_and_insert_events(&mut event_data, events, skip_serialization)?;
            cgka_source_hashes.insert(*source_id, hashes);
        }

        // Phase 2: union of all agent IDs across the three indices.
        let mut all_agent_ids: BTreeSet<Identifier> =
            all_membership.index.keys().copied().collect();
        all_agent_ids.extend(all_prekey.index.keys().copied());
        all_agent_ids.extend(all_cgka.index.keys().copied());

        // Phase 3: roll source-keyed hashes up to per-agent sets, closing each set over the key
        // material its naming events require.
        //
        // A delegation is advertised together with the key material its delegate needs to be
        // pickable (`pickable_individuals`), so a peer never records a counterparty it cannot
        // co-sign with. The bytes stay in `event_data`: this decides what we tell a peer, not what
        // we serve for a hash it already knows from elsewhere.
        //
        // Coverage is attached here and never enforced by withholding: a name is forwarded by
        // nodes that may be unable to back it — a relay that learned a grant without ever
        // holding the grantee's prekeys — and dropping the name at that hop stops membership
        // from crossing it at all, which is the whole point of a relay. What closes the split is
        // the attachment, on the node that does hold the material, together with
        // `KeyOp::topsort` keeping a rotated individual's ops serializable so its holder can
        // pass them on.
        let closure =
            reference_closure(&keyhive, &named_delegates_per_source, &prekey_source_hashes).await;
        let source_delegate_prekeys = closure.attached_per_source;

        let mut agent_hashes: BTreeMap<KeyhivePeerId, BTreeSet<EventHash>> = BTreeMap::new();
        for agent_id in &all_agent_ids {
            let mut hash_set: BTreeSet<EventHash> = BTreeSet::new();
            extend_from_index(
                &mut hash_set,
                &all_membership.index,
                &membership_source_hashes,
                agent_id,
            );
            extend_from_index(
                &mut hash_set,
                &all_prekey.index,
                &prekey_source_hashes,
                agent_id,
            );
            extend_from_index(
                &mut hash_set,
                &all_cgka.index,
                &cgka_source_hashes,
                agent_id,
            );
            if let Some(sources) = all_membership.index.get(agent_id) {
                for source in sources {
                    if let Some(delegate_hashes) = source_delegate_prekeys.get(source) {
                        hash_set.extend(delegate_hashes);
                    }
                }
            }
            let peer = KeyhivePeerId::from_identifier(agent_id);
            agent_hashes.insert(peer, hash_set);
        }

        tracing::debug!(
            keyhive_peer = %self.peer_id,
            named_delegates = closure.named_delegates,
            uncovered_naming_events = closure.uncovered_naming_events,
            uncovered_delegates = ?closure.uncovered_delegates,
            missing_individuals = ?closure.missing_individuals,
            missing_registered_empty = closure.missing_registered_empty,
            missing_unregistered = closure.missing_unregistered,
            exempt_individuals_skipped = closure.exempt_individuals_skipped,
            attached_prekey_hashes = source_delegate_prekeys
                .values()
                .map(BTreeSet::len)
                .sum::<usize>(),
            agents = agent_hashes.len(),
            "INSTR selection reference closure (advertisement)"
        );

        Ok(crate::all_agent_events::AllAgentEvents {
            agent_hashes,
            event_data,
        })
    }

    /// Initiate a keyhive sync with connected peers.
    ///
    /// If `target` is `Some`, only that peer is synced. Otherwise all connected
    /// peers are synced.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if peer ID conversion, message signing, or
    /// sending fails.
    #[tracing::instrument(name = "keyhive_sync", level = "debug", skip_all, fields(target = ?target))]
    pub async fn sync_keyhive(
        &self,
        target: Option<&KeyhivePeerId>,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        let peer_ids = match target {
            Some(t) => vec![t.clone()],
            None => self.peer_ids().await,
        };

        for target_id in &peer_ids {
            if target_id.same_identity(&self.peer_id) {
                continue;
            }
            self.sync_keyhive_for_request(target_id, self.next_request_id())
                .await?;
        }

        Ok(())
    }

    async fn sync_keyhive_for_request(
        &self,
        target_id: &KeyhivePeerId,
        request_id: RequestId,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        self.ensure_cache_current().await?;
        let advertised_events =
            if let Some(cached) = self.cached_events_for_pair_with_peer(target_id).await {
                Some(cached)
            } else {
                match self.get_events_for_peer_pair(target_id).await {
                    Ok(pair) => pair.map(Arc::new),
                    Err(error) => {
                        tracing::warn!(
                            target = %target_id,
                            error = %error,
                            "failed to get hashes for peer pair, skipping"
                        );
                        return Ok(());
                    }
                }
            };
        if let Some(advertised_events) = advertised_events {
            let found: Vec<EventHash> = advertised_events.keys().copied().collect();
            let pending = self.get_pending_hashes().await?;

            let message = Message::SyncRequest {
                sender_id: self.peer_id.clone(),
                target_id: target_id.clone(),
                request_id: request_id.clone(),
                found,
                pending,
            };

            tracing::debug!(
                target = %target_id,
                ?request_id,
                advertised_events = advertised_events.len(),
                "sending sync request"
            );

            self.outbound_requests.lock().await.insert(
                request_id.clone(),
                OutboundRequest {
                    peer: target_id.clone(),
                    advertised_events,
                },
            );
            if let Err(error) = self.sign_and_send(target_id, message, false).await {
                self.outbound_requests.lock().await.remove(&request_id);
                return Err(error);
            }
        } else {
            tracing::debug!(
                target = %target_id,
                ?request_id,
                "requesting contact card"
            );

            let message = Message::RequestContactCard {
                sender_id: self.peer_id.clone(),
                target_id: target_id.clone(),
                request_id,
            };

            self.sign_and_send(target_id, message, true).await?;
        }

        Ok(())
    }

    /// Send a lightweight sync check to a peer.
    ///
    /// This is called instead of [`sync_keyhive`](Self::sync_keyhive)
    /// when there is an established syncpoint for the target. Computes the local
    /// total and sends a [`Message::SyncCheck`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if total computation, signing, or sending fails.
    pub async fn sync_check_keyhive(
        &self,
        target: &KeyhivePeerId,
        our_syncpoint_for_target: u64,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        self.sync_check_keyhive_for_request(
            target,
            our_syncpoint_for_target,
            self.next_request_id(),
        )
        .await
    }

    async fn sync_check_keyhive_for_request(
        &self,
        target: &KeyhivePeerId,
        our_syncpoint_for_target: u64,
        request_id: RequestId,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        self.ensure_cache_current().await?;
        let (our_total, our_digest) = self.compute_total_and_digest_for_peer(target).await?;
        let msg = Message::SyncCheck {
            sender_id: self.peer_id.clone(),
            target_id: target.clone(),
            request_id,
            sender_total: our_total,
            sender_syncpoint: our_syncpoint_for_target,
            sender_digest: our_digest,
        };
        self.sign_and_send(target, msg, false).await
    }

    async fn resolve_sync_check(
        &self,
        peer: &KeyhivePeerId,
        request_id: RequestId,
        sender_total: u64,
        sender_syncpoint: u64,
        sender_digest: EventHash,
        local_syncpoint_for_sender: u64,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        self.ensure_cache_current().await?;
        let (our_total, our_digest) = self.compute_total_and_digest_for_peer(peer).await?;

        let digests_match = sender_digest == our_digest;
        let in_sync = local_syncpoint_for_sender == sender_total
            && sender_syncpoint == our_total
            && digests_match;

        if in_sync {
            tracing::debug!(
                peer = %peer,
                "sync check passed, peers are in sync"
            );
            let confirmation = Message::SyncConfirmation {
                sender_id: self.peer_id.clone(),
                target_id: peer.clone(),
                request_id,
                confirmer_total: our_total,
            };
            self.sign_and_send(peer, confirmation, false).await?;
        } else {
            tracing::debug!(
                peer = %peer,
                our_total,
                sender_total,
                sender_syncpoint,
                local_syncpoint_for_sender,
                digests_match,
                "sync check mismatch, falling back to full sync"
            );
            self.sync_keyhive_for_request(peer, request_id).await?;
        }
        Ok(())
    }

    /// Handle an incoming signed message from a peer.
    ///
    /// Verifies the message signature, optionally ingests a contact card,
    /// and dispatches to the appropriate handler based on message type.
    /// Updates syncpoints internally.
    ///
    /// The optional `conn` is used to auto-register unknown peers when an
    /// authenticated message arrives before any explicit `add_peer` call.
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if signature verification, contact card
    /// ingestion, or message handling fails.
    #[tracing::instrument(name = "keyhive_handle_message", level = "debug", skip_all, fields(peer = %from))]
    pub async fn handle_message(
        &self,
        from: &KeyhivePeerId,
        signed_msg: SignedMessage,
        conn: Option<Conn>,
    ) -> Result<SyncStatus, ProtocolError<Conn::SendError>> {
        let verified = signed_msg.verify(from)?;

        if let Some(contact_card) = &verified.contact_card {
            self.ingest_contact_card(contact_card, Some(from.clone()))
                .await?;
        }
        if !self.has_peer(&verified.sender_id).await
            && let Some(connection) = conn.clone()
        {
            self.add_peer(verified.sender_id.clone(), connection).await;
        }
        self.ensure_cache_current().await?;
        let cached_sender_pair = self.cached_events_for_pair_with_peer(from).await;

        let message: Message = cbor_deserialize(&verified.payload)
            .map_err(|e| VerificationError::Deserialization(e.to_string()))?;

        // Reject messages where the inner sender_id doesn't match the signer.
        if !message.sender_id().same_identity(&verified.sender_id) {
            return Err(VerificationError::SenderMismatch {
                expected: verified.sender_id.clone(),
                actual: message.sender_id().clone(),
            }
            .into());
        }

        let status = match &message {
            Message::SyncRequest { .. } => self
                .handle_sync_request(message, cached_sender_pair.as_deref())
                .await
                .map(|()| SyncStatus::Pending),
            Message::SyncResponse { .. } => {
                self.handle_sync_response(message, cached_sender_pair.as_deref())
                    .await
            }
            Message::SyncOps { .. } => self.handle_sync_ops(message).await,
            Message::RequestContactCard { .. } => self
                .handle_request_contact_card(message)
                .await
                .map(|()| SyncStatus::Pending),
            Message::MissingContactCard { .. } => self
                .handle_missing_contact_card(message)
                .await
                .map(|()| SyncStatus::Pending),
            Message::SyncCheck {
                sender_id,
                request_id,
                sender_total,
                sender_syncpoint,
                sender_digest,
                ..
            } => {
                if !self.has_peer(sender_id).await
                    && let Some(c) = conn
                {
                    self.add_peer(sender_id.clone(), c).await;
                }
                let local_syncpoint_for_sender =
                    self.syncpoints.lock().await.get(sender_id).unwrap_or(0);
                self.resolve_sync_check(
                    sender_id,
                    request_id.clone(),
                    *sender_total,
                    *sender_syncpoint,
                    *sender_digest,
                    local_syncpoint_for_sender,
                )
                .await
                .map(|()| SyncStatus::Pending)
            }
            Message::SyncConfirmation {
                sender_id,
                request_id,
                confirmer_total,
                ..
            } => {
                self.syncpoints
                    .lock()
                    .await
                    .set(sender_id.clone(), *confirmer_total);
                Ok(SyncStatus::Done {
                    request_id: request_id.clone(),
                    changed: false,
                })
            }
        }?;

        Ok(status)
    }

    /// Handle a `SyncRequest`: compute which ops to send and which to request.
    async fn handle_sync_request(
        &self,
        message: Message,
        cached_sender_pair: Option<&AgentHashMap>,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        let _instr_guard = InstrHandlerTimer(stringify!(handle_sync_request), std::time::Instant::now()); // INSTR
        let Message::SyncRequest {
            sender_id,
            request_id,
            found: peer_found,
            pending: peer_pending,
            ..
        } = message
        else {
            return Err(ProtocolError::UnexpectedMessageType {
                expected: "SyncRequest",
                actual: message.variant_name(),
            });
        };

        tracing::debug!(
            from = %sender_id,
            found = peer_found.len(),
            pending = peer_pending.len(),
            "handling sync request"
        );

        let computed;
        let local_events = if let Some(c) = cached_sender_pair {
            c
        } else {
            let Some(c) = self.get_events_for_peer_pair(&sender_id).await? else {
                // We don't know this peer. Request their contact card.
                tracing::debug!(from = %sender_id, "no agent found, requesting contact card");
                let msg = Message::RequestContactCard {
                    sender_id: self.peer_id.clone(),
                    target_id: sender_id.clone(),
                    request_id,
                };
                self.sign_and_send(&sender_id, msg, true).await?;
                return Ok(());
            };
            computed = c;
            &computed
        };

        let our_pending_hashes = self.get_pending_hashes().await?;

        // Compute totals from the original collections before building sets.
        let sync_responder_total = (local_events.len() + our_pending_hashes.len()) as u64;
        let sync_requester_total = (peer_found.len() + peer_pending.len()) as u64;

        // Build sets for comparison.
        let peer_found_set: Set<EventHash> = peer_found.iter().copied().collect();
        let peer_pending_set: Set<EventHash> = peer_pending.iter().copied().collect();
        let our_pending_set: Set<EventHash> = our_pending_hashes.iter().copied().collect();

        // Ops to send = local - (peer_found U peer_pending)
        let mut found_ops: Vec<Arc<[u8]>> = Vec::new();
        for (h, event_bytes) in local_events {
            if !peer_found_set.contains(h) && !peer_pending_set.contains(h) {
                found_ops.push(event_bytes.dupe());
            }
        }

        // Ops to request = peer_found - (local U our_pending)
        let requested: Vec<EventHash> = peer_found
            .into_iter()
            .filter(|h| !local_events.contains_key(h) && !our_pending_set.contains(h))
            .collect();
        // TEMPORARY instrumentation
        Self::log_sync_response_plan(
            &self.peer_id(),
            &sender_id,
            &request_id,
            &found_ops,
            &requested,
            our_pending_hashes.len(),
        );
        tracing::debug!(
            from = %sender_id,
            ?request_id,
            sending = found_ops.len(),
            requesting = requested.len(),
            sync_responder_total,
            sync_requester_total,
            "sending sync response"
        );
        let response = Message::SyncResponse {
            sender_id: self.peer_id.clone(),
            target_id: sender_id.clone(),
            request_id,
            requested,
            found: found_ops,
            sync_responder_total,
            sync_requester_total,
        };

        self.sign_and_send(&sender_id, response, false).await?;
        Ok(())
    }

    /// TEMPORARY instrumentation: log a sync response's send/request sets
    /// with per-event kind prefixes, so a divergence between peers is readable
    /// from the logs alone.
    fn log_sync_response_plan(
        local: &KeyhivePeerId,
        sender_id: &KeyhivePeerId,
        request_id: &RequestId,
        found_ops: &[Arc<[u8]>],
        requested: &[EventHash],
        our_pending: usize,
    ) {
        let send_prefixes: Vec<alloc::string::String> = found_ops
            .iter()
            .map(|bytes| {
                let h = crate::storage_ops::hash_event_bytes(bytes).0;
                let kind = match bincode_deserialize::<StaticEvent<Vec<u8>>>(bytes) {
                    Ok(ev) => match &ev {
                        StaticEvent::Delegated(_) => "deleg",
                        StaticEvent::Revoked(_) => "revok",
                        StaticEvent::PrekeysExpanded(_) | StaticEvent::PrekeyRotated(_) => "prek",
                        StaticEvent::CgkaOperation(_) => "cgka",
                    },
                    Err(_) => "unk",
                };
                alloc::format!("{}:{kind}", Self::short_hash(&h))
            })
            .collect();
        let req_prefixes: Vec<alloc::string::String> =
            requested.iter().map(|h| Self::short_hash(h)).collect();
        tracing::warn!(
            local = %local,
            from = %sender_id,
            ?request_id,
            sending = found_ops.len(),
            ?send_prefixes,
            requesting = requested.len(),
            ?req_prefixes,
            our_pending,
            "INSTR sync response"
        );
    }

    /// Handle a `SyncResponse`: ingest events we received and send any
    /// requested ops back.
    ///
    /// If ops are sent back, the other side will confirm in `handle_sync_ops`.
    /// If no ops are sent, we send a confirmation and establish a syncpoint.
    #[allow(clippy::too_many_lines)]
    async fn handle_sync_response(
        &self,
        message: Message,
        _cached_sender_pair: Option<&AgentHashMap>,
    ) -> Result<SyncStatus, ProtocolError<Conn::SendError>> {
        let _instr_guard = InstrHandlerTimer(stringify!(handle_sync_response), std::time::Instant::now()); // INSTR
        let Message::SyncResponse {
            sender_id,
            request_id,
            requested: requested_hashes,
            found: found_events,
            sync_responder_total,
            sync_requester_total,
            ..
        } = message
        else {
            return Err(ProtocolError::UnexpectedMessageType {
                expected: "SyncResponse",
                actual: message.variant_name(),
            });
        };

        tracing::debug!(
            from = %sender_id,
            ?request_id,
            received = found_events.len(),
            requested = requested_hashes.len(),
            sync_responder_total,
            sync_requester_total,
            "handling sync response"
        );

        let outbound_request = self.outbound_requests.lock().await.remove(&request_id);
        if let Some(request) = &outbound_request {
            if request.peer != sender_id {
                return Err(ProtocolError::ProtocolInvariant(format!(
                    "request {request_id:?} expected peer {}, got {sender_id}",
                    request.peer
                )));
            }
        } else {
            tracing::debug!(
                from = %sender_id,
                ?request_id,
                "ignoring untracked SyncResponse as an unsolicited duplicate",
            );
            return Ok(SyncStatus::Done {
                request_id,
                changed: false,
            });
        }

        // TEMPORARY instrumentation: incoming response hashes + kinds
        let instr_received: Vec<alloc::string::String> = found_events
            .iter()
            .map(|bytes| {
                let h = crate::storage_ops::hash_event_bytes(bytes.as_ref()).0;
                let kind = match bincode_deserialize::<StaticEvent<Vec<u8>>>(bytes.as_ref()) {
                    Ok(ev) => match &ev {
                        StaticEvent::Delegated(_) => "deleg",
                        StaticEvent::Revoked(_) => "revok",
                        StaticEvent::PrekeysExpanded(_) | StaticEvent::PrekeyRotated(_) => "prek",
                        StaticEvent::CgkaOperation(_) => "cgka",
                    },
                    Err(_) => "unk",
                };
                alloc::format!("{}:{kind}", Self::short_hash(&h))
            })
            .collect();
        let advanced = if found_events.is_empty() {
            false
        } else {
            self.ingest_events(&found_events, Some(sender_id.clone()))
                .await?
        };
        // TEMPORARY instrumentation
        {
            let pending_after: Vec<alloc::string::String> = self
                .get_pending_hashes()
                .await?
                .iter()
                .map(|h| Self::short_hash(h))
                .collect();
            tracing::warn!(
                local = %self.peer_id(),
                from = %sender_id,
                received = ?instr_received,
                pending_total = pending_after.len(),
                ?pending_after,
                advanced,
                "INSTR sync resp ingested"
            );
        }
        // Serve requested operations from the immutable pair snapshot whose
        // hashes this request advertised, never from the current cache generation.
        if !requested_hashes.is_empty() {
            let ops = self
                .get_event_bytes_for_requested(
                    &sender_id,
                    &requested_hashes,
                    outbound_request
                        .as_ref()
                        .map(|request| request.advertised_events.as_ref()),
                )
                .await?;

            if ops.len() != requested_hashes.len() {
                return Err(ProtocolError::ProtocolInvariant(format!(
                    "peer requested {} operations from {request_id:?}, but its advertised snapshot contained {}",
                    requested_hashes.len(),
                    ops.len()
                )));
            }

            tracing::debug!(
                to = %sender_id,
                count = ops.len(),
                ?request_id,
                "sending requested ops"
            );

            let msg = Message::SyncOps {
                sender_id: self.peer_id.clone(),
                target_id: sender_id.clone(),
                request_id: request_id.clone(),
                ops,
                sync_responder_total,
                sync_requester_total,
            };

            self.sign_and_send(&sender_id, msg, false).await?;
            // The other side will send a confirmation after ingesting.
            if advanced {
                self.syncpoints.lock().await.invalidate_all();
            }
            return Ok(SyncStatus::Pending);
        }

        // No ops to send back. Send confirmation and establish syncpoint.
        // Our total is sync_requester_total (we are the requester).
        let confirmation = Message::SyncConfirmation {
            sender_id: self.peer_id.clone(),
            target_id: sender_id.clone(),
            request_id: request_id.clone(),
            confirmer_total: sync_requester_total,
        };
        self.sign_and_send(&sender_id, confirmation, false).await?;

        {
            let mut map = self.syncpoints.lock().await;
            if advanced {
                map.invalidate_all();
            }
            map.set(sender_id, sync_responder_total);
        }

        Ok(SyncStatus::Done {
            request_id,
            changed: advanced,
        })
    }

    /// Handle `SyncOps`: ingest received operations and send confirmation.
    async fn handle_sync_ops(
        &self,
        message: Message,
    ) -> Result<SyncStatus, ProtocolError<Conn::SendError>> {
        let _instr_guard = InstrHandlerTimer(stringify!(handle_sync_ops), std::time::Instant::now()); // INSTR
        let Message::SyncOps {
            sender_id,
            request_id,
            ops,
            sync_responder_total,
            sync_requester_total,
            ..
        } = message
        else {
            return Err(ProtocolError::UnexpectedMessageType {
                expected: "SyncOps",
                actual: message.variant_name(),
            });
        };

        // TEMPORARY instrumentation
        let instr_incoming: Vec<alloc::string::String> = ops
            .iter()
            .map(|bytes| {
                let h = crate::storage_ops::hash_event_bytes(bytes.as_ref()).0;
                let kind = match bincode_deserialize::<StaticEvent<Vec<u8>>>(bytes.as_ref()) {
                    Ok(ev) => match &ev {
                        StaticEvent::Delegated(_) => "deleg",
                        StaticEvent::Revoked(_) => "revok",
                        StaticEvent::PrekeysExpanded(_) | StaticEvent::PrekeyRotated(_) => "prek",
                        StaticEvent::CgkaOperation(_) => "cgka",
                    },
                    Err(_) => "unk",
                };
                alloc::format!("{}:{kind}", Self::short_hash(&h))
            })
            .collect();
        tracing::debug!(
            from = %sender_id,
            count = ops.len(),
            "handling sync ops"
        );
        let advanced = if ops.is_empty() {
            false
        } else {
            self.ingest_events(&ops, Some(sender_id.clone())).await?
        };
        // TEMPORARY instrumentation
        {
            let pending_after: Vec<alloc::string::String> = self
                .get_pending_hashes()
                .await?
                .iter()
                .map(|h| Self::short_hash(h))
                .collect();
            tracing::warn!(
                local = %self.peer_id(),
                from = %sender_id,
                incoming = ?instr_incoming,
                pending_total = pending_after.len(),
                ?pending_after,
                advanced,
                "INSTR sync ops ingested"
            );
        }
        // Send confirmation after ingesting ops.
        // Our total is sync_responder_total (we are the responder).
        let confirmation = Message::SyncConfirmation {
            sender_id: self.peer_id.clone(),
            target_id: sender_id.clone(),
            request_id: request_id.clone(),
            confirmer_total: sync_responder_total,
        };
        self.sign_and_send(&sender_id, confirmation, false).await?;

        {
            let mut map = self.syncpoints.lock().await;
            if advanced {
                map.invalidate_all();
            }
            map.set(sender_id, sync_requester_total);
        }

        Ok(SyncStatus::Done {
            request_id,
            changed: advanced,
        })
    }

    /// Handle `RequestContactCard`: send our contact card to the requesting
    /// peer.
    async fn handle_request_contact_card(
        &self,
        message: Message,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        let Message::RequestContactCard {
            sender_id,
            request_id,
            ..
        } = message
        else {
            return Err(ProtocolError::UnexpectedMessageType {
                expected: "RequestContactCard",
                actual: message.variant_name(),
            });
        };

        tracing::debug!(
            from = %sender_id,
            "sending missing contact card"
        );

        let msg = Message::MissingContactCard {
            sender_id: self.peer_id.clone(),
            target_id: sender_id.clone(),
            request_id,
        };

        self.sign_and_send(&sender_id, msg, true).await?;
        Ok(())
    }

    /// Handle `MissingContactCard`: the contact card was already ingested in
    /// `handle_message`, so now we trigger a sync with the peer.
    async fn handle_missing_contact_card(
        &self,
        message: Message,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        let Message::MissingContactCard {
            sender_id,
            request_id,
            ..
        } = message
        else {
            return Err(ProtocolError::UnexpectedMessageType {
                expected: "MissingContactCard",
                actual: message.variant_name(),
            });
        };

        tracing::debug!(
            from = %sender_id,
            "received contact card, initiating sync"
        );

        self.sync_keyhive_for_request(&sender_id, request_id)
            .await?;
        Ok(())
    }

    /// CBOR-serialize a message, sign it, and wrap it as a [`SignedMessage`].
    pub(crate) async fn build_signed_message(
        &self,
        message: Message,
        include_contact_card: bool,
    ) -> Result<SignedMessage, ProtocolError<Conn::SendError>> {
        let msg_bytes =
            cbor_serialize(&message).map_err(|e| SigningError::Serialization(e.to_string()))?;

        let signed: Signed<Vec<u8>> = {
            let keyhive = Arc::clone(&self.keyhive);
            keyhive
                .try_sign(msg_bytes)
                .await
                .map_err(SigningError::SigningFailed)?
        };

        // Wire format: bincode `Signed<Vec<u8>>` (matches `Signed.toBytes()`
        // from keyhive-wasm; see `keyhive_wasm/src/js/signed.rs`).
        let signed_bytes =
            bincode::serialize(&signed).map_err(|e| SigningError::Serialization(e.to_string()))?;

        Ok(if include_contact_card {
            SignedMessage::with_contact_card(signed_bytes, self.contact_card.clone())
        } else {
            SignedMessage::new(signed_bytes)
        })
    }

    /// Sign a message and send it to a peer.
    async fn sign_and_send(
        &self,
        target_peer_id: &KeyhivePeerId,
        message: Message,
        include_contact_card: bool,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        let signed_message = self
            .build_signed_message(message, include_contact_card)
            .await?;

        let conn = {
            let peers = self.peers.lock().await;
            peers
                .get(target_peer_id)
                .cloned()
                .ok_or_else(|| ProtocolError::UnknownPeer(target_peer_id.clone()))?
        };

        conn.send(signed_message).await.map_err(ProtocolError::Send)
    }

    /// Get the intersection of event hashes accessible to both us and a peer.
    ///
    /// Returns `None` if the peer is unknown (no agent found in keyhive).
    async fn get_events_for_peer_pair(
        &self,
        peer_id: &KeyhivePeerId,
    ) -> Result<Option<AgentHashMap>, ProtocolError<Conn::SendError>> {
        let our_id = self
            .peer_id
            .to_identifier()
            .map_err(ProtocolError::InvalidIdentifier)?;
        let their_id = peer_id
            .to_identifier()
            .map_err(ProtocolError::InvalidIdentifier)?;

        let (our_events, their_events, public_events) = {
            let keyhive = Arc::clone(&self.keyhive);

            let our_agent = keyhive.get_agent(our_id).await;
            let their_agent = keyhive.get_agent(their_id).await;

            match (our_agent, their_agent) {
                (Some(ref our_agent), Some(ref their_agent)) => {
                    let our_events = sync_events_for_agent(&keyhive, our_agent).await;
                    let their_events = sync_events_for_agent(&keyhive, their_agent).await;
                    let public_events: Map<Digest<StaticEvent<CRef>>, StaticEvent<CRef>> =
                        if let Some(ref public_agent) = keyhive.get_agent(Public.id()).await {
                            sync_events_for_agent(&keyhive, public_agent).await
                        } else {
                            Map::new()
                        };
                    (our_events, their_events, public_events)
                }
                _ => return Ok(None),
            }
        };

        let mut result = AgentHashMap::new();
        // INSTR selection composition: prekey ops are advertised only through
        // `reachable_prekey_ops_for_agent`, and whether they are selected is decided independently
        // of the delegations that name the same individuals (which reach the peer through their
        // own subject-root reachability). If delegations are selected while prekey ops are not, the
        // receiver records membership for an agent it cannot co-sign with — a state with no causal
        // parent, so nothing else in keyhive notices it.
        {
            let mut sent_prekeys = 0usize;
            let mut sent_delegations = 0usize;
            let mut local_prekeys = 0usize;
            let mut peer_prekeys = 0usize;
            for event in our_events.values() {
                if matches!(
                    event,
                    StaticEvent::PrekeysExpanded(_) | StaticEvent::PrekeyRotated(_)
                ) {
                    local_prekeys += 1;
                }
            }
            for event in their_events.values() {
                if matches!(
                    event,
                    StaticEvent::PrekeysExpanded(_) | StaticEvent::PrekeyRotated(_)
                ) {
                    peer_prekeys += 1;
                }
            }
            for (digest, event) in &our_events {
                if !their_events.contains_key(digest) {
                    continue;
                }
                if matches!(
                    event,
                    StaticEvent::PrekeysExpanded(_) | StaticEvent::PrekeyRotated(_)
                ) {
                    sent_prekeys += 1;
                } else if matches!(event, StaticEvent::Delegated(_)) {
                    sent_delegations += 1;
                }
            }
            tracing::warn!(
                sent_prekeys,
                sent_delegations,
                local_prekeys,
                peer_prekeys,
                public = public_events.len(),
                "INSTR selection composition"
            );
        }

        for (digest, event) in public_events {
            let h = digest_to_bytes(&digest);
            let pair = serialize_event(&event)?;
            result.insert(h, pair);
        }

        // Reference closure: an event that names an agent travels with that agent's key ops (see
        // `close_references`).
        self.close_references(&mut result, &our_events, &their_events)
            .await?;

        Ok(Some(result))
    }

    /// Close a selection over the key material its naming events require.
    ///
    /// An event that names an agent travels with that agent's key ops. The intersection that
    /// selected the event computes reachability on the event's subject, while the agent's key ops
    /// are reached through the container walk, so the two can be split; attaching the material here
    /// closes that split, and reveals nothing extra, since the naming event already tells the peer
    /// that the agent exists.
    ///
    /// Nothing is withheld: an intermediate node legitimately holds a name whose material it does
    /// not have (the grant's author had the delegate's prekeys; a relay may have only learned the
    /// grant), and dropping the name there would stop membership crossing that hop. See
    /// `all_agent_events` for the same rule on the path that runs in practice.
    async fn close_references(
        &self,
        result: &mut AgentHashMap,
        our_events: &Map<Digest<StaticEvent<CRef>>, StaticEvent<CRef>>,
        their_events: &Map<Digest<StaticEvent<CRef>>, StaticEvent<CRef>>,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        let named = named_agents(
            our_events
                .iter()
                .filter(|(digest, _)| their_events.contains_key(digest))
                .map(|(_, event)| event),
        );
        let keyhive = Arc::clone(&self.keyhive);
        // One reachability pass for the whole exchange: deciding per named agent would re-walk every
        // group's and document's transitive members once per delegation.
        let reachable = keyhive.reachable_prekey_ops_for_all_agents().await;
        let mut attachments: Vec<(Digest<StaticEvent<CRef>>, StaticEvent<CRef>)> = Vec::new();
        for &agent in &named {
            attachments.extend(prekey_closure_for_agent(keyhive.as_ref(), &reachable, agent).await);
        }
        let attached_count = attachments.len();

        for (digest, event) in our_events {
            if !their_events.contains_key(digest) {
                continue;
            }
            let h = digest_to_bytes(digest);
            if let Entry::Vacant(entry) = result.entry(h) {
                entry.insert(serialize_event(event)?);
            }
        }

        for (digest, event) in attachments {
            let h = digest_to_bytes(&digest);
            if let Entry::Vacant(entry) = result.entry(h) {
                entry.insert(serialize_event(&event)?);
            }
        }

        tracing::warn!(
            named_agents = ?named,
            attached_prekey_events = attached_count,
            "INSTR selection reference closure"
        );

        Ok(())
    }

    /// Get pending event hashes as `Vec<EventHash>`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if the keyhive lock or hash computation fails.
    pub async fn get_pending_hashes(
        &self,
    ) -> Result<Vec<EventHash>, ProtocolError<Conn::SendError>> {
        let digests = self.keyhive.pending_event_hashes().await;
        Ok(digests.into_iter().map(|d| digest_to_bytes(&d)).collect())
    }

    /// Fetch serialized event bytes for the given hashes.
    async fn get_event_bytes_for_requested(
        &self,
        sender_id: &KeyhivePeerId,
        requested: &[EventHash],
        cached_pair: Option<&AgentHashMap>,
    ) -> Result<Vec<Arc<[u8]>>, ProtocolError<Conn::SendError>> {
        let computed;
        let pair = if let Some(c) = cached_pair {
            c
        } else {
            let Some(c) = self.get_events_for_peer_pair(sender_id).await? else {
                return Ok(Vec::new());
            };
            computed = c;
            &computed
        };

        let mut result = Vec::with_capacity(requested.len().min(pair.len()));
        for h in requested {
            if let Some(bytes) = pair.get(h) {
                result.push(bytes.dupe());
            }
        }
        Ok(result)
    }

    /// Ingest received event bytes into keyhive and persist them to storage.
    ///
    /// If some events remain pending (missing dependencies), attempts recovery
    /// by loading from storage and retrying.
    /// TEMPORARY instrumentation: count Delegated events in a fresh
    /// all-agent snapshot, plus per-agent set sizes.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if the snapshot cannot be built.
    pub async fn snapshot_probe(
        &self,
        peer: &KeyhivePeerId,
    ) -> Result<(usize, Option<usize>), ProtocolError<Conn::SendError>> {
        let snapshot = self.all_agent_events(&BTreeSet::default()).await?;
        let delegs = snapshot
            .event_data
            .values()
            .filter(|bytes| {
                matches!(
                    bincode_deserialize::<StaticEvent<Vec<u8>>>(bytes),
                    Ok(StaticEvent::Delegated(_))
                )
            })
            .count();
        let peer_set = snapshot
            .agent_hashes
            .iter()
            .find(|(k, _)| *k == peer)
            .map(|(_, v)| v.len());
        Ok((delegs, peer_set))
    }

    /// TEMPORARY instrumentation: hash prefixes of every persisted event.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if the stored events cannot be loaded.
    pub async fn load_event_hash_prefixes(
        &self,
    ) -> Result<Vec<alloc::string::String>, ProtocolError<Conn::SendError>> {
        let mut out = Vec::new();
        let stored = self
            .storage
            .load_events()
            .await
            .map_err(|error| ProtocolError::Storage(StorageError::Load(error.to_string())))?;
        for (hash, bytes) in stored {
            let StorageHash(hb) = hash;
            let mut s = alloc::string::String::new();
            for b in hb.iter().take(4) {
                use core::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
            }
            // Identify by SIGNATURE prefix — identical for the same logical
            // event on every node, independent of storage-hash specifics.
            let ident = match bincode_deserialize::<StaticEvent<Vec<u8>>>(&bytes) {
                Ok(ev) => match &ev {
                    StaticEvent::Delegated(sg) => ("deleg".to_string(), sg.signature().to_bytes()),
                    StaticEvent::Revoked(sg) => ("revok".to_string(), sg.signature().to_bytes()),
                    StaticEvent::PrekeysExpanded(sg) => {
                        ("prekx".to_string(), sg.signature().to_bytes())
                    }
                    StaticEvent::PrekeyRotated(sg) => {
                        ("prekr".to_string(), sg.signature().to_bytes())
                    }
                    StaticEvent::CgkaOperation(sg) => {
                        ("cgka".to_string(), sg.signature().to_bytes())
                    }
                },
                Err(_) => ("unk".to_string(), [0u8; 64]),
            };
            let mut ep = alloc::string::String::new();
            for b in ident.1.iter().take(4) {
                use core::fmt::Write as _;
                let _ = write!(ep, "{b:02x}");
            }
            out.push(alloc::format!("{}={ep}", ident.0));
        }
        out.sort();
        Ok(out)
    }

    /// TEMPORARY instrumentation: short hex prefix of an event-hash for logs.
    fn short_hash(h: &EventHash) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        for b in &h[..4] {
            use core::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    async fn ingest_events<B: AsRef<[u8]>>(
        &self,
        event_bytes_list: &[B],
        source: Option<KeyhivePeerId>,
    ) -> Result<bool, ProtocolError<Conn::SendError>> {
        let mut events: Vec<StaticEvent<CRef>> = Vec::with_capacity(event_bytes_list.len());
        for (idx, item) in event_bytes_list.iter().enumerate() {
            let bytes = item.as_ref();
            match bincode_deserialize::<StaticEvent<CRef>>(bytes) {
                Ok(ev) => events.push(ev),
                Err(e) => {
                    let head_len = core::cmp::min(bytes.len(), 96);
                    let mut head_hex = alloc::string::String::with_capacity(head_len * 2);
                    for b in bytes.get(..head_len).unwrap_or(bytes) {
                        use core::fmt::Write;
                        let _ = write!(head_hex, "{b:02x}");
                    }
                    tracing::warn!(
                        index = idx,
                        total = event_bytes_list.len(),
                        len = bytes.len(),
                        head = %head_hex,
                        error = ?e,
                        "failed to deserialize incoming event"
                    );
                    return Err(ProtocolError::Deserialization(e.to_string()));
                }
            }
        }
        // Capture the projection's pending set before this exchange so the
        // reporter can attribute resolutions to the exchange that resolved
        // them — including boot-time pending events that this exchange's
        // ingestion (or storage recovery) finally resolves.
        let prev_pending: BTreeSet<EventHash> = match self.pending_hashes.lock().await.as_ref() {
            Some(prev) => prev.clone(),
            None => self.pending_event_hashes().await,
        };

        let instr_in = events.len(); // INSTR
        let instr_start = std::time::Instant::now(); // INSTR
        let (pending, mut resolved_pending) = self
            .keyhive
            .ingest_unsorted_static_events_with_pending_progress(events)
            .await;
        let instr_ingest = instr_start.elapsed(); // INSTR
        tracing::warn!(events_in = instr_in, pending_after = pending.len(), ingest = ?instr_ingest, per_event_us = instr_ingest.as_micros() as u64 / (instr_in.max(1) as u64), "INSTR keyhive ingest batch timing"); // INSTR

        if !pending.is_empty() {
            if self.attempt_storage_recovery {
                tracing::warn!(
                    count = pending.len(),
                    "events pending after ingestion, attempting storage recovery"
                );

                match self.try_storage_recovery(event_bytes_list).await {
                    Ok((retry_pending, recovery_progress)) => {
                        resolved_pending |= recovery_progress || retry_pending < pending.len();
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "storage recovery failed"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    count = pending.len(),
                    "events pending after ingestion; storage recovery disabled"
                );
            }
        }

        // Publish events to durable storage only after the in-memory Keyhive
        // projection has ingested them. Consumers use this log as a dirty hint
        // and must never observe an event before its corresponding state.
        // The exchange is not acknowledged until these writes complete, so a
        // crash between ingestion and persistence causes the sender to retry.
        let instr_persist_start = std::time::Instant::now(); // INSTR
        let inserted = self
            .persist_incorporated_event_bytes(event_bytes_list, source, prev_pending)
            .await?;
        tracing::warn!(events_in = instr_in, persist = ?instr_persist_start.elapsed(), total = ?instr_start.elapsed(), "INSTR keyhive persist batch timing"); // INSTR
        Ok(!inserted.is_empty() || resolved_pending)
    }

    /// Persist locally-created events and await the durable incorporation hook.
    ///
    /// Call this immediately after the corresponding Keyhive mutation. Startup
    /// full-projection reconciliation repairs any crash between mutation,
    /// persistence, and durable admission.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if serialization, storage, or the durable
    /// admission hook fails.
    pub async fn persist_local_events(
        &self,
        events: Vec<StaticEvent<CRef>>,
    ) -> Result<Vec<EventHash>, ProtocolError<Conn::SendError>> {
        // Local events are created by mutating the projection outside Keyhive
        // methods (delegations, revocations, CGKA updates), so the structural
        // generation must be marked here — otherwise the next refresh
        // early-exits and serves a cache missing these events.
        self.keyhive.note_direct_mutation();
        self.syncpoints.lock().await.invalidate_all();
        let prev_pending = match self.pending_hashes.lock().await.as_ref() {
            Some(previous) => previous.clone(),
            None => self.pending_event_hashes().await,
        };
        let mut bytes = Vec::with_capacity(events.len());
        for event in events {
            bytes.push(bincode_serialize(&event)?);
        }
        self.persist_incorporated_event_bytes(&bytes, None, prev_pending)
            .await
    }

    /// Single event-WAL/admission chokepoint for local and remote events.
    async fn persist_incorporated_event_bytes<B: AsRef<[u8]>>(
        &self,
        event_bytes_list: &[B],
        source: Option<KeyhivePeerId>,
        prev_pending: BTreeSet<EventHash>,
    ) -> Result<Vec<EventHash>, ProtocolError<Conn::SendError>> {
        let mut inserted_hashes = Vec::new();
        for event_bytes in event_bytes_list {
            let (hash, inserted) = storage_ops::save_event_bytes(
                &self.storage,
                event_bytes.as_ref().to_vec(),
                source.clone(),
            )
            .await?;
            if inserted {
                inserted_hashes.push(hash.0);
            }
        }
        self.report_newly_admitted(
            prev_pending,
            inserted_hashes
                .iter()
                .copied()
                .map(|hash| (hash, source.clone()))
                .collect(),
        )
        .await?;
        Ok(inserted_hashes)
    }

    /// The keyhive projection's current pending event hashes.
    async fn pending_event_hashes(&self) -> BTreeSet<EventHash> {
        self.keyhive
            .pending_event_hashes()
            .await
            .into_iter()
            .map(|digest| *digest.raw.as_bytes())
            .collect()
    }

    /// Report hashes newly incorporated into the keyhive projection, then
    /// record the new pending set only after durable reporting succeeds.
    async fn report_newly_admitted(
        &self,
        prev_pending: BTreeSet<EventHash>,
        inserted_hashes: Vec<(EventHash, Option<KeyhivePeerId>)>,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        let new_pending = self.pending_event_hashes().await;
        let resolved: BTreeSet<_> = prev_pending.difference(&new_pending).copied().collect();
        let mut newly_admitted = BTreeMap::new();

        if !resolved.is_empty() {
            let stored = self
                .storage
                .load_events_with_source()
                .await
                .map_err(|error| ProtocolError::Storage(StorageError::Load(error.to_string())))?;
            for (hash, _, source) in stored {
                if resolved.contains(hash.as_bytes()) {
                    newly_admitted.insert(*hash.as_bytes(), source);
                }
            }
        }
        // An event written while still pending keeps its place in the log but has
        // no admission row. Whichever exchange first observes it as incorporated
        // must admit it, so re-check everything this protocol is still holding —
        // not only what this exchange inserted. Relying on `prev_pending` alone
        // loses the resolution whenever a concurrent exchange snapshotted its
        // pending set before this event was written.
        {
            let mut tracked = self.unadmitted_inserted.lock().await;
            for (hash, source) in inserted_hashes {
                tracked.entry(hash).or_insert(source);
            }
            let outstanding: Vec<_> = core::mem::take(&mut *tracked).into_iter().collect();
            for (hash, source) in outstanding {
                if new_pending.contains(&hash) {
                    tracked.insert(hash, source);
                } else {
                    newly_admitted.insert(hash, source);
                }
            }
        }

        if let Some(sink) = &self.on_durable_incorporation {
            let mut unreported = self.unreported_incorporations.lock().await;
            for (hash, source) in newly_admitted {
                unreported.entry(hash).or_insert(source);
            }
            let pending_reports = unreported.clone();
            drop(unreported);

            let mut by_source: BTreeMap<Option<KeyhivePeerId>, Vec<EventHash>> = BTreeMap::new();
            for (hash, source) in &pending_reports {
                by_source.entry(source.clone()).or_default().push(*hash);
            }
            for (source, hashes) in by_source {
                sink.clone()
                    .admit(hashes.clone(), source)
                    .await
                    .map_err(ProtocolError::Storage)?;
                self.unreported_incorporations
                    .lock()
                    .await
                    .retain(|hash, _| !hashes.contains(hash));
            }
        }
        *self.pending_hashes.lock().await = Some(new_pending);
        Ok(())
    }

    /// Attempt to recover by ingesting from storage and retrying.
    async fn try_storage_recovery<B: AsRef<[u8]>>(
        &self,
        event_bytes_list: &[B],
    ) -> Result<(usize, bool), StorageError> {
        let (storage_pending, mut resolved_pending) =
            storage_ops::ingest_from_storage_with_pending_progress(&self.keyhive, &self.storage)
                .await?;

        let events: Vec<StaticEvent<CRef>> = event_bytes_list
            .iter()
            .filter_map(|bytes| match bincode_deserialize(bytes.as_ref()) {
                Ok(ev) => Some(ev),
                Err(e) => {
                    tracing::warn!(error = %e, "storage recovery: failed to deserialize event");
                    None
                }
            })
            .collect();

        if events.is_empty() {
            return Ok((storage_pending.len(), resolved_pending));
        }

        let (retry_pending, retry_progress) = self
            .keyhive
            .ingest_unsorted_static_events_with_pending_progress(events)
            .await;
        resolved_pending |= retry_progress;
        if retry_pending.is_empty() {
            tracing::debug!("all events ingested after storage recovery");
        } else {
            tracing::warn!(
                count = retry_pending.len(),
                "events still pending after storage recovery"
            );
        }
        Ok((retry_pending.len(), resolved_pending))
    }

    /// Ingest a contact card into keyhive and persist its prekey op to
    /// storage.
    async fn ingest_contact_card(
        &self,
        contact_card: &ContactCard,
        source: Option<KeyhivePeerId>,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        let prev_pending = match self.pending_hashes.lock().await.as_ref() {
            Some(previous) => previous.clone(),
            None => self.pending_event_hashes().await,
        };
        // Validate first: only persist after keyhive accepts the card.
        self.keyhive
            .receive_contact_card(contact_card)
            .await
            .map_err(ProtocolError::ReceiveContactCard)?;

        let event: StaticEvent<CRef> = match contact_card.op() {
            KeyOp::Add(add) => StaticEvent::PrekeysExpanded(Box::new(add.as_ref().clone())),
            KeyOp::Rotate(rot) => StaticEvent::PrekeyRotated(Box::new(rot.as_ref().clone())),
        };
        let bytes = [bincode_serialize(&event)?];
        self.persist_incorporated_event_bytes(&bytes, source, prev_pending)
            .await?;

        tracing::debug!("ingested contact card");
        Ok(())
    }

    /// Compact keyhive storage.
    ///
    /// Consolidates archives and removes processed events. This should be
    /// called periodically by the owner of the protocol handler.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if any storage operation, serialization, or
    /// deserialization fails.
    pub async fn compact(&self, storage_id: StorageHash) -> Result<(), StorageError> {
        storage_ops::compact(&self.keyhive, &self.storage, storage_id).await
    }

    /// Load and ingest all stored archives and events, then reconcile the
    /// durable incorporation boundary.
    ///
    /// Archives are async checkpoints; the event WAL is the durable log. An
    /// event that was persisted and applied to the projection but whose
    /// admission had not committed at crash time replays from the WAL here yet
    /// was never admitted — this method closes exactly that window.
    ///
    /// Reconciliation is diff-first: candidates are WAL rows lacking an
    /// admission entry (`DurableIncorporationSink::unadmitted_wal_events`, ONE
    /// embedder-side set-diff query). The common boot has no candidates and
    /// never reads event bytes or probes the projection. A non-empty candidate
    /// set is checked event-by-event against the projection's owning stores;
    /// unrelated projection history is never inventoried. Compaction deletes
    /// WAL rows only after admission completed, so archive-only state needs no
    /// repair here and original source attribution always survives.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if loading, ingestion, or admission fails.
    pub async fn ingest_from_storage(&self) -> Result<(), StorageError> {
        storage_ops::ingest_from_storage(&self.keyhive, &self.storage).await?;
        let result = self.reconcile_unadmitted().await;
        // Publish the post-recovery pending set so the next exchange's reporter
        // diff starts from the recovered projection.
        *self.pending_hashes.lock().await = Some(self.pending_event_hashes().await);
        result
    }

    /// Report WAL events incorporated by recovery but missing an admission
    /// entry. See [`Self::ingest_from_storage`] for the rationale.
    async fn reconcile_unadmitted(&self) -> Result<(), StorageError> {
        let Some(sink) = &self.on_durable_incorporation else {
            return Ok(());
        };
        let candidates = sink.clone().unadmitted_wal_events().await?;
        if candidates.is_empty() {
            return Ok(());
        }
        let pending = self.pending_event_hashes().await;
        let mut by_source: BTreeMap<Option<KeyhivePeerId>, Vec<EventHash>> = BTreeMap::new();
        for (hash, bytes, source) in candidates {
            if pending.contains(&hash) {
                continue;
            }
            let event: StaticEvent<CRef> = bincode_deserialize(&bytes)?;
            let decoded_hash = *Digest::hash(&event).raw.as_bytes();
            if decoded_hash != hash {
                return Err(StorageError::Load(alloc::format!(
                    "unadmitted WAL event hash mismatch: stored {hash:?}, decoded {decoded_hash:?}"
                )));
            }
            if !self.keyhive.contains_incorporated_event(&event).await {
                return Err(StorageError::Load(alloc::format!(
                    "unadmitted WAL event {hash:?} is neither pending nor incorporated"
                )));
            }
            by_source.entry(source).or_default().push(hash);
        }
        for (source, hashes) in by_source {
            sink.clone().admit(hashes, source).await?;
        }
        Ok(())
    }

    /// Look up cached events for us paired with the provided peer.
    ///
    /// `None` means the cache cannot answer for this peer: the local keyhive holds no
    /// visible set for it at all, i.e. it has never seen it. That is the only reason this
    /// declines. An empty set is returned as-is, because "we know the peer and there is
    /// nothing to advertise" is a different fact from "we have never seen the peer", and
    /// callers decide whether to ask for a contact card on exactly that difference. A
    /// caller that receives `None` falls through to [`Self::get_events_for_peer_pair`],
    /// which asks the keyhive directly and also answers `None` for an unknown peer.
    async fn cached_events_for_pair_with_peer(
        &self,
        peer: &KeyhivePeerId,
    ) -> Option<Arc<AgentHashMap>> {
        let cache = self.cache.lock().await;
        let local = self.peer_id();
        match cache.events_for_peer_pair(&local, peer) {
            PeerPairProjection::Unknown => None,
            PeerPairProjection::Known { events } => Some(events),
        }
    }

    /// Compute the per-pair total op count and a digest of the pair's op-hash
    /// set.
    ///
    /// The total is the number of intersection hashes plus pending hashes. The
    /// digest is an order-independent XOR of the intersection hashes.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if hash or pending computation fails.
    async fn compute_total_and_digest_for_peer(
        &self,
        peer: &KeyhivePeerId,
    ) -> Result<(u64, EventHash), ProtocolError<Conn::SendError>> {
        let (hash_count, digest) =
            if let Some(cached) = self.cached_events_for_pair_with_peer(peer).await {
                (cached.len(), pair_set_digest(cached.keys()))
            } else if let Some(pair) = self.get_events_for_peer_pair(peer).await? {
                (pair.len(), pair_set_digest(pair.keys()))
            } else {
                (0, [0u8; 32])
            };
        let pending_count = self.get_pending_hashes().await?.len();
        Ok(((hash_count + pending_count) as u64, digest))
    }
    /// Sync with a peer using the best available strategy.
    ///
    /// Sends a lightweight sync check when a syncpoint exists for the
    /// peer; otherwise falls back to a full sync.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if the protocol call fails.
    #[tracing::instrument(name = "keyhive_initiate_sync", level = "debug", skip_all, fields(peer = %peer))]
    pub async fn initiate_sync_with_peer(
        &self,
        peer: &KeyhivePeerId,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        self.initiate_sync_with_request(peer, self.next_request_id())
            .await
    }

    /// Initiate a sync using a caller-provided request identifier.
    ///
    /// Runtime integrations use this to correlate the protocol completion with
    /// the operation that admitted the round. The identifier is echoed through
    /// every message in the exchange.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if the cache refresh or the sync exchange fails.
    pub async fn initiate_sync_with_request(
        &self,
        peer: &KeyhivePeerId,
        request_id: RequestId,
    ) -> Result<(), ProtocolError<Conn::SendError>> {
        self.ensure_cache_current().await?;
        let syncpoint = self.syncpoints.lock().await.get(peer);
        match syncpoint {
            Some(sp) => {
                self.sync_check_keyhive_for_request(peer, sp, request_id)
                    .await
            }
            None => self.sync_keyhive_for_request(peer, request_id).await,
        }
    }

    /// Refresh the periodic event cache from the underlying keyhive.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if any per-agent walk fails.
    pub async fn refresh_cache(&self) -> Result<(), ProtocolError<Conn::SendError>> {
        self.ensure_cache_current().await
    }

    /// Classify a batch of changed event hashes against the connected peer
    /// set, using the freshly published cache snapshot.
    ///
    /// A peer is selected when any changed hash is public (visible to every
    /// peer) or is in that peer's cached visible set. Hashes absent from the
    /// visible projection are returned in `unclassified` for conservative
    /// handling by the caller. The returned generation is the snapshot the
    /// classification was performed against.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if the cache refresh fails.
    pub async fn notification_targets(
        &self,
        batch: VisibilityBatch<'_>,
    ) -> Result<VisibilityTargets, ProtocolError<Conn::SendError>> {
        self.ensure_cache_current().await?;
        let published_generation = self.snapshot_state_generation.load(Ordering::Acquire);
        let (peers, unclassified) = {
            let cache = self.cache.lock().await;
            cache.notification_targets(&self.peer_id, batch.connected, batch.changed)
        };
        Ok(VisibilityTargets {
            published_generation,
            peers,
            unclassified,
        })
    }

    async fn ensure_cache_current(&self) -> Result<(), ProtocolError<Conn::SendError>> {
        let _refresh_guard = self.cache_refresh_lock.lock().await;
        loop {
            let snapshot_generation = self.snapshot_state_generation.load(Ordering::Acquire);
            let before = self.keyhive.state_generation();
            let nested_now = self.keyhive.nested_store_generation_sum().await;
            if snapshot_generation == before {
                // Two-sample staleness check. The hive generation alone cannot see
                // a mutation that reached only a principal store, and a cache that
                // serves a pre-mutation advertisement view will never tell a peer
                // about the resulting event. If any route still escapes the shared
                // counter, this both reports it and rebuilds anyway.
                let published_nested = self.snapshot_nested_generation.load(Ordering::Acquire);
                if nested_now == published_nested {
                    return Ok(());
                }
                tracing::warn!(
                    hive_generation = before,
                    snapshot_generation,
                    published_nested,
                    nested_now,
                    "principal store counters moved while the hive generation did not;                      rebuilding the advertisement cache"
                );
            }

            // A structural projection change invalidates every peer syncpoint.
            // Do this before rebuilding so no short-circuit can survive drift.
            self.syncpoints.lock().await.invalidate_all();
            {
                let mut cache = self.cache.lock().await;
                cache.refresh(self).await?;
            }
            let after = self.keyhive.state_generation();
            if before != after {
                continue;
            }

            // Publish exactly the generation observed before and after the
            // rebuild. Never label an older snapshot with a later generation.
            self.snapshot_state_generation
                .store(before, Ordering::Release);
            self.snapshot_nested_generation.store(
                self.keyhive.nested_store_generation_sum().await,
                Ordering::Release,
            );
            if self.keyhive.state_generation() == before {
                return Ok(());
            }
        }
    }
}

/// Get sync-relevant events for an agent: membership, prekey, and CGKA operations.
async fn sync_events_for_agent<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>(
    keyhive: &Keyhive<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>,
    agent: &Agent<Async, Signer, CRef, Listener>,
) -> Map<Digest<StaticEvent<CRef>>, StaticEvent<CRef>>
where
    Async: future_form::FutureForm,
    Signer: AsyncSigner<Async> + Clone,
    CRef: ContentRef,
    Plaintext: for<'de> serde::Deserialize<'de>,
    CipherStore: CiphertextStore<Async, CRef, Plaintext>
        + CiphertextStoreExt<Async, CRef, Plaintext>
        + Clone,
    Listener: MembershipListener<Async, Signer, CRef>,
    Rng: rand::CryptoRng + rand::RngCore,
{
    keyhive
        .static_events_for_agent(agent.id())
        .await
        .into_iter()
        .collect::<Map<Digest<StaticEvent<CRef>>, StaticEvent<CRef>>>()
}

/// The agents named by events the peer is about to receive.
///
/// Only delegations count: they add a principal the receiver may later have to act as the
/// counterparty of. A revocation removes one instead (acting on a removal needs no key material),
/// and prekey and CGKA events name no counterparty at all.
fn named_agents<'a, CRef>(
    events: impl Iterator<Item = &'a StaticEvent<CRef>>,
) -> HashSet<Identifier>
where
    CRef: ContentRef + 'a,
{
    let mut named = HashSet::new();
    for event in events {
        if let StaticEvent::Delegated(delegation) = event {
            named.insert(delegation.payload().delegate);
        }
    }
    named
}

/// The individuals whose key ops must accompany an event naming `agent`.
///
/// Mirrors keyhive's `pick_individual_prekeys`: it walks the principal's transitive members,
/// keeps the individuals at `Read` or better, and needs a published prekey for each of them. An
/// individual is pickable directly, a group or document through the individuals flattened into its
/// transitive members, and a group's or document's own entry is deliberately not part of the set
/// because both routinely publish no prekey of their own. keyhive's walk skips nested groups and
/// documents for the same reason: `transitive_members` is already transitive.
///
/// Both selection paths call this — the advertisement cache and the per-pair fallback — so that
/// "who is pickable" has one definition rather than one per path.
async fn pickable_individuals<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>(
    keyhive: &Keyhive<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>,
    agent: Identifier,
) -> Vec<Identifier>
where
    Async: future_form::FutureForm,
    Signer: AsyncSigner<Async> + Clone,
    CRef: ContentRef,
    Plaintext: for<'de> serde::Deserialize<'de>,
    CipherStore: CiphertextStore<Async, CRef, Plaintext>
        + CiphertextStoreExt<Async, CRef, Plaintext>
        + Clone,
    Listener: MembershipListener<Async, Signer, CRef>,
    Rng: rand::CryptoRng + rand::RngCore,
{
    match keyhive.get_agent(agent).await.and_then(|a| a.as_membered()) {
        Some(membered) => membered
            .transitive_members()
            .await
            .into_iter()
            .filter(|(_, (member, access))| {
                access.is_reader() && matches!(member, Agent::Individual(..) | Agent::Active(..))
            })
            .map(|(id, _)| id)
            .collect(),
        None => vec![agent],
    }
}

/// What one attachment pass over a round's named delegates attached, and what it could not.
///
/// The two `uncovered_*` counters are the diagnostic an operator reads to decide whether a
/// "name without material" split occurred, so they report only delegates whose material is
/// genuinely *absent*. A pick set holding nothing but `Public` has nothing to attach **by
/// design** — `Public`'s key is well known and it publishes no prekey ops of its own — and a pick
/// set with no individuals at all has nobody to co-sign with. Counting either as uncovered was a
/// permanent false positive: any round naming `Public` reported an uncovered delegate, which made
/// the counter unable to distinguish "a split occurred" from "the round mentioned `Public`".
/// The exempt skips are counted separately, in `exempt_individuals_skipped`, so that work stays
/// visible without being mislabelled as absent material.
#[derive(Debug, Default)]
struct ReferenceClosure {
    /// Per naming source, the key ops of the delegates the named events need.
    attached_per_source: BTreeMap<Identifier, BTreeSet<EventHash>>,
    /// Naming events, across every delegate whose pick set was walked.
    named_delegates: usize,
    /// Delegates whose material was expected and absent.
    uncovered_delegates: BTreeSet<Identifier>,
    /// Naming events for those uncovered delegates.
    uncovered_naming_events: usize,
    /// Pickable individuals this node holds no material for.
    missing_individuals: BTreeSet<Identifier>,
    /// How many of those are registered but hold no key ops: a restore or a prune.
    missing_registered_empty: usize,
    /// How many of those never registered, so no op of theirs reached this node.
    missing_unregistered: usize,
    /// Pickable individuals skipped by design, whose key material is well known.
    exempt_individuals_skipped: usize,
}

/// Close each named delegate's events over the key material a peer needs to co-sign with it.
///
/// Attachment is never conditional on covering the whole set: a name is forwarded by nodes that
/// may be unable to back it (a relay that learned a grant without ever holding the grantee's
/// prekeys), and dropping the name at that hop stops membership from crossing it at all. Partial
/// material is strictly better than none, and dropping a whole delegate because one member is
/// momentarily missing would strand the rest — so what this returns is a diagnostic, never a
/// withhold.
async fn reference_closure<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>(
    keyhive: &Keyhive<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>,
    named_delegates_per_source: &BTreeMap<Identifier, Vec<(EventHash, Identifier)>>,
    prekey_source_hashes: &BTreeMap<Identifier, Vec<EventHash>>,
) -> ReferenceClosure
where
    Async: future_form::FutureForm,
    Signer: AsyncSigner<Async> + Clone,
    CRef: ContentRef,
    Plaintext: for<'de> serde::Deserialize<'de>,
    CipherStore: CiphertextStore<Async, CRef, Plaintext>
        + CiphertextStoreExt<Async, CRef, Plaintext>
        + Clone,
    Listener: MembershipListener<Async, Signer, CRef>,
    Rng: rand::CryptoRng + rand::RngCore,
{
    // Invert the source-keyed delegations so each delegate's pick set is walked once, however
    // many delegations and sources name it.
    let mut delegations_per_delegate: BTreeMap<Identifier, Vec<(Identifier, EventHash)>> =
        BTreeMap::new();
    for (source_id, delegations) in named_delegates_per_source {
        for (delegation_hash, delegate_id) in delegations {
            delegations_per_delegate
                .entry(*delegate_id)
                .or_default()
                .push((*source_id, *delegation_hash));
        }
    }

    let mut closure = ReferenceClosure::default();
    for (delegate_id, naming_events) in &delegations_per_delegate {
        let pickable = pickable_individuals(keyhive, *delegate_id).await;
        let mut delegate_hashes: BTreeSet<EventHash> = BTreeSet::new();
        // Whether any pickable individual was *expected* to contribute material. A pick set that
        // holds only exempt principals, or holds none at all, has nothing to attach by design, so
        // it cannot be a name held without material.
        let mut expected_material = false;
        for individual in &pickable {
            // `Public` has one well-known key and no prekey ops of its own to attach.
            if *individual == Public.id() {
                closure.exempt_individuals_skipped += 1;
                continue;
            }
            expected_material = true;
            match prekey_source_hashes.get(individual) {
                Some(hashes) if !hashes.is_empty() => {
                    delegate_hashes.extend(hashes.iter().copied());
                }
                Some(_) => {
                    // Registered here, but holding no prekey ops: a restore or a prune, since
                    // an individual is built from the op that registers it.
                    closure.missing_individuals.insert(*individual);
                    closure.missing_registered_empty += 1;
                }
                None => {
                    // No op of its own ever reached this node, so nothing to attach.
                    closure.missing_individuals.insert(*individual);
                    closure.missing_unregistered += 1;
                }
            }
        }
        closure.named_delegates += naming_events.len();
        if !delegate_hashes.is_empty() {
            for (source_id, _) in naming_events {
                closure
                    .attached_per_source
                    .entry(*source_id)
                    .or_default()
                    .extend(delegate_hashes.iter().copied());
            }
        } else if expected_material {
            // A peer receiving this name would hold it without the material to co-sign with the
            // delegate: worth surfacing, and never a reason to withhold the name itself.
            closure.uncovered_delegates.insert(*delegate_id);
            closure.uncovered_naming_events += naming_events.len();
        }
    }
    closure
}

/// The key ops that must accompany an event naming `agent`.
///
/// A peer that records an event naming a principal should later be able to co-sign with everyone
/// that event makes pickable: keyhive's `pick_individual_prekeys` walks the principal's transitive
/// members, keeps the individuals at `Read` or better, and needs a published prekey for each of
/// them. So the material attached to a naming event is that walk's set — an individual's own key
/// ops, or for a group or document the ops of its member individuals. A group's own entry is
/// deliberately not part of it: groups and documents routinely publish no prekey of their own, and
/// keyhive's walk skips nested groups and documents because `transitive_members` is already
/// transitive.
///
/// Whatever we hold is attached and whatever we lack is simply not sent — nothing is withheld. An
/// intermediate node legitimately holds a name it cannot back (the grant's author had the
/// delegate's prekeys; a relay may have only learned the grant), so dropping the name at that hop
/// would stop membership crossing it. `all_agent_events` carries the same rule on the path that
/// runs in practice.
///
/// Attachment is a lookup into the exchange-wide reachability pass rather than another walk: its
/// `ops` map is keyed by every principal in the graph. Its `index` is not usable here, because it is
/// keyed by member — a principal's entry lists the containers it belongs to, never the members it
/// contains.
async fn prekey_closure_for_agent<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>(
    keyhive: &Keyhive<Async, Signer, CRef, Plaintext, CipherStore, Listener, Rng>,
    reachable: &AllReachablePrekeyOps,
    agent: Identifier,
) -> Vec<(Digest<StaticEvent<CRef>>, StaticEvent<CRef>)>
where
    Async: future_form::FutureForm,
    Signer: AsyncSigner<Async> + Clone,
    CRef: ContentRef,
    Plaintext: for<'de> serde::Deserialize<'de>,
    CipherStore: CiphertextStore<Async, CRef, Plaintext>
        + CiphertextStoreExt<Async, CRef, Plaintext>
        + Clone,
    Listener: MembershipListener<Async, Signer, CRef>,
    Rng: rand::CryptoRng + rand::RngCore,
{
    let pickable = pickable_individuals(keyhive, agent).await;

    let mut attached: Vec<(Digest<StaticEvent<CRef>>, StaticEvent<CRef>)> = Vec::new();
    for id in pickable {
        for op in reachable.ops.get(&id).into_iter().flatten() {
            // The digest is taken over the `Event` and coerced, exactly as `events_for_agent`
            // derives the pairs it hands to `static_events_for_agent`: the peer hashes the same
            // bytes, so an attachment deduplicates against the selection instead of being served
            // twice.
            let event = Event::<Async, Signer, CRef, Listener>::from(op.as_ref().dupe());
            attached.push((Digest::hash(&event).coerce(), event.into()));
        }
    }
    attached
}

/// Hash, serialize, and deduplicate events into `event_data`, returning hashes.
///
/// Hashes present in `skip_serialization` are recorded but not serialized.
fn hash_and_insert_events<Async, Signer, CRef, Listener, E>(
    event_data: &mut BTreeMap<EventHash, Arc<[u8]>>,
    events: impl Iterator<Item = Event<Async, Signer, CRef, Listener>>,
    skip_serialization: &BTreeSet<EventHash>,
) -> Result<Vec<EventHash>, ProtocolError<E>>
where
    Async: future_form::FutureForm,
    Signer: AsyncSigner<Async> + Clone,
    CRef: ContentRef,
    Listener: MembershipListener<Async, Signer, CRef>,
    E: core::error::Error + 'static,
{
    let mut hashes = Vec::new();
    for event in events {
        let digest = Digest::hash(&event);
        let h = digest_to_bytes(&digest);
        hashes.push(h);
        if !skip_serialization.contains(&h)
            && let Entry::Vacant(e) = event_data.entry(h)
        {
            let static_event = StaticEvent::from(event);
            e.insert(serialize_event(&static_event)?);
        }
    }
    Ok(hashes)
}

/// Serialize a map of digested events into a hash-keyed byte map.
fn collect_serialized_events<CRef: ContentRef, E: core::error::Error + 'static>(
    events: Map<Digest<StaticEvent<CRef>>, StaticEvent<CRef>>,
) -> Result<AgentHashMap, ProtocolError<E>> {
    let mut out = AgentHashMap::new();
    for (digest, event) in events {
        let h = digest_to_bytes(&digest);
        out.insert(h, serialize_event(&event)?);
    }
    Ok(out)
}

/// Serialize a `StaticEvent` to bincode bytes, `Arc`-shared.
///
/// The bytes are `Arc`-shared so the periodic cache and every served response
/// reference one copy instead of each deep-copying the bytes.
fn serialize_event<CRef: ContentRef, E: core::error::Error + 'static>(
    event: &StaticEvent<CRef>,
) -> Result<Arc<[u8]>, ProtocolError<E>> {
    let bytes =
        bincode_serialize(event).map_err(|e| ProtocolError::Serialization(e.to_string()))?;
    Ok(Arc::from(bytes))
}

/// Collect hashes reachable from `agent_id` through `index` into `hash_set`.
fn extend_from_index(
    hash_set: &mut BTreeSet<EventHash>,
    index: &HashMap<Identifier, HashSet<Identifier>>,
    source_hashes: &BTreeMap<Identifier, Vec<EventHash>>,
    agent_id: &Identifier,
) {
    if let Some(sources) = index.get(agent_id) {
        for s in sources {
            if let Some(hs) = source_hashes.get(s) {
                hash_set.extend(hs);
            }
        }
    }
}

/// Serialize a value to CBOR bytes.
fn cbor_serialize<V: serde::Serialize>(value: &V) -> Result<Vec<u8>, StorageError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| StorageError::Serialization(e.to_string()))?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes.
fn cbor_deserialize<V: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<V, StorageError> {
    ciborium::from_reader(bytes).map_err(|e| StorageError::Deserialization(e.to_string()))
}

/// Convert a `Digest` to a 32-byte array.
const fn digest_to_bytes<U: serde::Serialize>(digest: &Digest<U>) -> [u8; 32] {
    *digest.raw.as_bytes()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::wildcard_enum_match_arm,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use crate::{
        message::EventBytes,
        storage::MemoryKeyhiveStorage,
        test_utils::{
            SimpleKeyhive, TestProtocol, TwoPeerHarness, create_channel_pair,
            create_group_with_read_members, exchange_all_contact_cards,
            exchange_contact_cards_and_setup, keyhive_peer_id, make_keyhive,
            make_protocol_with_shared_keyhive, run_sync_round, sync_pair_rounds,
        },
    };
    use future_form::{FutureForm, Local};
    use keyhive_core::{
        access::Access,
        principal::{
            identifier::Identifier,
            membered::{Membered, id::MemberedId},
        },
    };
    use nonempty::nonempty;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};

    /// Configurable [`DurableIncorporationSink`] for tests: records admits,
    /// can simulate a crash (failed admit), and serves a canned
    /// WAL-minus-admission diff.
    struct RecordingSink {
        reports: async_lock::Mutex<Vec<(Vec<EventHash>, Option<KeyhivePeerId>)>>,
        admitted: async_lock::Mutex<BTreeSet<EventHash>>,
        unadmitted: async_lock::Mutex<UnadmittedWalEvents>,
        unadmitted_queries: AtomicUsize,
        fail_admit: AtomicBool,
    }

    impl RecordingSink {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                reports: async_lock::Mutex::new(Vec::new()),
                admitted: async_lock::Mutex::new(BTreeSet::new()),
                unadmitted: async_lock::Mutex::new(Vec::new()),
                unadmitted_queries: AtomicUsize::new(0),
                fail_admit: AtomicBool::new(false),
            })
        }
    }

    impl DurableIncorporationSink<Local> for RecordingSink {
        fn admit(
            self: Arc<Self>,
            hashes: Vec<EventHash>,
            source: Option<KeyhivePeerId>,
        ) -> <Local as FutureForm>::Future<'static, Result<(), StorageError>> {
            Local::from_future(async move {
                if self.fail_admit.load(AtomicOrdering::SeqCst) {
                    return Err(StorageError::Save("simulated crash".to_string()));
                }
                self.reports.lock().await.push((hashes.clone(), source));
                self.admitted.lock().await.extend(hashes);
                Ok(())
            })
        }

        fn unadmitted_wal_events(
            self: Arc<Self>,
        ) -> <Local as FutureForm>::Future<
            'static,
            Result<Vec<(EventHash, Vec<u8>, Option<KeyhivePeerId>)>, StorageError>,
        > {
            Local::from_future(async move {
                self.unadmitted_queries.fetch_add(1, AtomicOrdering::SeqCst);
                Ok(self.unadmitted.lock().await.clone())
            })
        }
    }

    /// The reference closure keys off the agent a delegation names, and nothing else.
    ///
    /// A delegation is the only static event that adds a co-signing counterparty: prekey and CGKA
    /// events name no agent, and a revocation removes one (no key material is needed to act on a
    /// removal).
    #[test]
    fn named_agents_matches_delegates_only() {
        use keyhive_core::principal::{
            group::delegation::StaticDelegation, individual::op::add_key::AddKeyOp,
        };
        use keyhive_crypto::share_key::ShareKey;

        let issuer = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        let delegate =
            Identifier(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key());
        let signature = ed25519_dalek::Signature::from_bytes(&[0u8; 64]);

        let delegation = StaticEvent::Delegated(Signed::new(
            StaticDelegation::<[u8; 32]> {
                can: Access::Read,
                proof: None,
                delegate,
                after_revocations: Vec::new(),
                after_content: BTreeMap::new(),
            },
            issuer,
            signature,
        ));
        let prekey = StaticEvent::PrekeysExpanded(Box::new(Signed::new(
            // Built from its public field: `AddKeyOp::generate` sits behind keyhive's `test_utils`
            // feature, which this crate does not enable.
            AddKeyOp {
                share_key: ShareKey::generate(&mut rand::rngs::OsRng),
            },
            issuer,
            signature,
        )));

        let named = named_agents([&delegation, &prekey].into_iter());
        assert_eq!(named.len(), 1, "only the delegation names a counterparty");
        assert!(named.contains(&delegate));
    }

    /// The owner of a prekey event, for asserting whose material a closure attached.
    fn prekey_owner(event: &StaticEvent<[u8; 32]>) -> Option<Identifier> {
        match event {
            StaticEvent::PrekeysExpanded(op) => Some(Identifier(op.issuer)),
            StaticEvent::PrekeyRotated(op) => Some(Identifier(op.issuer)),
            StaticEvent::CgkaOperation(_) | StaticEvent::Delegated(_) | StaticEvent::Revoked(_) => {
                None
            }
        }
    }

    /// The closure attaches an individual's own key ops, and attaches nothing for an agent we
    /// hold none for.
    ///
    /// The second half is load bearing: every principal's reachable set includes the active
    /// individual, so an agent we hold nothing for must not come back "covered" by our own ops.
    ///
    /// Nothing is ever withheld: an agent we cannot cover is attached as empty rather than
    /// refused, because a relay legitimately holds a name it cannot back and dropping the name
    /// at that hop would stop membership from crossing it.
    #[tokio::test(flavor = "current_thread")]
    async fn prekey_closure_covers_known_agents_and_refuses_unknown_ones() {
        let harness = exchange_contact_cards_and_setup().await;
        deliver_own_prekey_ops(harness.alice_kh.as_ref(), harness.bob_kh.as_ref()).await;
        let bob = harness.bob_id.to_identifier().expect("bob identifier");
        let reachable = harness.alice_kh.reachable_prekey_ops_for_all_agents().await;

        let attached = prekey_closure_for_agent(harness.alice_kh.as_ref(), &reachable, bob).await;
        assert!(
            attached
                .iter()
                .any(|(_, event)| prekey_owner(event) == Some(bob)),
            "the named individual's own key ops must be attached"
        );

        let stranger =
            Identifier(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key());
        assert!(
            prekey_closure_for_agent(harness.alice_kh.as_ref(), &reachable, stranger)
                .await
                .is_empty(),
            "an agent we hold no key ops for must attach nothing"
        );
    }

    /// A group delegate is covered through its members, not through its own ops.
    ///
    /// Daybook documents delegate to their drawer and content-docs groups, and those groups publish
    /// no prekey of their own — so a gate that read the named principal's own entry withheld
    /// exactly the delegations the product creates.
    #[tokio::test(flavor = "current_thread")]
    async fn prekey_closure_covers_a_group_delegate_through_its_members() {
        let harness = exchange_contact_cards_and_setup().await;
        deliver_own_prekey_ops(harness.alice_kh.as_ref(), harness.bob_kh.as_ref()).await;
        let bob = harness.bob_id.to_identifier().expect("bob identifier");
        let group_id =
            create_group_with_read_members(harness.alice_kh.as_ref(), &[&harness.bob_id]).await;
        let group = Identifier::from(MemberedId::GroupId(group_id));
        let reachable = harness.alice_kh.reachable_prekey_ops_for_all_agents().await;

        // Precondition of the case being covered: the group published nothing of its own, and the
        // member's ops are held.
        assert!(
            reachable.ops.get(&group).is_none_or(Vec::is_empty),
            "precondition: the group published no prekey of its own"
        );
        assert!(
            reachable.ops.get(&bob).is_some_and(|ops| !ops.is_empty()),
            "precondition: alice holds the member's key ops"
        );

        let attached = prekey_closure_for_agent(harness.alice_kh.as_ref(), &reachable, group).await;
        assert!(
            !attached.is_empty(),
            "a group delegate is covered by its members' key ops"
        );
        assert!(
            attached
                .iter()
                .any(|(_, event)| prekey_owner(event) == Some(bob)),
            "the member's key ops must be attached for a group delegate"
        );
    }

    /// Decode every event a peer would be served, from an advertisement alone.
    ///
    /// The bytes come out of `event_data`, so this asserts servability as well as membership: a
    /// hash in a peer's set with no bytes behind it is a promise the response cannot keep.
    fn advertised_events(
        snapshot: &crate::all_agent_events::AllAgentEvents,
        peer: &KeyhivePeerId,
    ) -> Vec<StaticEvent<[u8; 32]>> {
        snapshot
            .hashes_for(peer)
            .expect("the peer must have an advertised set")
            .iter()
            .filter_map(|hash| snapshot.event_data.get(hash))
            .map(|bytes| bincode_deserialize(bytes).expect("advertised bytes are a static event"))
            .collect()
    }

    /// Whether an advertisement carries the named agent's own key ops.
    fn advertises_prekey_of(advertisement: &AgentHashMap, who: Identifier) -> bool {
        advertisement
            .values()
            .filter_map(|bytes| bincode_deserialize::<StaticEvent<[u8; 32]>>(bytes).ok())
            .any(|event| prekey_owner(&event) == Some(who))
    }

    /// Install `from`'s own key ops into `to`, which is how a peer learns them from a sync.
    ///
    /// A contact card alone does not establish "we hold their key ops". The card is a *rotation*, so
    /// it installs a rotation-only state, and at the keyhive rev this workspace resolves
    /// (`keyhive_core` git rev `28a53997`, `Cargo.toml`) `KeyOp::topsort` seeds only from `Add` ops —
    /// a rotation-only state therefore serializes to **zero** ops, and
    /// `reachable_prekey_ops_for_all_agents` reports nothing for an individual learned that way. A
    /// fixture that stops at the card exchange therefore does not hold the key ops it assumes, and
    /// the resulting failure looks like a missing attachment instead of a missing precondition.
    /// (That is the prekey-loss bug `../keyhive` fixes in its working copy; the `[patch]` that would
    /// supply it here is commented out in `Cargo.toml`.)
    ///
    /// Delivering the ops explicitly makes the fixtures below independent of which keyhive the
    /// workspace resolves against, so they test the advertisement rather than the dependency's
    /// topsort — and it is faithful: receiving a peer's static prekey events is the production path.
    async fn deliver_own_prekey_ops(to: &SimpleKeyhive, from: &SimpleKeyhive) {
        let from_id: Identifier = from.id().into();
        let ops = from
            .reachable_prekey_ops_for_all_agents()
            .await
            .ops
            .get(&from_id)
            .cloned()
            .unwrap_or_default();
        assert!(
            !ops.is_empty(),
            "precondition: `from`'s own key ops must exist for them to be delivered"
        );
        for op in ops {
            to.receive_prekey_op(&op).await.expect("ingest peer key op");
        }
    }

    /// An attachment assertion about `who` is only meaningful if we hold `who`'s key ops.
    async fn assert_holds_prekey_ops(to: &SimpleKeyhive, who: Identifier) {
        assert!(
            to.reachable_prekey_ops_for_all_agents()
                .await
                .ops
                .get(&who)
                .is_some_and(|ops| !ops.is_empty()),
            "precondition: the fixture must hold {who}'s key ops for an attachment to have material"
        );
    }

    /// The advertisement path production runs attaches a delegate's key ops to the event naming
    /// him.
    ///
    /// Path fact: `all_agent_events` is the only thing `SyncCache::refresh` calls, and the cache is
    /// what `sync_keyhive_for_request` serves a peer from. The fallback (`close_references` →
    /// `prekey_closure_for_agent`) runs only when no cached pair exists, so a test that exercised
    /// only the fallback would prove nothing about what a peer is actually told.
    ///
    /// The delegate is revoked, and that is what makes the assertion load bearing: a revoked
    /// delegate is no longer in the document's `transitive_members`, so neither the co-member's
    /// reachability sets nor the group walks can produce his key ops — yet the delegation that
    /// names him is still part of the document's membership history and is still advertised. Only
    /// the attachment can put the two in the same message.
    #[tokio::test(flavor = "current_thread")]
    async fn advertisement_attaches_the_delegates_pickable_prekey_hashes() {
        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let carol = make_keyhive().await;
        exchange_all_contact_cards(&[&alice, &bob, &carol]).await;
        deliver_own_prekey_ops(&alice, &bob).await;

        let bob_identifier: Identifier = bob.id().into();
        let carol_identifier: Identifier = carol.id().into();
        let carol_id = keyhive_peer_id(&carol);

        let (alice_proto, alice_kh, _) = make_protocol_with_shared_keyhive(alice).await;

        let doc = alice_kh
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = doc;
        let doc = alice_kh
            .get_document(doc_id)
            .await
            .expect("generated document is present");
        let membered = Membered::Document(doc_id, doc.clone());
        alice_kh
            .add_member(bob_identifier, membered.membered_id(), Access::Edit, &[])
            .await
            .unwrap();
        alice_kh
            .add_member(carol_identifier, membered.membered_id(), Access::Read, &[])
            .await
            .unwrap();
        alice_kh
            .revoke_member(bob_identifier, true, membered.membered_id())
            .await
            .unwrap();

        assert!(
            !doc.lock()
                .await
                .transitive_members()
                .await
                .contains_key(&bob_identifier),
            "precondition: the revoked delegate is not a transitive member any more"
        );
        assert_holds_prekey_ops(&alice_kh, bob_identifier).await;

        let snapshot = alice_proto
            .all_agent_events(&BTreeSet::new())
            .await
            .unwrap();
        let advertised = advertised_events(&snapshot, &carol_id);

        assert!(
            advertised.iter().any(|event| matches!(
                event,
                StaticEvent::Delegated(delegation)
                    if delegation.payload.delegate == bob_identifier
            )),
            "the delegation naming the delegate must be advertised"
        );
        assert!(
            advertised
                .iter()
                .any(|event| prekey_owner(event) == Some(bob_identifier)),
            "the delegate's key ops must be attached to the event that names him"
        );
    }

    /// A group delegate is covered through its members' key ops, not through its own.
    ///
    /// Daybook documents delegate to their drawer and content-docs groups, so this is the hot
    /// path. The first implementation walked the named principal's containers and produced nothing
    /// for a group — a group's own op set is routinely empty — which withheld precisely the
    /// delegations the product creates. This is the test that catches that walk coming back.
    #[tokio::test(flavor = "current_thread")]
    async fn advertisement_attaches_a_group_delegates_member_prekeys() {
        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let carol = make_keyhive().await;
        exchange_all_contact_cards(&[&alice, &bob, &carol]).await;
        deliver_own_prekey_ops(&alice, &bob).await;

        let bob_identifier: Identifier = bob.id().into();
        let carol_identifier: Identifier = carol.id().into();
        let carol_id = keyhive_peer_id(&carol);
        let group_id = create_group_with_read_members(&alice, &[&keyhive_peer_id(&bob)]).await;
        let group = Identifier::from(MemberedId::GroupId(group_id));

        let (alice_proto, alice_kh, _) = make_protocol_with_shared_keyhive(alice).await;

        let doc = alice_kh
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = doc;
        let doc = alice_kh
            .get_document(doc_id)
            .await
            .expect("generated document is present");
        let membered = Membered::Document(doc_id, doc.clone());
        alice_kh
            .add_member(group, membered.membered_id(), Access::Read, &[])
            .await
            .unwrap();
        alice_kh
            .add_member(carol_identifier, membered.membered_id(), Access::Read, &[])
            .await
            .unwrap();

        assert!(
            alice_kh
                .reachable_prekey_ops_for_all_agents()
                .await
                .ops
                .get(&group)
                .is_none_or(Vec::is_empty),
            "precondition: the group published no prekey of its own"
        );
        assert_holds_prekey_ops(&alice_kh, bob_identifier).await;

        let snapshot = alice_proto
            .all_agent_events(&BTreeSet::new())
            .await
            .unwrap();
        let advertised = advertised_events(&snapshot, &carol_id);

        assert!(
            advertised.iter().any(|event| matches!(
                event,
                StaticEvent::Delegated(delegation) if delegation.payload.delegate == group
            )),
            "the delegation naming the group must be advertised"
        );
        assert!(
            advertised
                .iter()
                .any(|event| prekey_owner(event) == Some(bob_identifier)),
            "the group's members' key ops must be attached for a group delegate"
        );
    }

    /// A name is always advertised, even when the material behind it cannot be attached.
    ///
    /// This is the half that was added, measured harmful, and removed: a relay legitimately holds
    /// a name it cannot back, and withholding the name at that hop stops membership from crossing
    /// it at all (a deleted-branch topology went from passing in 1.76s to a permanent stall).
    /// Attachment is per delegate and never conditional on the whole set being covered, so a
    /// regression that re-adds the withhold is caught here by the naming event disappearing from a
    /// peer's advertised set.
    ///
    /// The witness for "nothing attachable" is `Public`: the attachment loop skips it by
    /// construction, so no material is ever attached for a delegation naming it. That skip is
    /// *exempt* rather than uncovered — `Public` has one well-known key and publishes no prekey ops
    /// of its own — so it is counted as `exempt_individuals_skipped` and never as
    /// `uncovered_delegates`. The counters are assertable from here: `reference_closure` returns the
    /// whole `ReferenceClosure`, and `coverage_reports_absent_material_and_not_the_exempt_skip`
    /// asserts that a `Public`-only round reports zero uncovered. What *this* test asserts is the
    /// rule and its shape: the name stays, and the delegate we do hold material for is attached in
    /// the same advertisement.
    #[tokio::test(flavor = "current_thread")]
    async fn advertisement_never_withholds_a_name_whose_material_is_missing() {
        use keyhive_core::principal::public::Public;

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        exchange_all_contact_cards(&[&alice, &bob]).await;
        deliver_own_prekey_ops(&alice, &bob).await;

        let bob_identifier: Identifier = bob.id().into();
        let bob_id = keyhive_peer_id(&bob);

        let (alice_proto, alice_kh, _) = make_protocol_with_shared_keyhive(alice).await;

        let doc = alice_kh
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = doc;
        let doc = alice_kh
            .get_document(doc_id)
            .await
            .expect("generated document is present");
        let membered = Membered::Document(doc_id, doc.clone());
        // One delegate we hold material for, one we never can.
        alice_kh
            .add_member(bob_identifier, membered.membered_id(), Access::Edit, &[])
            .await
            .unwrap();
        // `Public` is a unit principal; binding it keeps the call below shaped like the other
        // delegate additions in this module.
        let public_delegate = Public;
        alice_kh
            .add_member(
                public_delegate.id(),
                membered.membered_id(),
                Access::Edit,
                &[],
            )
            .await
            .unwrap();

        let snapshot = alice_proto
            .all_agent_events(&BTreeSet::new())
            .await
            .unwrap();
        let advertised = advertised_events(&snapshot, &bob_id);

        // Direction 1: a delegation nothing can be attached for is still advertised. This is the
        // half that was added, measured harmful, and removed — withholding the name at a hop that
        // cannot back it stopped membership from crossing that hop entirely (a deleted-branch
        // topology went from passing in 1.76s to a permanent stall), so a regression here is the
        // stall coming back. `Public` is the witness because the attachment loop skips it by
        // construction, so nothing is ever attached for a delegation naming it.
        assert!(
            advertised.iter().any(|event| matches!(
                event,
                StaticEvent::Delegated(delegation) if delegation.payload.delegate == Public.id()
            )),
            "a name whose material cannot be attached must still be advertised"
        );
        // Direction 2: attachment is per delegate and never conditional on the whole set being
        // covered, so the delegate we do hold material for is attached in the same advertisement.
        assert!(
            advertised
                .iter()
                .any(|event| prekey_owner(event) == Some(bob_identifier)),
            "the covered delegate's key ops must still be attached in the same advertisement"
        );
        // Note on the state itself: "nothing is attachable for `Public`" is *not* observable as
        // "no `Public`-owned prekey event is advertised". `Public` is a member of this document, so
        // `all_prekey.index[bob]` is extended with every transitive member of the document,
        // `Public` included, and `Public`'s own individual is built from an `AddKeyOp` — so its
        // ops reach `bob` through the ordinary reachability sets regardless of any attachment. What
        // is empty here is the Phase 3 attachment for `Public`'s delegation (the loop `continue`s
        // on `Public`, which is exempt and counted as `exempt_individuals_skipped` instead), and the
        // counters are readable from here through `reference_closure`'s `ReferenceClosure`.
        //
        // Worth knowing for whoever reads those diagnostics: the `Public` skip is exempt, so a round
        // carrying only a delegation naming `Public` reports zero `uncovered_delegates` and zero
        // `uncovered_naming_events`, plus one `exempt_individuals_skipped`. The "name without
        // material" counter can therefore be read as "a split occurred" again, and
        // `coverage_reports_absent_material_and_not_the_exempt_skip` pins that reading in three
        // directions — so a change that silenced the counter wholesale fails it too.
    }

    /// The coverage counters report absent material, and not the deliberate `Public` skip.
    ///
    /// `Public` is skipped for attachment because its key is well known and it publishes no prekey
    /// ops of its own, so a delegation naming only `Public` has nothing to attach — by design. The
    /// coverage check used to run *after* that skip, so the skip counted as absent material: any
    /// round naming `Public` reported `uncovered_delegates` containing `Public` and a non-zero
    /// `uncovered_naming_events`. That made the counter — the diagnostic an operator reads to
    /// decide whether a "name without material" split occurred — permanently unable to distinguish
    /// "a split occurred" from "the round mentioned `Public`".
    ///
    /// All three directions are asserted, because a change that silenced the counter entirely
    /// would satisfy the first: a `Public`-only round is not a withhold, a round that also names a
    /// delegate whose material never arrived still reports that delegate, and the same delegate
    /// with material in hand is attached rather than reported.
    #[tokio::test(flavor = "current_thread")]
    async fn coverage_reports_absent_material_and_not_the_exempt_skip() {
        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let bob_identifier: Identifier = bob.id().into();
        let source: Identifier = alice.id().into();

        // Three delegates over one naming source: the exempt principal, one whose material never
        // arrived, and — for the last direction — one whose material is in hand.
        let public_naming: (EventHash, Identifier) = ([1; 32], Public.id());
        let absent_naming: (EventHash, Identifier) = ([2; 32], bob_identifier);
        let public_only = BTreeMap::from([(source, vec![public_naming])]);
        let with_absent = BTreeMap::from([(source, vec![public_naming, absent_naming])]);
        let empty_prekeys: BTreeMap<Identifier, Vec<EventHash>> = BTreeMap::new();

        // Direction 1: a round naming only `Public` is not a withhold at all. `Public` is not a
        // membered principal, so its pick set is itself — the case the skip exists for.
        let closure = reference_closure(&alice, &public_only, &empty_prekeys).await;
        assert_eq!(
            closure.uncovered_delegates,
            BTreeSet::new(),
            "an exempt principal has no material that can be absent"
        );
        assert_eq!(
            closure.uncovered_naming_events, 0,
            "a round naming only `Public` names no event without material"
        );
        assert_eq!(
            closure.exempt_individuals_skipped, 1,
            "the skip still happens, and is reported under its own name"
        );

        // Direction 2: the same round still reports the delegate whose material is absent, so the
        // counter cannot be silenced into passing direction 1.
        let closure = reference_closure(&alice, &with_absent, &empty_prekeys).await;
        assert_eq!(
            closure.uncovered_delegates,
            BTreeSet::from([bob_identifier]),
            "a delegate whose material never arrived is still reported"
        );
        assert_eq!(
            closure.uncovered_naming_events, 1,
            "the naming event for the absent delegate is counted once"
        );

        // Direction 3: the same delegate with material in hand is attached, not reported — the
        // attachment itself is unchanged, only the diagnostic was wrong.
        let bob_prekeys: BTreeMap<Identifier, Vec<EventHash>> =
            BTreeMap::from([(bob_identifier, vec![[7; 32]])]);
        let closure = reference_closure(&alice, &with_absent, &bob_prekeys).await;
        assert_eq!(
            closure.uncovered_delegates,
            BTreeSet::new(),
            "material in hand is not an absence"
        );
        assert_eq!(
            closure.attached_per_source.get(&source),
            Some(&BTreeSet::from([[7u8; 32]])),
            "the held material is attached to the event naming the delegate"
        );
    }

    /// The served advertisement is rebuilt once the material behind a name becomes pickable.
    ///
    /// Path fact: the cache is what a peer is served from, and `ensure_cache_current` gates its
    /// rebuild on two integer samples (`state_generation()` + `nested_store_generation_sum()`),
    /// which `cache.rs` documents as the reason it must never be skipped on indirect heuristics. A
    /// mutation that bumps neither counter leaves a stale advertisement that will never tell the
    /// peer about events it needs — silent divergence, which is the failure this pins.
    ///
    /// The material here arrives as *membership*: the document already names the group, and Bob
    /// joins that group between the two refreshes, which is what makes the document's delegate
    /// pickable and its key ops part of what co-members are told.
    #[tokio::test(flavor = "current_thread")]
    async fn refresh_cache_reattaches_after_prekey_ops_land() {
        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let carol = make_keyhive().await;
        exchange_all_contact_cards(&[&alice, &bob, &carol]).await;
        deliver_own_prekey_ops(&alice, &bob).await;

        let alice_id = keyhive_peer_id(&alice);
        let carol_id = keyhive_peer_id(&carol);
        let bob_identifier: Identifier = bob.id().into();
        let carol_identifier: Identifier = carol.id().into();

        // A group with no members yet: the document names it, so a co-member learns the name
        // while there is nothing to attach for the principal it points at.
        let group_id = alice.generate_group(vec![]).await.unwrap();
        let group = Identifier::from(MemberedId::GroupId(group_id));

        let (alice_proto, alice_kh, _) = make_protocol_with_shared_keyhive(alice).await;
        let (carol_conn, _inbound) = create_channel_pair(alice_id.clone(), &carol_id);
        alice_proto.add_peer(carol_id.clone(), carol_conn).await;

        // The delegate's material is in hand before the first refresh: what the two refreshes
        // below separate is the delegate becoming *pickable*, not the ops arriving.
        assert_holds_prekey_ops(&alice_kh, bob_identifier).await;

        let doc = alice_kh
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = doc;
        let doc = alice_kh
            .get_document(doc_id)
            .await
            .expect("generated document is present");
        let membered = Membered::Document(doc_id, doc.clone());
        alice_kh
            .add_member(group, membered.membered_id(), Access::Read, &[])
            .await
            .unwrap();
        alice_kh
            .add_member(carol_identifier, membered.membered_id(), Access::Read, &[])
            .await
            .unwrap();

        alice_proto.refresh_cache().await.unwrap();
        let before = alice_proto
            .cached_events_for_pair_with_peer(&carol_id)
            .await
            .expect("the co-member has a cached advertisement");
        assert!(
            !advertises_prekey_of(&before, bob_identifier),
            "precondition: Bob is not pickable for the document's group yet"
        );

        // The material lands: Bob joins the group the document names.
        alice_kh
            .add_member(
                bob_identifier,
                MemberedId::GroupId(group_id),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        alice_proto.refresh_cache().await.unwrap();
        let after = alice_proto
            .cached_events_for_pair_with_peer(&carol_id)
            .await
            .expect("the co-member still has a cached advertisement");
        assert!(
            advertises_prekey_of(&after, bob_identifier),
            "the refreshed advertisement must carry the newly pickable delegate's key ops"
        );
    }

    /// Helper to create a test protocol instance.
    async fn make_protocol() -> (TestProtocol, SimpleKeyhive) {
        let keyhive = make_keyhive().await;
        let peer_id = keyhive_peer_id(&keyhive);
        let cc = keyhive.generate_contact_card().await.unwrap();
        let storage = MemoryKeyhiveStorage::new();
        let shared = Arc::new(keyhive.clone());
        let protocol = TestProtocol::new(shared, storage, peer_id, cc);
        (protocol, keyhive)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sign_and_verify_roundtrip() {
        let (protocol, _keyhive) = make_protocol().await;
        let peer_id = protocol.peer_id.clone();

        // Create a peer so we can send to them
        let other = make_keyhive().await;
        let other_id = keyhive_peer_id(&other);

        let (conn_to_other, conn_to_us) = create_channel_pair(peer_id.clone(), &other_id);
        protocol.add_peer(other_id.clone(), conn_to_other).await;

        // Send a message
        let message = Message::RequestContactCard {
            sender_id: peer_id.clone(),
            target_id: other_id.clone(),
            request_id: RequestId {
                requestor: peer_id.clone(),
                nonce: 0,
            },
        };
        protocol
            .sign_and_send(&other_id, message, true)
            .await
            .unwrap();

        // Read the signed message from the channel
        let signed_msg = conn_to_us.inbound_rx.recv().await.unwrap();

        // Verify and decode
        let verified = signed_msg.verify(&peer_id).unwrap();
        let decoded_msg: Message = cbor_deserialize(&verified.payload).unwrap();

        // The decoded message should match
        assert!(matches!(decoded_msg, Message::RequestContactCard { .. }));
        assert_eq!(decoded_msg.sender_id(), &peer_id);
        assert_eq!(decoded_msg.target_id(), &other_id);

        // Contact card should be present since we set include_contact_card=true
        assert!(verified.contact_card.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_rejects_wrong_sender() {
        let (protocol, _keyhive) = make_protocol().await;
        let peer_id = protocol.peer_id.clone();

        let other = make_keyhive().await;
        let other_id = keyhive_peer_id(&other);

        let (conn_to_other, conn_to_us) = create_channel_pair(peer_id.clone(), &other_id);
        protocol.add_peer(other_id.clone(), conn_to_other).await;

        let message = Message::RequestContactCard {
            sender_id: peer_id.clone(),
            target_id: other_id.clone(),
            request_id: RequestId {
                requestor: peer_id.clone(),
                nonce: 0,
            },
        };
        protocol
            .sign_and_send(&other_id, message, false)
            .await
            .unwrap();

        let signed_msg = conn_to_us.inbound_rx.recv().await.unwrap();

        // Try to verify as if it came from the wrong sender
        let wrong_sender = keyhive_peer_id(&make_keyhive().await);
        let result = signed_msg.verify(&wrong_sender);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::error::VerificationError::SenderMismatch { .. }),
            "expected SenderMismatch, got: {err:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_message_rejects_forged_inner_sender_id() {
        // Alice signs a message that *claims* (via the inner Message
        // payload's `sender_id`) to come from Bob. The signature
        // verifies (Alice really did sign), but the cross-check
        // between `verified.sender_id` (from the signing key) and the
        // inner payload's `sender_id` should reject.
        let (alice, _alice_kh) = make_protocol().await;
        let alice_id = alice.peer_id.clone();
        let bob_id = keyhive_peer_id(&make_keyhive().await);
        let (conn_alice_to_bob, _conn_bob_to_alice) =
            create_channel_pair(alice_id.clone(), &bob_id);
        alice.add_peer(bob_id.clone(), conn_alice_to_bob).await;

        // Construct a Message whose inner sender_id is Bob, even though
        // Alice will sign it.
        let forged = Message::RequestContactCard {
            sender_id: bob_id.clone(),
            target_id: alice_id.clone(),
            request_id: RequestId {
                requestor: bob_id.clone(),
                nonce: 0,
            },
        };
        let payload = cbor_serialize(&forged).expect("forged payload should serialize");
        let signed: keyhive_crypto::signed::Signed<Vec<u8>> = {
            let kh = alice.keyhive.clone();
            kh.try_sign(payload).await.expect("alice signs")
        };
        let signed_bytes = bincode::serialize(&signed).expect("bincode encode");
        let signed_msg = SignedMessage::new(signed_bytes);

        let err = alice
            .handle_message(&alice_id, signed_msg, None)
            .await
            .expect_err("should reject forged inner sender_id");
        assert!(
            matches!(
                err,
                ProtocolError::Verification(VerificationError::SenderMismatch { .. })
            ),
            "expected SenderMismatch, got: {err:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_rejects_tampered_message() {
        let (protocol, _keyhive) = make_protocol().await;
        let peer_id = protocol.peer_id.clone();

        let other = make_keyhive().await;
        let other_id = keyhive_peer_id(&other);

        let (conn_to_other, conn_to_us) = create_channel_pair(peer_id.clone(), &other_id);
        protocol.add_peer(other_id.clone(), conn_to_other).await;

        let message = Message::RequestContactCard {
            sender_id: peer_id.clone(),
            target_id: other_id.clone(),
            request_id: RequestId {
                requestor: peer_id.clone(),
                nonce: 0,
            },
        };
        protocol
            .sign_and_send(&other_id, message, false)
            .await
            .unwrap();

        let mut signed_msg = conn_to_us.inbound_rx.recv().await.unwrap();

        // Tamper with the signed bytes
        if let Some(byte) = signed_msg.signed_bytes_mut().last_mut() {
            *byte ^= 0xFF;
        }

        let result = signed_msg.verify(&peer_id);
        assert!(result.is_err(), "tampered message should fail verification");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peer_management() {
        let (protocol, _keyhive) = make_protocol().await;
        let peer_id = protocol.peer_id.clone();

        let peer1 = keyhive_peer_id(&make_keyhive().await);
        let peer2 = keyhive_peer_id(&make_keyhive().await);

        let (conn1, _) = create_channel_pair(peer_id.clone(), &peer1);
        let (conn2, _) = create_channel_pair(peer_id.clone(), &peer2);

        assert!(
            protocol.peer_ids().await.is_empty(),
            "no peers before any add"
        );

        protocol.add_peer(peer1.clone(), conn1).await;
        protocol.add_peer(peer2.clone(), conn2).await;
        assert_eq!(protocol.peer_ids().await.len(), 2);

        protocol.remove_peer(&peer1).await;
        let remaining = protocol.peer_ids().await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], peer2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_requests_contact_card_for_unknown_peer() {
        let (protocol, _keyhive) = make_protocol().await;
        let peer_id = protocol.peer_id.clone();

        // Create a peer that our keyhive doesn't know about
        let other = make_keyhive().await;
        let other_id = keyhive_peer_id(&other);

        let (conn_to_other, conn_to_us) = create_channel_pair(peer_id.clone(), &other_id);
        protocol.add_peer(other_id.clone(), conn_to_other).await;

        // Sync should request a contact card since we don't know the peer
        protocol.sync_keyhive(Some(&other_id)).await.unwrap();

        // Verify we got a RequestContactCard
        let signed_msg = conn_to_us.inbound_rx.recv().await.unwrap();
        let verified = signed_msg.verify(&peer_id).unwrap();
        let decoded: Message = cbor_deserialize(&verified.payload).unwrap();

        assert!(matches!(decoded, Message::RequestContactCard { .. }));
        // Should include our contact card so the peer can learn about us
        assert!(verified.contact_card.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn contact_card_exchange_flow() {
        // Alice doesn't know Bob, and vice versa
        let (alice_proto, _alice_kh) = make_protocol().await;
        let alice_id = alice_proto.peer_id.clone();

        let (bob_proto, _bob_kh) = make_protocol().await;
        let bob_id = bob_proto.peer_id.clone();

        // Set up channels
        let (alice_conn, bob_conn) = create_channel_pair(alice_id.clone(), &bob_id);
        alice_proto
            .add_peer(bob_id.clone(), alice_conn.clone())
            .await;
        bob_proto.add_peer(alice_id.clone(), bob_conn.clone()).await;

        // Alice tries to sync with Bob (she doesn't know him)
        alice_proto.sync_keyhive(Some(&bob_id)).await.unwrap();

        // Alice should have sent RequestContactCard
        let signed_msg1 = bob_conn.inbound_rx.recv().await.unwrap();

        let verified1 = signed_msg1.clone().verify(&alice_id).unwrap();
        let decoded1: Message = cbor_deserialize(&verified1.payload).unwrap();
        assert!(
            matches!(decoded1, Message::RequestContactCard { .. }),
            "alice should request bob's contact card"
        );

        // Bob handles alice's RequestContactCard
        bob_proto
            .handle_message(&alice_id, signed_msg1, None)
            .await
            .unwrap();

        // Bob should have sent MissingContactCard back
        let signed_msg2 = alice_conn.inbound_rx.recv().await.unwrap();

        let verified2 = signed_msg2.clone().verify(&bob_id).unwrap();
        let decoded2: Message = cbor_deserialize(&verified2.payload).unwrap();
        assert!(
            matches!(decoded2, Message::MissingContactCard { .. }),
            "bob should respond with MissingContactCard"
        );
        // Bob's response should include his contact card
        assert!(
            verified2.contact_card.is_some(),
            "bob's response should include contact card"
        );

        // Alice handles Bob's MissingContactCard (which includes Bob's contact card)
        // This should trigger Alice to initiate a sync
        alice_proto
            .handle_message(&bob_id, signed_msg2, None)
            .await
            .unwrap();

        // Alice should now have sent either a SyncRequest or another RequestContactCard
        // to Bob (depending on whether she successfully ingested Bob's CC)
        let signed_msg3 = bob_conn.inbound_rx.recv().await.unwrap();
        let verified3 = signed_msg3.verify(&alice_id).unwrap();
        let decoded3: Message = cbor_deserialize(&verified3.payload).unwrap();

        // After ingesting Bob's contact card, Alice should send a SyncRequest
        assert!(
            matches!(decoded3, Message::SyncRequest { .. }),
            "alice should now be able to send a sync request, got: {decoded3:?}"
        );
    }

    /// A peer the local keyhive has never seen must not look like one it knows.
    ///
    /// This is the protocol-facing half of the cache distinction. Both cases serve the
    /// public set, so the pair lookup used to answer both with the same map and callers
    /// inferred "unknown" from emptiness — which never held, so the contact-card request
    /// never fired and a peer's key material was never delivered.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unknown_peer_has_no_cached_pair_while_a_known_peer_does() {
        let (alice_proto, alice_kh) = make_protocol().await;

        // Bob is known: alice holds his card, and therefore his individual. The pair
        // still shares nothing private, so the served set is only the public set — the
        // case that used to be indistinguishable from a peer we have never met.
        let (bob_proto, bob_kh) = make_protocol().await;
        let bob_id = bob_proto.peer_id.clone();
        let bob_cc = bob_kh.generate_contact_card().await.unwrap();
        alice_kh.receive_contact_card(&bob_cc).await.unwrap();
        alice_proto.refresh_cache().await.unwrap();
        assert!(
            alice_proto
                .cached_events_for_pair_with_peer(&bob_id)
                .await
                .is_some(),
            "a peer whose identity the hive holds has a cached pair, even when the \
             served set is public-only"
        );

        // Carol is a peer alice's keyhive has never seen: no projection exists for her,
        // and the cache must say so rather than answering with the public set.
        let carol_kh = make_keyhive().await;
        let carol_id = keyhive_peer_id(&carol_kh);
        assert!(
            alice_proto
                .cached_events_for_pair_with_peer(&carol_id)
                .await
                .is_none(),
            "an unknown peer must not be presented as a cached pair: that is the signal \
             the contact-card request turns on"
        );
    }

    /// A peer we already know must get our advertisement, not a contact-card request.
    ///
    /// The other half of the distinction: the fix must not over-correct into asking a
    /// known peer for credentials we already hold.
    #[tokio::test(flavor = "current_thread")]
    async fn sync_sends_a_request_to_a_known_peer_rather_than_asking_for_its_card() {
        let (alice_proto, alice_kh) = make_protocol().await;
        let alice_id = alice_proto.peer_id.clone();

        let (bob_proto, bob_kh) = make_protocol().await;
        let bob_id = bob_proto.peer_id.clone();
        let bob_cc = bob_kh.generate_contact_card().await.unwrap();
        alice_kh.receive_contact_card(&bob_cc).await.unwrap();

        let (alice_conn, bob_conn) = create_channel_pair(alice_id.clone(), &bob_id);
        alice_proto.add_peer(bob_id.clone(), alice_conn).await;

        alice_proto.sync_keyhive(Some(&bob_id)).await.unwrap();

        let signed_msg = bob_conn.inbound_rx.recv().await.unwrap();
        let verified = signed_msg.verify(&alice_id).unwrap();
        let decoded: Message = cbor_deserialize(&verified.payload).unwrap();
        assert!(
            matches!(decoded, Message::SyncRequest { .. }),
            "a known peer must be sent a sync request, not a contact-card ask: {decoded:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_request_response_flow_with_known_peers() {
        // Set up Alice and Bob who know each other
        let (alice_proto, alice_kh) = make_protocol().await;
        let alice_id = alice_proto.peer_id.clone();

        let (bob_proto, bob_kh) = make_protocol().await;
        let bob_id = bob_proto.peer_id.clone();

        // Exchange contact cards at the keyhive level
        let alice_cc = alice_kh.generate_contact_card().await.unwrap();
        let bob_cc = bob_kh.generate_contact_card().await.unwrap();
        alice_kh.receive_contact_card(&bob_cc).await.unwrap();
        bob_kh.receive_contact_card(&alice_cc).await.unwrap();

        // Set up channels
        let (alice_conn, bob_conn) = create_channel_pair(alice_id.clone(), &bob_id);
        alice_proto
            .add_peer(bob_id.clone(), alice_conn.clone())
            .await;
        bob_proto.add_peer(alice_id.clone(), bob_conn.clone()).await;

        // Alice initiates sync
        alice_proto.sync_keyhive(Some(&bob_id)).await.unwrap();

        // Read Alice's SyncRequest from the channel
        let signed_msg1 = bob_conn.inbound_rx.recv().await.unwrap();
        let verified1 = signed_msg1.clone().verify(&alice_id).unwrap();
        let decoded1: Message = cbor_deserialize(&verified1.payload).unwrap();

        assert!(
            matches!(decoded1, Message::SyncRequest { .. }),
            "alice should send SyncRequest when she knows bob"
        );

        // Bob handles the SyncRequest
        bob_proto
            .handle_message(&alice_id, signed_msg1, None)
            .await
            .unwrap();

        // Bob should respond with SyncResponse
        let signed_msg2 = alice_conn.inbound_rx.recv().await.unwrap();
        let verified2 = signed_msg2.clone().verify(&bob_id).unwrap();
        let decoded2: Message = cbor_deserialize(&verified2.payload).unwrap();

        assert!(
            matches!(decoded2, Message::SyncResponse { .. }),
            "bob should respond with SyncResponse, got: {decoded2:?}"
        );

        // Alice handles the SyncResponse
        alice_proto
            .handle_message(&bob_id, signed_msg2, None)
            .await
            .unwrap();

        // Depending on set differences, Alice might send SyncOps or nothing
        // At minimum, the protocol should complete without errors
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_bidirectional_sync() {
        // Create Alice and Bob, exchange contact cards, then sync both ways
        let alice_kh = make_keyhive().await;
        let bob_kh = make_keyhive().await;

        let alice_id = keyhive_peer_id(&alice_kh);
        let bob_id = keyhive_peer_id(&bob_kh);

        // Exchange contact cards
        let alice_cc = alice_kh.generate_contact_card().await.unwrap();
        let bob_cc = bob_kh.generate_contact_card().await.unwrap();
        alice_kh.receive_contact_card(&bob_cc).await.unwrap();
        bob_kh.receive_contact_card(&alice_cc).await.unwrap();

        let alice_storage = MemoryKeyhiveStorage::new();
        let bob_storage = MemoryKeyhiveStorage::new();

        let alice_shared = Arc::new(alice_kh);
        let bob_shared = Arc::new(bob_kh);

        let (alice_conn, bob_conn) = create_channel_pair(alice_id.clone(), &bob_id);

        let alice_proto = TestProtocol::new(
            alice_shared.clone(),
            alice_storage.clone(),
            alice_id.clone(),
            alice_cc.clone(),
        );
        let bob_proto = TestProtocol::new(
            bob_shared.clone(),
            bob_storage.clone(),
            bob_id.clone(),
            bob_cc.clone(),
        );

        alice_proto
            .add_peer(bob_id.clone(), alice_conn.clone())
            .await;
        bob_proto.add_peer(alice_id.clone(), bob_conn.clone()).await;

        // Alice → Bob sync
        alice_proto.sync_keyhive(Some(&bob_id)).await.unwrap();

        // Forward SyncRequest to Bob
        let a_to_b_rx = bob_conn.inbound_rx.clone();
        let b_to_a_rx = alice_conn.inbound_rx.clone();

        let sync_request = a_to_b_rx.recv().await.unwrap();
        bob_proto
            .handle_message(&alice_id, sync_request, None)
            .await
            .unwrap();

        // Forward SyncResponse to Alice
        let sync_response = b_to_a_rx.recv().await.unwrap();
        alice_proto
            .handle_message(&bob_id, sync_response, None)
            .await
            .unwrap();

        // If Alice sent SyncOps, forward those too
        if let Ok(sync_ops) = a_to_b_rx.try_recv() {
            bob_proto
                .handle_message(&alice_id, sync_ops, None)
                .await
                .unwrap();
        }

        // Handle any confirmation messages before next round
        while let Ok(msg) = a_to_b_rx.try_recv() {
            bob_proto
                .handle_message(&alice_id, msg, None)
                .await
                .unwrap();
        }
        while let Ok(msg) = b_to_a_rx.try_recv() {
            alice_proto
                .handle_message(&bob_id, msg, None)
                .await
                .unwrap();
        }

        // Now Bob → Alice sync
        bob_proto.sync_keyhive(Some(&alice_id)).await.unwrap();

        let sync_request2 = b_to_a_rx.recv().await.unwrap();
        alice_proto
            .handle_message(&bob_id, sync_request2, None)
            .await
            .unwrap();

        let sync_response2 = a_to_b_rx.recv().await.unwrap();
        bob_proto
            .handle_message(&alice_id, sync_response2, None)
            .await
            .unwrap();

        if let Ok(sync_ops2) = b_to_a_rx.try_recv() {
            alice_proto
                .handle_message(&bob_id, sync_ops2, None)
                .await
                .unwrap();
        }

        // Handle any remaining confirmation messages
        while let Ok(msg) = a_to_b_rx.try_recv() {
            bob_proto
                .handle_message(&alice_id, msg, None)
                .await
                .unwrap();
        }
        while let Ok(msg) = b_to_a_rx.try_recv() {
            alice_proto
                .handle_message(&bob_id, msg, None)
                .await
                .unwrap();
        }

        // After bidirectional sync, both should have the same pending state
        let alice_pending = {
            let kh = alice_shared.clone();
            kh.pending_event_hashes().await
        };
        let bob_pending = {
            let kh = bob_shared.clone();
            kh.pending_event_hashes().await
        };

        // Both should have the same pending hashes (possibly empty)
        assert_eq!(
            alice_pending, bob_pending,
            "after bidirectional sync, pending hashes should match"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_skips_self_peer() {
        let (protocol, _keyhive) = make_protocol().await;
        let peer_id = protocol.peer_id.clone();

        // Add ourselves as a peer (edge case)
        let (conn, _) = create_channel_pair(peer_id.clone(), &peer_id);
        protocol.add_peer(peer_id.clone(), conn).await;

        // Sync should skip ourselves
        protocol.sync_keyhive(None).await.unwrap();

        // No messages should have been sent (we skipped ourselves)
        // The protocol should complete without error
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ingest_events_persists_individual_files() {
        // Event ingestion persists each event; archive creation belongs to
        // periodic compaction rather than the receive path.
        let alice_kh = make_keyhive().await;
        let bob_kh = make_keyhive().await;
        let alice_id = keyhive_peer_id(&alice_kh);
        let bob_id = keyhive_peer_id(&bob_kh);

        let alice_cc = alice_kh.generate_contact_card().await.unwrap();
        let bob_cc = bob_kh.generate_contact_card().await.unwrap();
        alice_kh.receive_contact_card(&bob_cc).await.unwrap();
        bob_kh.receive_contact_card(&alice_cc).await.unwrap();

        let storage = MemoryKeyhiveStorage::new();
        let shared = Arc::new(alice_kh.clone());
        let protocol = TestProtocol::new(shared, storage.clone(), alice_id.clone(), alice_cc);

        let pair = protocol
            .get_events_for_agent(&bob_id)
            .await
            .unwrap()
            .unwrap();
        let event_bytes: Vec<Arc<[u8]>> = pair.values().map(Dupe::dupe).collect();
        assert!(!event_bytes.is_empty(), "the peer pair has events to send");

        protocol.ingest_events(&event_bytes, None).await.unwrap();

        let archives = crate::storage_ops::load_archives::<[u8; 32], _, Local>(&storage)
            .await
            .unwrap();
        let events = crate::storage_ops::load_events::<[u8; 32], _, Local>(&storage)
            .await
            .unwrap();
        assert!(archives.is_empty(), "ingestion does not create archives");
        assert_eq!(
            events.len(),
            event_bytes.len(),
            "expected one event file per ingested event"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ingest_events_triggers_recovery_only_when_enabled() {
        // `other` creates a group, then adds a member. The add-member
        // delegation depends on the group-creation delegation, so feeding
        // only the former to a fresh keyhive leaves it pending.
        //
        // Storage holds `other`'s full archive. A pending event should
        // trigger a reload from storage only when recovery is enabled. Check
        // the recovered grant itself, and that dependency replay reports the
        // formerly pending delegation through the incorporation hook.
        let other = make_keyhive().await;
        let member = make_keyhive().await;
        let member_id = keyhive_peer_id(&member);
        let member_cc = member.generate_contact_card().await.unwrap();
        other.receive_contact_card(&member_cc).await.unwrap();

        let other_id = keyhive_peer_id(&other);
        let other_cc = other.generate_contact_card().await.unwrap();
        let other_proto = TestProtocol::new(
            Arc::new(other.clone()),
            MemoryKeyhiveStorage::new(),
            other_id.clone(),
            other_cc,
        );

        // Group-creation delegation.
        let group = other.generate_group(vec![]).await.unwrap();
        let group_id = group;
        let before_add_events = other_proto
            .get_events_for_agent(&other_id)
            .await
            .unwrap()
            .expect("other resolves to an agent");
        let before_add: Vec<EventHash> = before_add_events.keys().copied().collect();
        assert!(
            !before_add.is_empty(),
            "group creation should produce a delegation"
        );

        // Add-member delegation, which depends on the group-creation one.
        // Restrict `dependent` to the delegation itself: since keyhive 0.6.0
        // `add_member` may also emit an independent prekey op (e.g. a rotation)
        // that is admissible without the group-creation dependency being
        // present, which would defeat the pending-to-active premise below.
        let agent = other
            .get_agent(member_id.to_identifier().unwrap())
            .await
            .unwrap();
        other
            .add_member(agent.id(), MemberedId::GroupId(group_id), Access::Read, &[])
            .await
            .unwrap();
        let dependent: Vec<Arc<[u8]>> = other_proto
            .get_events_for_agent(&other_id)
            .await
            .unwrap()
            .expect("other resolves to an agent")
            .into_iter()
            .filter(|(hash, _)| !before_add.contains(hash))
            .filter(|(_, bytes)| {
                bincode_deserialize::<StaticEvent<[u8; 32]>>(bytes)
                    .is_ok_and(|event| matches!(event, StaticEvent::Delegated(_)))
            })
            .map(|(_, bytes)| bytes)
            .collect();
        assert!(
            !dependent.is_empty(),
            "add_member should introduce a dependent delegation"
        );
        let dependent_hashes: BTreeSet<EventHash> = dependent
            .iter()
            .map(|bytes| {
                let event: StaticEvent<[u8; 32]> = bincode_deserialize(bytes).unwrap();
                *Digest::hash(&event).raw.as_bytes()
            })
            .collect();

        // Persist the dependent first, then replay its dependencies. The
        // dependent's pending-to-active transition must cross the same hook.
        let dst_resolution = make_keyhive().await;
        let sink_resolution = RecordingSink::new();
        let proto_resolution = TestProtocol::new(
            Arc::new(dst_resolution.clone()),
            MemoryKeyhiveStorage::new(),
            keyhive_peer_id(&dst_resolution),
            dst_resolution.generate_contact_card().await.unwrap(),
        )
        .with_durable_incorporation_sink(sink_resolution.clone());
        proto_resolution
            .ingest_events(&dependent, None)
            .await
            .unwrap();
        assert!(sink_resolution.admitted.lock().await.is_empty());
        // Replay the complete prerequisite set, including the newly named member
        // and any prekey material emitted alongside the delegation.
        let dependencies: Vec<Arc<[u8]>> = other_proto
            .get_events_for_agent(&other_id)
            .await
            .unwrap()
            .unwrap()
            .into_iter()
            .filter(|(hash, _)| !dependent_hashes.contains(hash))
            .map(|(_, bytes)| bytes)
            .collect();
        proto_resolution
            .ingest_events(&dependencies, None)
            .await
            .unwrap();
        assert!(
            dependent_hashes.is_subset(&*sink_resolution.admitted.lock().await),
            "the formerly pending delegation must cross the incorporation hook"
        );

        // Store `other`'s full archive so recovery has deps to reload.
        let storage = MemoryKeyhiveStorage::new();
        let storage_id = crate::storage::StorageHash::new([9u8; 32]);
        let archive = other.into_archive().await;
        crate::storage_ops::save_keyhive_archive::<_, _, Local>(&storage, storage_id, &archive)
            .await
            .unwrap();

        // Recovery disabled: the pending event ingests nothing and no
        // reload happens, so the op count is unchanged.
        let dst_off = make_keyhive().await;
        let proto_off = TestProtocol::new(
            Arc::new(dst_off.clone()),
            storage.clone(),
            keyhive_peer_id(&dst_off),
            dst_off.generate_contact_card().await.unwrap(),
        );
        let before_off = proto_off.total_ops().await;
        proto_off.ingest_events(&dependent, None).await.unwrap();
        assert_eq!(
            proto_off.total_ops().await,
            before_off,
            "with recovery off, a pending event must not change the op count"
        );

        // Recovery enabled: reloading the archive restores the member grant.
        let dst_on = make_keyhive().await;
        let proto_on = TestProtocol::new(
            Arc::new(dst_on.clone()),
            storage.clone(),
            keyhive_peer_id(&dst_on),
            dst_on.generate_contact_card().await.unwrap(),
        )
        .with_storage_recovery();
        proto_on.ingest_events(&dependent, None).await.unwrap();
        let recovered_members = dst_on.reachable_members(group_id).await;
        assert_eq!(
            recovered_members
                .get(&member_id.to_identifier().unwrap())
                .copied(),
            Some(Access::Read),
            "archive recovery must restore the dependent member grant"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_sync_response_serves_requested_from_cached_pair() {
        // Regression test for the byte-fetch divergence between ARK and
        // Subduction (see
        // `~/dev/prg/sync-server/keyhive-sync-protocol-ts-vs-rust-comparison.md`).
        //
        // Pre-fix, `handle_sync_response` ignored the protocol's
        // cached pair entirely and walked our own active agent's
        // reachable set via `sync_events_for_agent`. That silently
        // dropped any hash advertised via public-agent reachability,
        // any hash whose direct reachability had since narrowed
        // (revocation/expansion), and any hash present in the cached
        // bytes store but not in the live walk, leaving the requesting
        // peer stuck on dependent pending events.
        //
        // We exercise the request-snapshot path directly with a synthetic hash
        // and bytes that are not in Alice's live keyhive at all. The response
        // must use the exact immutable pair snapshot retained when the request
        // advertised that hash, not whichever periodic-cache generation is
        // current when the response arrives.
        let TwoPeerHarness {
            alice_proto,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        let synthetic_hash: EventHash = [0xAB; 32];
        let synthetic_bytes: EventBytes = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let mut cached_pair = AgentHashMap::new();
        cached_pair.insert(synthetic_hash, synthetic_bytes.clone().into());

        let request_id = RequestId {
            requestor: alice_id.clone(),
            nonce: 42,
        };
        alice_proto.outbound_requests.lock().await.insert(
            request_id.clone(),
            OutboundRequest {
                peer: bob_id.clone(),
                advertised_events: Arc::new(cached_pair),
            },
        );

        // SyncResponse from Bob asking Alice for the synthetic hash.
        let msg = Message::SyncResponse {
            sender_id: bob_id.clone(),
            request_id,
            target_id: alice_id.clone(),
            requested: vec![synthetic_hash],
            found: vec![],
            sync_responder_total: 0,
            sync_requester_total: 0,
        };

        alice_proto
            .handle_sync_response(msg, None)
            .await
            .expect("alice handle_sync_response with cached pair");

        // Drain Bob's inbound channel and verify Alice sent SyncOps
        // carrying the cached bytes.
        let signed = bob_conn
            .inbound_rx
            .try_recv()
            .expect("bob should have received a SyncOps from alice");
        let verified = signed
            .verify(&alice_id)
            .expect("alice's signature verifies");
        let outbound: Message =
            cbor_deserialize(&verified.payload).expect("decode alice's outbound payload");

        let Message::SyncOps { ops, .. } = outbound else {
            panic!(
                "expected SyncOps from alice (carrying cached bytes), got: {:?}",
                outbound.variant_name()
            );
        };
        assert_eq!(
            ops.len(),
            1,
            "alice should have served exactly one op (the synthetic one)"
        );
        assert_eq!(
            ops[0].as_ref(),
            synthetic_bytes.as_slice(),
            "served bytes should match the cached pair entry, \
             not anything from a live keyhive walk"
        );

        // And Bob shouldn't have received anything else.
        assert!(
            bob_conn.inbound_rx.try_recv().is_err(),
            "no further messages expected from alice"
        );
        // Symmetric: alice didn't loop a message to herself.
        assert!(
            alice_conn.inbound_rx.try_recv().is_err(),
            "no inbound message expected on alice's side"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_message_rejects_unsigned_junk() {
        let (protocol, _keyhive) = make_protocol().await;

        let fake_sender = keyhive_peer_id(&make_keyhive().await);

        // Create a SignedMessage with junk data
        let junk = SignedMessage::new(vec![0xFF, 0xFE, 0xFD]);

        let result = protocol.handle_message(&fake_sender, junk, None).await;
        assert!(result.is_err(), "junk data should fail verification");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn compact_via_protocol() {
        let (protocol, keyhive) = make_protocol().await;
        let storage_id = crate::storage::StorageHash::new([1u8; 32]);

        // Save an archive to storage via storage_ops
        let archive = keyhive.into_archive().await;
        crate::storage_ops::save_keyhive_archive::<_, _, Local>(
            &MemoryKeyhiveStorage::new(),
            storage_id,
            &archive,
        )
        .await
        .unwrap();

        // Compact via protocol should work
        let result = protocol.compact(storage_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn boot_reconciliation_reports_crash_window_once() {
        let keyhive = make_keyhive().await;
        let peer_id = keyhive_peer_id(&keyhive);
        let cc = keyhive.generate_contact_card().await.unwrap();
        // The group's founding event is the precondition for the crash window below;
        // the handle itself is `Copy` and holds no lock, so the call is the whole effect.
        keyhive.generate_group(vec![]).await.unwrap();

        let storage = MemoryKeyhiveStorage::new();
        // Crash window: an incorporated founding event was persisted to the
        // WAL, but admission never committed.
        let card = keyhive.get_existing_contact_card().await;
        let event: StaticEvent<[u8; 32]> = match card.op() {
            KeyOp::Add(op) => StaticEvent::PrekeysExpanded(Box::new(op.as_ref().clone())),
            KeyOp::Rotate(op) => StaticEvent::PrekeyRotated(Box::new(op.as_ref().clone())),
        };
        let hash: EventHash = *Digest::hash(&event).raw.as_bytes();
        let event_bytes = bincode_serialize(&event).unwrap();
        let (stored_hash, inserted) =
            storage_ops::save_event_bytes::<_, Local>(&storage, event_bytes.clone(), None)
                .await
                .unwrap();
        assert!(inserted);
        assert_eq!(*stored_hash.as_bytes(), hash);

        // Recovery materializes the archive before replaying the retained WAL.
        let archive = keyhive.into_archive().await;
        let storage_id = crate::storage::StorageHash::new([1u8; 32]);
        storage_ops::save_keyhive_archive::<_, _, Local>(&storage, storage_id, &archive)
            .await
            .unwrap();

        let sink = RecordingSink::new();
        sink.unadmitted.lock().await.push((hash, event_bytes, None));
        let protocol = TestProtocol::new(Arc::new(keyhive), storage, peer_id, cc)
            .with_durable_incorporation_sink(sink.clone());

        protocol.ingest_from_storage().await.unwrap();
        assert!(
            sink.admitted.lock().await.contains(&hash),
            "crash-window candidate must be admitted at boot"
        );
        let first_report_count = sink.reports.lock().await.len();
        assert_eq!(first_report_count, 1);

        // Admission committed; a second boot must not re-report.
        sink.unadmitted.lock().await.clear();
        protocol.ingest_from_storage().await.unwrap();
        assert_eq!(
            sink.reports.lock().await.len(),
            first_report_count,
            "duplicate reconciliation must be idempotent"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn boot_reconciliation_skips_pending_candidates() {
        let keyhive = make_keyhive().await;
        let peer_id = keyhive_peer_id(&keyhive);
        let cc = keyhive.generate_contact_card().await.unwrap();

        // A candidate whose dependencies are missing stays pending after
        // replay; it is unadmitted but not incorporated, so it must not be
        // reported. Its admission fires when a later exchange resolves it.
        let remote = make_keyhive().await;
        let remote_doc = remote
            .generate_doc(vec![], nonempty![[1u8; 32]])
            .await
            .unwrap();
        let pending_operation = {
            let document = remote
                .get_document(remote_doc)
                .await
                .expect("generated document is present");
            let document = document.lock().await;
            document
                .cgka_ops()
                .unwrap()
                .iter()
                .flat_map(|epoch| epoch.iter())
                .next()
                .unwrap()
                .as_ref()
                .clone()
        };
        let pending_event: StaticEvent<[u8; 32]> =
            StaticEvent::CgkaOperation(Box::new(pending_operation));
        let pending_hash: EventHash = *Digest::hash(&pending_event).raw.as_bytes();
        let pending_bytes = bincode_serialize(&pending_event).unwrap();
        let source = Some(keyhive_peer_id(&remote));
        let storage = MemoryKeyhiveStorage::new();
        storage_ops::save_event_bytes::<_, Local>(&storage, pending_bytes.clone(), source.clone())
            .await
            .unwrap();

        let sink = RecordingSink::new();
        sink.unadmitted
            .lock()
            .await
            .push((pending_hash, pending_bytes, source));
        let protocol = TestProtocol::new(Arc::new(keyhive), storage, peer_id, cc)
            .with_durable_incorporation_sink(sink.clone());
        protocol.ingest_from_storage().await.unwrap();
        assert!(
            sink.admitted.lock().await.is_empty(),
            "pending candidates must not be admitted"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn boot_reconciliation_empty_diff_short_circuits() {
        let keyhive = make_keyhive().await;
        let sink = RecordingSink::new();
        let protocol = TestProtocol::new(
            Arc::new(keyhive.clone()),
            MemoryKeyhiveStorage::new(),
            keyhive_peer_id(&keyhive),
            keyhive.generate_contact_card().await.unwrap(),
        )
        .with_durable_incorporation_sink(sink.clone());

        protocol.ingest_from_storage().await.unwrap();

        assert_eq!(
            sink.unadmitted_queries.load(AtomicOrdering::SeqCst),
            1,
            "boot must issue exactly one WAL-minus-admission query"
        );
        assert!(sink.reports.lock().await.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn boot_reconciliation_rejects_unknown_candidate() {
        let keyhive = make_keyhive().await;
        let remote = make_keyhive().await;
        let other = make_keyhive().await;
        let remote_card = remote.get_existing_contact_card().await;
        keyhive.receive_contact_card(&remote_card).await.unwrap();
        let other_card = other.get_existing_contact_card().await;
        let (KeyOp::Add(remote_add), KeyOp::Add(other_add)) = (remote_card.op(), other_card.op())
        else {
            panic!("fresh contact cards must contain add-key operations");
        };
        let mut invalid_add = remote_add.as_ref().clone();
        invalid_add.signature = other_add.signature;
        let event: StaticEvent<[u8; 32]> = StaticEvent::PrekeysExpanded(Box::new(invalid_add));
        let hash = *Digest::hash(&event).raw.as_bytes();
        let bytes = bincode_serialize(&event).unwrap();
        let source = Some(keyhive_peer_id(&remote));
        let storage = MemoryKeyhiveStorage::new();
        storage_ops::save_event_bytes::<_, Local>(&storage, bytes.clone(), source.clone())
            .await
            .unwrap();
        let sink = RecordingSink::new();
        sink.unadmitted.lock().await.push((hash, bytes, source));
        let protocol = TestProtocol::new(
            Arc::new(keyhive.clone()),
            storage,
            keyhive_peer_id(&keyhive),
            keyhive.generate_contact_card().await.unwrap(),
        )
        .with_durable_incorporation_sink(sink);

        let error = protocol.ingest_from_storage().await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("neither pending nor incorporated"),
            "unexpected recovery error: {error}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_and_remote_events_share_durable_incorporation_hook() {
        let keyhive = make_keyhive().await;
        let peer_id = keyhive_peer_id(&keyhive);
        let storage = MemoryKeyhiveStorage::new();
        let sink = RecordingSink::new();
        let protocol = TestProtocol::new(
            Arc::new(keyhive.clone()),
            storage,
            peer_id,
            keyhive.generate_contact_card().await.unwrap(),
        )
        .with_durable_incorporation_sink(sink.clone());

        keyhive.generate_group(vec![]).await.unwrap();
        let local_events = protocol
            .all_agent_events(&BTreeSet::new())
            .await
            .unwrap()
            .event_data
            .values()
            .map(|bytes| bincode_deserialize(bytes).unwrap())
            .collect();
        protocol.persist_local_events(local_events).await.unwrap();

        let remote = make_keyhive().await;
        let remote_id = keyhive_peer_id(&remote);
        protocol
            .ingest_contact_card(
                &remote.generate_contact_card().await.unwrap(),
                Some(remote_id.clone()),
            )
            .await
            .unwrap();

        let reports = sink.reports.lock().await;
        assert!(
            reports
                .iter()
                .any(|(hashes, source)| !hashes.is_empty() && source.is_none())
        );
        assert!(
            reports
                .iter()
                .any(|(hashes, source)| !hashes.is_empty() && source.as_ref() == Some(&remote_id))
        );
    }

    // -----------------------------------------------------------------------
    // Integration tests: divergent ops sync convergence
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn sync_group_membership_converges() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
        } = exchange_contact_cards_and_setup().await;

        // Alice creates a group and adds Bob as a Read member
        let (group_id, bob_individual_id) = {
            let kh = alice_kh.clone();
            let group = kh.generate_group(vec![]).await.unwrap();
            let group_id = group;

            // Get Bob's Individual on Alice's keyhive
            let bob_identifier = bob_id.to_identifier().unwrap();
            let bob_agent = kh.get_agent(bob_identifier).await.unwrap();

            kh.add_member(
                bob_agent.id(),
                MemberedId::GroupId(group_id),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

            let bob_identifier: Identifier = bob_identifier;
            (group_id, bob_identifier)
        };

        // Before sync: Bob should not have the group
        {
            let kh = bob_kh.clone();
            assert!(
                kh.get_group(group_id).await.is_none(),
                "Bob should not have the group before sync"
            );
        }

        // Sync Alice → Bob
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // After sync: Bob should have the group and his membership
        {
            let kh = bob_kh.clone();
            let group = kh.get_group(group_id).await;
            assert!(group.is_some(), "Bob should have the group after sync");

            let members = kh.reachable_members(group_id).await;

            assert!(
                members.contains_key(&bob_individual_id),
                "Bob should be a member of the group"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_document_access_converges() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
        } = exchange_contact_cards_and_setup().await;

        // Alice creates group, adds Bob, creates doc owned by group
        let doc_id = {
            let kh = alice_kh.clone();
            let group = kh.generate_group(vec![]).await.unwrap();
            let group_id = group;

            let bob_identifier = bob_id.to_identifier().unwrap();
            let bob_agent = kh.get_agent(bob_identifier).await.unwrap();

            kh.add_member(
                bob_agent.id(),
                MemberedId::GroupId(group_id),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

            kh.generate_doc(
                vec![Identifier::from(MemberedId::GroupId(group_id))],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap()
        };

        // Before sync: Bob should not have the document
        {
            let kh = bob_kh.clone();
            assert!(
                kh.get_document(doc_id).await.is_none(),
                "Bob should not have the document before sync"
            );
        }

        // Sync Alice → Bob
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // After sync: Bob should have the document and it should be reachable
        {
            let kh = bob_kh.clone();
            let doc = kh.get_document(doc_id).await;
            assert!(doc.is_some(), "Bob should have the document after sync");

            let reachable = kh.reachable_docs().await;
            assert!(
                reachable.contains_key(&doc_id),
                "Bob's reachable docs should include the synced document"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bidirectional_sync_with_divergent_ops_converges() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
        } = exchange_contact_cards_and_setup().await;

        // Alice creates her group and adds Bob
        let alice_group_id = {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await
        };

        // Bob creates his group and adds Alice
        let bob_group_id = {
            let kh = bob_kh.clone();
            create_group_with_read_members(&kh, &[&alice_id]).await
        };

        // Before sync: each peer only has their own group
        {
            let alice = alice_kh.clone();
            assert!(alice.get_group(alice_group_id).await.is_some());
            assert!(
                alice.get_group(bob_group_id).await.is_none(),
                "Alice should not have Bob's group before sync"
            );
        }
        {
            let bob = bob_kh.clone();
            assert!(bob.get_group(bob_group_id).await.is_some());
            assert!(
                bob.get_group(alice_group_id).await.is_none(),
                "Bob should not have Alice's group before sync"
            );
        }

        // Bidirectional sync: Alice → Bob, then Bob → Alice
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;
        run_sync_round(
            &bob_proto,
            &alice_proto,
            &bob_id,
            &alice_id,
            &bob_conn,
            &alice_conn,
        )
        .await;

        // Verify both keyhives have both groups
        {
            let alice = alice_kh.clone();
            assert!(alice.get_group(alice_group_id).await.is_some());
            assert!(alice.get_group(bob_group_id).await.is_some());
        }
        {
            let bob = bob_kh.clone();
            assert!(bob.get_group(alice_group_id).await.is_some());
            assert!(bob.get_group(bob_group_id).await.is_some());
        }

        // Verify membership op counts match
        {
            let alice = alice_kh.clone();
            let bob = bob_kh.clone();

            let alice_self = alice
                .get_agent(alice_id.to_identifier().unwrap())
                .await
                .unwrap();
            let bob_self = bob
                .get_agent(bob_id.to_identifier().unwrap())
                .await
                .unwrap();

            let alice_ops = alice.membership_ops_for_agent(alice_self.id()).await;
            let bob_ops = bob.membership_ops_for_agent(bob_self.id()).await;
            assert_eq!(
                alice_ops.len(),
                bob_ops.len(),
                "membership op counts should match after bidirectional sync"
            );
        }

        // Verify pending state is empty
        {
            let alice = alice_kh.clone();
            let bob = bob_kh.clone();
            assert!(alice.pending_event_hashes().await.is_empty());
            assert!(bob.pending_event_hashes().await.is_empty());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_revocation_propagates() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
        } = exchange_contact_cards_and_setup().await;

        // Alice creates group and adds Bob
        let group_id = {
            let kh = alice_kh.clone();
            let group = kh.generate_group(vec![]).await.unwrap();
            let group_id = group;

            let bob_identifier = bob_id.to_identifier().unwrap();
            let bob_agent = kh.get_agent(bob_identifier).await.unwrap();

            kh.add_member(
                bob_agent.id(),
                MemberedId::GroupId(group_id),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

            group_id
        };

        // Before first sync: Bob should not have the group
        {
            let kh = bob_kh.clone();
            assert!(
                kh.get_group(group_id).await.is_none(),
                "Bob should not have the group before sync"
            );
        }

        // First sync: Alice → Bob — Bob gets the group
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // Bob should now have the group, but no revocations yet
        {
            let kh = bob_kh.clone();
            assert!(
                kh.get_group(group_id).await.is_some(),
                "Bob should have the group after first sync"
            );

            let bob_identifier = bob_id.to_identifier().unwrap();
            let bob_agent = kh.get_agent(bob_identifier).await.unwrap();
            let group = kh.get_group(group_id).await.unwrap();
            let revocations = Membered::Group(group_id, group)
                .get_agent_revocations(&bob_agent)
                .await;
            assert!(
                revocations.is_empty(),
                "Bob should have no revocations before Alice revokes"
            );
        }

        // Alice revokes Bob from the group
        {
            let kh = alice_kh.clone();
            let _group = kh.get_group(group_id).await.unwrap();
            let bob_identifier = bob_id.to_identifier().unwrap();

            kh.revoke_member(bob_identifier, true, MemberedId::GroupId(group_id))
                .await
                .unwrap();
        };

        // Second sync: Alice → Bob — Bob receives the revocation
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // Verify Bob's keyhive has the revocation
        {
            let bob = bob_kh.clone();
            let bob_identifier = bob_id.to_identifier().unwrap();
            let bob_agent = bob.get_agent(bob_identifier).await.unwrap();

            let group = bob.get_group(group_id).await.unwrap();
            let revocations = Membered::Group(group_id, group)
                .get_agent_revocations(&bob_agent)
                .await;

            assert!(
                !revocations.is_empty(),
                "Bob should have received the revocation"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn three_peer_transitive_sync() {
        let alice_keyhive = make_keyhive().await;
        let bob_keyhive = make_keyhive().await;
        let carol_keyhive = make_keyhive().await;

        exchange_all_contact_cards(&[&alice_keyhive, &bob_keyhive, &carol_keyhive]).await;

        let alice_id = keyhive_peer_id(&alice_keyhive);
        let bob_id = keyhive_peer_id(&bob_keyhive);
        let carol_id = keyhive_peer_id(&carol_keyhive);

        let (alice_proto, alice_kh, _) = make_protocol_with_shared_keyhive(alice_keyhive).await;
        let (bob_proto, bob_kh, _) = make_protocol_with_shared_keyhive(bob_keyhive).await;
        let (carol_proto, carol_kh, _) = make_protocol_with_shared_keyhive(carol_keyhive).await;

        let (ab_conn_a, ab_conn_b) = create_channel_pair(alice_id.clone(), &bob_id);
        let (bc_conn_b, bc_conn_c) = create_channel_pair(bob_id.clone(), &carol_id);

        alice_proto
            .add_peer(bob_id.clone(), ab_conn_a.clone())
            .await;
        bob_proto
            .add_peer(alice_id.clone(), ab_conn_b.clone())
            .await;
        bob_proto
            .add_peer(carol_id.clone(), bc_conn_b.clone())
            .await;
        carol_proto
            .add_peer(bob_id.clone(), bc_conn_c.clone())
            .await;

        // Alice creates a group and adds Bob and Carol
        let group_id = {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id, &carol_id]).await
        };

        // Before any sync: neither Bob nor Carol has the group
        {
            let kh = bob_kh.clone();
            assert!(
                kh.get_group(group_id).await.is_none(),
                "Bob should not have the group before sync"
            );
        }
        {
            let kh = carol_kh.clone();
            assert!(
                kh.get_group(group_id).await.is_none(),
                "Carol should not have the group before sync"
            );
        }

        // Alice syncs to Bob only
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &ab_conn_a,
            &ab_conn_b,
        )
        .await;

        {
            let kh = bob_kh.clone();
            assert!(
                kh.get_group(group_id).await.is_some(),
                "Bob should have the group after Alice→Bob sync"
            );
        }
        // Carol still shouldn't have it
        {
            let kh = carol_kh.clone();
            assert!(
                kh.get_group(group_id).await.is_none(),
                "Carol should not have the group before Bob→Carol sync"
            );
        }

        // Bob syncs to Carol
        run_sync_round(
            &bob_proto,
            &carol_proto,
            &bob_id,
            &carol_id,
            &bc_conn_b,
            &bc_conn_c,
        )
        .await;

        // Verify Carol got the group and her membership
        {
            let kh = carol_kh.clone();
            let group = kh.get_group(group_id).await;
            assert!(
                group.is_some(),
                "Carol should have the group after transitive sync"
            );

            let carol_identifier = carol_id.to_identifier().unwrap();
            let members = kh.reachable_members(group_id).await;

            assert!(
                members.contains_key(&carol_identifier),
                "Carol should be a member of the group"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_round_produces_confirmation_with_correct_totals() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        // Alice creates a group so there are ops to sync
        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }

        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // Both sides should have established syncpoints with non-zero totals
        // (there are ops from the group creation).
        let alice_sp = alice_proto.syncpoints.lock().await.get(&bob_id);
        let bob_sp = bob_proto.syncpoints.lock().await.get(&alice_id);
        assert!(
            alice_sp.is_some_and(|v| v > 0),
            "alice should have a non-zero syncpoint for bob, got: {alice_sp:?}"
        );
        assert!(
            bob_sp.is_some_and(|v| v > 0),
            "bob should have a non-zero syncpoint for alice, got: {bob_sp:?}"
        );
    }

    /// Reproduces the e2e cross-stack scenario where the responder owns
    /// every op and the requester has none to send back. The responder's
    /// `SyncResponse` carries `requested=[]` and `found=many`, so the
    /// requester must close the round directly with `SyncConfirmation`
    /// (no intervening `SyncOps` step).
    ///
    /// Setup runs an initial alignment round so that both peers share the
    /// baseline (prekey / contact-card) history; then Bob creates a group,
    /// and a second round exercises the asymmetric "responder has more,
    /// requester has nothing new" path that the e2e periodic sync hits.
    #[tokio::test(flavor = "current_thread")]
    async fn sync_round_with_empty_requested_returns_confirmation_directly() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        // Initial alignment round: drains each side's baseline history so
        // a subsequent round with one-sided new ops actually has an empty
        // `requested` field. Without this, each peer's prekey/contact-card
        // history that the other doesn't yet know about causes the round
        // to take the SyncOps path instead.
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // Now Bob alone gets new ops. Alice has no new ops to offer back.
        {
            let kh = bob_kh.clone();
            create_group_with_read_members(&kh, &[&alice_id]).await;
        }

        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // Both sides should have established syncpoints with non-zero totals.
        // The empty-requested path (Alice has nothing to send back) should
        // close via direct SyncConfirmation, establishing syncpoints.
        let alice_sp = alice_proto.syncpoints.lock().await.get(&bob_id);
        let bob_sp = bob_proto.syncpoints.lock().await.get(&alice_id);
        assert!(
            alice_sp.is_some_and(|v| v > 0),
            "alice should have a non-zero syncpoint for bob after the \
             empty-requested round, got: {alice_sp:?}"
        );
        assert!(
            bob_sp.is_some_and(|v| v > 0),
            "bob should have a non-zero syncpoint for alice, got: {bob_sp:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_hashes_for_agent_returns_serialised_events_for_known_peer() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        // Give Alice some membership ops so the per-agent walk has content.
        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }

        // Run a full sync round so Bob's keyhive learns about Alice's ops.
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        let alice_hashes = alice_proto
            .get_events_for_agent(&alice_id)
            .await
            .expect("alice get_hashes_for_agent")
            .expect("alice agent exists");
        assert!(
            !alice_hashes.is_empty(),
            "alice's agent should have membership/cgka ops after the group was created"
        );

        // Event bytes round-trip via bincode (matching keyhive-wasm).
        for event_bytes in alice_hashes.values() {
            bincode_deserialize::<StaticEvent<[u8; 32]>>(event_bytes)
                .expect("event_bytes round-trips");
        }

        // Symmetric: querying for a peer keyhive doesn't know about returns None.
        let unknown = KeyhivePeerId::from_bytes([0xAA; 32]);
        assert!(
            alice_proto
                .get_events_for_agent(&unknown)
                .await
                .expect("get_hashes_for_agent for unknown peer")
                .is_none()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn total_ops_increases_after_local_mutation() {
        let (protocol, _) = make_protocol().await;
        let before = protocol.total_ops().await;

        // Generate some keyhive activity by creating a group.
        {
            let kh = protocol.keyhive.clone();
            kh.generate_group(vec![]).await.expect("generate_group");
        }

        let after = protocol.total_ops().await;
        assert!(
            after > before,
            "total_ops should increase after creating a group: {before} -> {after}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_check_returns_in_sync_when_totals_match() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        // Alice creates a group and syncs with Bob
        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }

        // First sync round to get both sides aligned (exchanges ops)
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // Second sync round with no new ops — establishes stable syncpoints.
        // The first round ingested ops (invalidating syncpoints), so the
        // second round's zero-op exchange produces usable syncpoints.
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        let alice_sp = alice_proto
            .syncpoints
            .lock()
            .await
            .get(&bob_id)
            .expect("should have Alice's syncpoint for Bob");

        // Now Alice sends a sync check to Bob
        alice_proto
            .sync_check_keyhive(&bob_id, alice_sp)
            .await
            .expect("sync_check_keyhive failed");

        // Bob receives the sync check — handle_message resolves it internally
        let check_msg = bob_conn
            .inbound_rx
            .recv()
            .await
            .expect("failed to receive sync check");
        bob_proto
            .handle_message(&alice_id, check_msg, None)
            .await
            .expect("bob failed to handle sync check");

        let confirmation = alice_conn
            .inbound_rx
            .try_recv()
            .expect("in-sync check should receive sync confirmation");
        let status = alice_proto
            .handle_message(&bob_id, confirmation, None)
            .await
            .expect("alice failed to handle sync confirmation");
        assert!(matches!(status, SyncStatus::Done { .. }));
        assert!(
            alice_conn.inbound_rx.try_recv().is_err(),
            "only a sync confirmation should be sent when peers are in sync"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_check_falls_back_when_out_of_sync() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        // Alice creates a group and syncs with Bob
        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }

        // First sync to exchange ops
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        // Second sync to establish stable syncpoints (no ops exchanged)
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        let alice_sp = alice_proto
            .syncpoints
            .lock()
            .await
            .get(&bob_id)
            .expect("should have Alice's syncpoint for Bob");

        // Alice creates ANOTHER group with Bob (changes her state without syncing)
        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }

        // Alice sends sync check — her total has changed but she passes
        // the stale syncpoint she got from the last round
        alice_proto
            .sync_check_keyhive(&bob_id, alice_sp)
            .await
            .expect("sync_check_keyhive failed");

        let check_msg = bob_conn
            .inbound_rx
            .recv()
            .await
            .expect("failed to receive sync check");

        // handle_message resolves the sync check internally and falls back
        bob_proto
            .handle_message(&alice_id, check_msg, None)
            .await
            .expect("bob failed to handle sync check");

        // Bob should have sent a full SyncRequest (fallback).
        // Use try_recv so the test fails fast instead of hanging if
        // the fallback didn't fire.
        let fallback_msg = alice_conn
            .inbound_rx
            .try_recv()
            .expect("should have received fallback SyncRequest from bob");
        alice_proto
            .handle_message(&bob_id, fallback_msg, None)
            .await
            .expect("alice failed to handle fallback message");
    }

    /// `pair_set_digest` must be order-independent, reduce
    /// an empty set to all zeros, and distinguish different op-sets.
    #[test]
    fn pair_set_digest_properties() {
        let mut a: EventHash = [0u8; 32];
        a[0] = 1;
        let mut b: EventHash = [0u8; 32];
        b[1] = 1;

        // An empty set yields all zeros, matching a peer that sends no digest.
        assert_eq!(
            pair_set_digest(core::iter::empty::<&EventHash>()),
            [0u8; 32]
        );

        // Iteration order does not change the digest.
        assert_eq!(pair_set_digest([&a, &b]), pair_set_digest([&b, &a]));

        // Different op-sets produce different digests.
        assert_ne!(pair_set_digest([&a, &b]), pair_set_digest([&a]));
    }

    /// When the counts cross-match on crossed syncpoints and the digests also
    /// match, `resolve_sync_check` short-circuits without a fallback sync.
    #[tokio::test(flavor = "current_thread")]
    async fn resolve_sync_check_in_sync_when_counts_and_digest_match() {
        let TwoPeerHarness {
            alice_proto,
            alice_kh,
            bob_id,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        // Give Alice some pair state with Bob so the digest is non-trivial.
        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }
        while bob_conn.inbound_rx.try_recv().is_ok() {}

        let (our_total, our_digest) = alice_proto
            .compute_total_and_digest_for_peer(&bob_id)
            .await
            .expect("compute total and digest");

        // local_syncpoint_for_sender == sender_total and sender_syncpoint ==
        // our_total, so the counts pass; the digest matches too.
        alice_proto
            .resolve_sync_check(
                &bob_id,
                RequestId {
                    requestor: bob_id.clone(),
                    nonce: 0,
                },
                our_total,
                our_total,
                our_digest,
                our_total,
            )
            .await
            .expect("resolve_sync_check");

        let confirmation = bob_conn
            .inbound_rx
            .try_recv()
            .expect("in-sync resolve should send sync confirmation");
        let verified = confirmation
            .verify(&alice_proto.peer_id)
            .expect("verify sync confirmation");
        let message: Message =
            cbor_deserialize(&verified.payload).expect("decode sync confirmation");
        assert!(
            matches!(message, Message::SyncConfirmation { .. }),
            "in-sync resolve should send sync confirmation, got {message:?}"
        );
        assert!(
            bob_conn.inbound_rx.try_recv().is_err(),
            "no fallback expected when counts and digest match"
        );
    }

    /// A digest mismatch forces a full sync even when the counts cross-match.
    #[tokio::test(flavor = "current_thread")]
    async fn resolve_sync_check_falls_back_on_digest_mismatch_despite_matching_counts() {
        let TwoPeerHarness {
            alice_proto,
            alice_kh,
            bob_id,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }
        while bob_conn.inbound_rx.try_recv().is_ok() {}

        let (our_total, our_digest) = alice_proto
            .compute_total_and_digest_for_peer(&bob_id)
            .await
            .expect("compute total and digest");

        // Identical crossed-syncpoint counts as the in-sync case, but a digest
        // that differs by one byte.
        let mut wrong_digest = our_digest;
        wrong_digest[0] ^= 0xFF;

        alice_proto
            .resolve_sync_check(
                &bob_id,
                RequestId {
                    requestor: bob_id.clone(),
                    nonce: 0,
                },
                our_total,
                our_total,
                wrong_digest,
                our_total,
            )
            .await
            .expect("resolve_sync_check");

        assert!(
            bob_conn.inbound_rx.try_recv().is_ok(),
            "digest mismatch should trigger a fallback sync"
        );
    }

    // ── Revocation chain regression tests ──────────────────────────────
    //
    // Scenario: A creates doc → make public → revoke public → add B →
    // revoke B → make public again. A and B sync incrementally with the
    // server after each step. Then fresh client C connects.
    //
    // These tests verify that:
    // 1. C receives all events with complete dependencies (no stuck pending)
    // 2. The `all_agent_events()` cache path includes delegate prekey ops
    //    for revoked agents (the root cause of the production bug)

    fn assert_event_deps_complete(
        hashes: &alloc::collections::BTreeSet<[u8; 32]>,
        events: &alloc::collections::BTreeMap<[u8; 32], StaticEvent<[u8; 32]>>,
        builtin_agents: &[keyhive_core::principal::identifier::Identifier],
        label: &str,
    ) {
        use core::fmt::Write;
        use keyhive_core::principal::identifier::Identifier;

        fn to_hex(bytes: &[u8]) -> String {
            bytes.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
        }

        let mut missing: Vec<String> = Vec::new();
        for (h, event) in events {
            let hh = to_hex(&h[..8]);
            match event {
                StaticEvent::Delegated(signed_dlg) => {
                    let dlg = &signed_dlg.payload;
                    if let Some(proof) = &dlg.proof {
                        let ph = digest_to_bytes(proof);
                        if !hashes.contains(&ph) {
                            missing.push(format!(
                                "delegation {hh} missing proof_dlg:{}",
                                to_hex(&ph[..8])
                            ));
                        }
                    }
                    for rev in &dlg.after_revocations {
                        let rh = digest_to_bytes(rev);
                        if !hashes.contains(&rh) {
                            missing.push(format!(
                                "delegation {hh} missing after_rev:{}",
                                to_hex(&rh[..8])
                            ));
                        }
                    }
                    let delegate_id = dlg.delegate;
                    let has_prekey = events.values().any(|e| match e {
                        StaticEvent::PrekeysExpanded(op) => Identifier(*op.issuer()) == delegate_id,
                        StaticEvent::PrekeyRotated(op) => Identifier(*op.issuer()) == delegate_id,
                        _ => false,
                    });
                    if !has_prekey && !builtin_agents.contains(&delegate_id) {
                        missing.push(format!(
                            "delegation {hh} missing prekey for delegate {delegate_id:?}",
                        ));
                    }
                }
                StaticEvent::Revoked(signed_rev) => {
                    let rev = &signed_rev.payload;
                    let rh = digest_to_bytes(&rev.revoke);
                    if !hashes.contains(&rh) {
                        missing.push(format!(
                            "revocation {hh} missing revoke_dlg:{}",
                            to_hex(&rh[..8])
                        ));
                    }
                    if let Some(proof) = &rev.proof {
                        let ph = digest_to_bytes(proof);
                        if !hashes.contains(&ph) {
                            missing.push(format!(
                                "revocation {hh} missing proof_dlg:{}",
                                to_hex(&ph[..8])
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        assert!(
            missing.is_empty(),
            "{label} has {} events but missing deps:\n{}",
            events.len(),
            missing.join("\n")
        );
    }

    /// A → server (with B syncing) → fresh C. Verifies C has no
    /// pending events after the revocation chain.
    #[tokio::test(flavor = "current_thread")]
    async fn fresh_client_gets_complete_deps_after_revocation_chain() {
        use keyhive_core::{
            access::Access,
            principal::{membered::Membered, public::Public},
        };

        let kh_a = make_keyhive().await;
        let kh_b = make_keyhive().await;
        let kh_server = make_keyhive().await;
        let kh_c = make_keyhive().await;

        exchange_all_contact_cards(&[&kh_a, &kh_b]).await;
        exchange_all_contact_cards(&[&kh_a, &kh_server]).await;
        exchange_all_contact_cards(&[&kh_b, &kh_server]).await;
        exchange_all_contact_cards(&[&kh_server, &kh_c]).await;

        let a_id = keyhive_peer_id(&kh_a);
        let b_id = keyhive_peer_id(&kh_b);
        let server_id = keyhive_peer_id(&kh_server);
        let c_id = keyhive_peer_id(&kh_c);

        let b_identifier = kh_b.id().into();
        let b_agent = kh_a.get_agent(b_identifier).await.unwrap();

        let doc = kh_a
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = doc;
        let doc = kh_a
            .get_document(doc_id)
            .await
            .expect("generated document is present");
        let membered = Membered::Document(doc_id, doc.clone());
        let public_agent = Public;

        let (a_proto, a_kh, _) = make_protocol_with_shared_keyhive(kh_a).await;
        let (b_proto, _b_kh, _) = make_protocol_with_shared_keyhive(kh_b).await;
        let (server_proto, server_kh, _) = make_protocol_with_shared_keyhive(kh_server).await;
        let (c_proto, c_kh, _) = make_protocol_with_shared_keyhive(kh_c).await;

        let (a_conn, server_conn_a) = create_channel_pair(a_id.clone(), &server_id);
        a_proto.add_peer(server_id.clone(), a_conn.clone()).await;
        server_proto
            .add_peer(a_id.clone(), server_conn_a.clone())
            .await;

        let (b_conn, server_conn_b) = create_channel_pair(b_id.clone(), &server_id);
        b_proto.add_peer(server_id.clone(), b_conn.clone()).await;
        server_proto
            .add_peer(b_id.clone(), server_conn_b.clone())
            .await;

        macro_rules! sync_a_server {
            () => {
                sync_pair_rounds(
                    &a_proto,
                    &server_proto,
                    &a_id,
                    &server_id,
                    &a_conn,
                    &server_conn_a,
                    3,
                )
                .await
            };
        }
        macro_rules! sync_b_server {
            () => {
                sync_pair_rounds(
                    &b_proto,
                    &server_proto,
                    &b_id,
                    &server_id,
                    &b_conn,
                    &server_conn_b,
                    3,
                )
                .await
            };
        }

        sync_a_server!();

        {
            a_kh.add_member(public_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(Public.id(), true, membered.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.add_member(b_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(b_identifier, true, membered.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.add_member(public_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();

        assert!(server_kh.get_document(doc_id).await.is_some());

        let (server_conn_c, c_conn) = create_channel_pair(server_id.clone(), &c_id);
        server_proto
            .add_peer(c_id.clone(), server_conn_c.clone())
            .await;
        c_proto.add_peer(server_id.clone(), c_conn.clone()).await;

        for _ in 0..3 {
            run_sync_round(
                &server_proto,
                &c_proto,
                &server_id,
                &c_id,
                &server_conn_c,
                &c_conn,
            )
            .await;
            run_sync_round(
                &c_proto,
                &server_proto,
                &c_id,
                &server_id,
                &c_conn,
                &server_conn_c,
            )
            .await;
        }

        let c = c_kh.clone();
        assert!(
            c.get_document(doc_id).await.is_some(),
            "C should have the doc"
        );
        drop(c);

        let snapshot = c_proto.all_agent_events(&BTreeSet::new()).await.unwrap();
        let public_peer = KeyhivePeerId::from_identifier(&Public.id());
        let public_hashes = snapshot.hashes_for(&public_peer).unwrap();

        let mut events: alloc::collections::BTreeMap<[u8; 32], StaticEvent<[u8; 32]>> =
            alloc::collections::BTreeMap::new();
        for h in public_hashes {
            if let Some(bytes) = snapshot.event_data.get(h) {
                events.insert(*h, bincode_deserialize(bytes).unwrap());
            }
        }

        let hash_set: alloc::collections::BTreeSet<[u8; 32]> =
            public_hashes.iter().copied().collect();
        let builtin = [Public.id()];
        assert_event_deps_complete(
            &hash_set,
            &events,
            &builtin,
            "fresh client C after revocation chain",
        );
    }

    /// Verifies the `all_agent_events()` cache path (used by the
    /// `PeriodicEventCache`) produces a dependency-
    /// complete public hash set after the revocation chain synced
    /// through the protocol.
    #[tokio::test(flavor = "current_thread")]
    async fn all_agent_events_complete_after_protocol_sync() {
        use keyhive_core::principal::{identifier::Identifier, membered::Membered, public::Public};

        let kh_a = make_keyhive().await;
        let kh_b = make_keyhive().await;
        let kh_server = make_keyhive().await;

        exchange_all_contact_cards(&[&kh_a, &kh_b]).await;
        exchange_all_contact_cards(&[&kh_a, &kh_server]).await;
        exchange_all_contact_cards(&[&kh_b, &kh_server]).await;

        let a_id = keyhive_peer_id(&kh_a);
        let b_id = keyhive_peer_id(&kh_b);
        let server_id = keyhive_peer_id(&kh_server);

        let b_identifier: Identifier = kh_b.id().into();
        let b_agent = kh_a.get_agent(b_identifier).await.unwrap();

        let doc = kh_a
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = doc;
        let doc = kh_a
            .get_document(doc_id)
            .await
            .expect("generated document is present");
        let membered = Membered::Document(doc_id, doc.clone());
        let public_agent = Public;

        let (a_proto, a_kh, _) = make_protocol_with_shared_keyhive(kh_a).await;
        let (b_proto, _b_kh, _) = make_protocol_with_shared_keyhive(kh_b).await;
        let (server_proto, _server_kh, _) = make_protocol_with_shared_keyhive(kh_server).await;

        let (a_conn, server_conn_a) = create_channel_pair(a_id.clone(), &server_id);
        a_proto.add_peer(server_id.clone(), a_conn.clone()).await;
        server_proto
            .add_peer(a_id.clone(), server_conn_a.clone())
            .await;

        let (b_conn, server_conn_b) = create_channel_pair(b_id.clone(), &server_id);
        b_proto.add_peer(server_id.clone(), b_conn.clone()).await;
        server_proto
            .add_peer(b_id.clone(), server_conn_b.clone())
            .await;

        macro_rules! sync_a_server {
            () => {
                sync_pair_rounds(
                    &a_proto,
                    &server_proto,
                    &a_id,
                    &server_id,
                    &a_conn,
                    &server_conn_a,
                    3,
                )
                .await
            };
        }
        macro_rules! sync_b_server {
            () => {
                sync_pair_rounds(
                    &b_proto,
                    &server_proto,
                    &b_id,
                    &server_id,
                    &b_conn,
                    &server_conn_b,
                    3,
                )
                .await
            };
        }

        sync_a_server!();
        {
            a_kh.add_member(public_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(Public.id(), true, membered.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.add_member(b_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(b_identifier, true, membered.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.add_member(public_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();

        let snapshot = server_proto
            .all_agent_events(&BTreeSet::new())
            .await
            .unwrap();
        let public_peer = KeyhivePeerId::from_identifier(&Public.id());
        let public_hashes = snapshot.hashes_for(&public_peer).unwrap();

        let mut events: alloc::collections::BTreeMap<[u8; 32], StaticEvent<[u8; 32]>> =
            alloc::collections::BTreeMap::new();
        for h in public_hashes {
            if let Some(bytes) = snapshot.event_data.get(h) {
                events.insert(*h, bincode_deserialize(bytes).unwrap());
            }
        }

        let hash_set: alloc::collections::BTreeSet<[u8; 32]> =
            public_hashes.iter().copied().collect();
        let builtin = [Public.id()];
        assert_event_deps_complete(
            &hash_set,
            &events,
            &builtin,
            "all_agent_events (after protocol sync)",
        );
    }

    /// `all_agent_events()` public hash set is dep-complete across four docs
    /// with varied delegation patterns (matches typical real-world TPW scenario).
    ///
    /// Doc 1: no extra members (baseline).
    /// Doc 2: made public, never revoked.
    /// Doc 3: made public then revoked.
    /// Doc 4: full chain: make public → revoke → add B → revoke B → make public.
    #[tokio::test(flavor = "current_thread")]
    async fn all_agent_events_complete_multiple_docs() {
        use keyhive_core::principal::{identifier::Identifier, membered::Membered, public::Public};

        let kh_a = make_keyhive().await;
        let kh_b = make_keyhive().await;
        let kh_server = make_keyhive().await;

        exchange_all_contact_cards(&[&kh_a, &kh_b]).await;
        exchange_all_contact_cards(&[&kh_a, &kh_server]).await;
        exchange_all_contact_cards(&[&kh_b, &kh_server]).await;

        let a_id = keyhive_peer_id(&kh_a);
        let b_id = keyhive_peer_id(&kh_b);
        let server_id = keyhive_peer_id(&kh_server);

        let b_identifier: Identifier = kh_b.id().into();
        let b_agent = kh_a.get_agent(b_identifier).await.unwrap();

        // Create all four docs before wrapping in protocols.
        let _doc1 = kh_a
            .generate_doc(vec![], nonempty![[1u8; 32]])
            .await
            .unwrap();
        let doc2 = kh_a
            .generate_doc(vec![], nonempty![[2u8; 32]])
            .await
            .unwrap();
        let doc3 = kh_a
            .generate_doc(vec![], nonempty![[3u8; 32]])
            .await
            .unwrap();
        let doc4 = kh_a
            .generate_doc(vec![], nonempty![[4u8; 32]])
            .await
            .unwrap();

        let doc2_id = doc2;
        let doc2 = kh_a
            .get_document(doc2_id)
            .await
            .expect("generated document is present");
        let doc3_id = doc3;
        let doc3 = kh_a
            .get_document(doc3_id)
            .await
            .expect("generated document is present");
        let doc4_id = doc4;
        let doc4 = kh_a
            .get_document(doc4_id)
            .await
            .expect("generated document is present");

        let membered2 = Membered::Document(doc2_id, doc2.clone());
        let membered3 = Membered::Document(doc3_id, doc3.clone());
        let membered4 = Membered::Document(doc4_id, doc4.clone());

        let public_agent = Public;

        let (a_proto, a_kh, _) = make_protocol_with_shared_keyhive(kh_a).await;
        let (b_proto, _b_kh, _) = make_protocol_with_shared_keyhive(kh_b).await;
        let (server_proto, _server_kh, _) = make_protocol_with_shared_keyhive(kh_server).await;

        let (a_conn, server_conn_a) = create_channel_pair(a_id.clone(), &server_id);
        a_proto.add_peer(server_id.clone(), a_conn.clone()).await;
        server_proto
            .add_peer(a_id.clone(), server_conn_a.clone())
            .await;

        let (b_conn, server_conn_b) = create_channel_pair(b_id.clone(), &server_id);
        b_proto.add_peer(server_id.clone(), b_conn.clone()).await;
        server_proto
            .add_peer(b_id.clone(), server_conn_b.clone())
            .await;

        // Doc 1: no changes — just sync the baseline.
        macro_rules! sync_a_server {
            () => {
                sync_pair_rounds(
                    &a_proto,
                    &server_proto,
                    &a_id,
                    &server_id,
                    &a_conn,
                    &server_conn_a,
                    3,
                )
                .await
            };
        }
        macro_rules! sync_b_server {
            () => {
                sync_pair_rounds(
                    &b_proto,
                    &server_proto,
                    &b_id,
                    &server_id,
                    &b_conn,
                    &server_conn_b,
                    3,
                )
                .await
            };
        }

        sync_a_server!();

        // Doc 2: make public, never revoke.
        {
            a_kh.add_member(
                public_agent.id(),
                membered2.membered_id(),
                Access::Edit,
                &[],
            )
            .await
            .unwrap();
        }
        sync_a_server!();
        sync_b_server!();

        // Doc 3: make public then revoke.
        {
            a_kh.add_member(
                public_agent.id(),
                membered3.membered_id(),
                Access::Edit,
                &[],
            )
            .await
            .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(Public.id(), true, membered3.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();

        // Doc 4: full chain.
        {
            a_kh.add_member(
                public_agent.id(),
                membered4.membered_id(),
                Access::Edit,
                &[],
            )
            .await
            .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(Public.id(), true, membered4.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.add_member(b_agent.id(), membered4.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(b_identifier, true, membered4.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.add_member(
                public_agent.id(),
                membered4.membered_id(),
                Access::Edit,
                &[],
            )
            .await
            .unwrap();
        }
        sync_a_server!();
        sync_b_server!();

        let snapshot = server_proto
            .all_agent_events(&BTreeSet::new())
            .await
            .unwrap();
        let public_peer = KeyhivePeerId::from_identifier(&Public.id());
        let public_hashes = snapshot.hashes_for(&public_peer).unwrap();

        let mut events: alloc::collections::BTreeMap<[u8; 32], StaticEvent<[u8; 32]>> =
            alloc::collections::BTreeMap::new();
        for h in public_hashes {
            if let Some(bytes) = snapshot.event_data.get(h) {
                events.insert(*h, bincode_deserialize(bytes).unwrap());
            }
        }

        let hash_set: alloc::collections::BTreeSet<[u8; 32]> =
            public_hashes.iter().copied().collect();
        let builtin = [Public.id()];
        assert_event_deps_complete(&hash_set, &events, &builtin, "all_agent_events multi-doc");
    }

    /// CGKA ops generated by the delegation chain (add/revoke members) are
    /// present and dependency-complete in the `all_agent_events()` public hash
    /// set after sync through the protocol. This is a regression test for the
    /// class of bugs where per-agent event sets silently drop CGKA ops
    /// associated with revoked agents.
    #[tokio::test(flavor = "current_thread")]
    async fn all_agent_events_includes_cgka_ops_after_revocation() {
        use keyhive_core::principal::{identifier::Identifier, membered::Membered, public::Public};

        let kh_a = make_keyhive().await;
        let kh_b = make_keyhive().await;
        let kh_server = make_keyhive().await;

        exchange_all_contact_cards(&[&kh_a, &kh_b]).await;
        exchange_all_contact_cards(&[&kh_a, &kh_server]).await;
        exchange_all_contact_cards(&[&kh_b, &kh_server]).await;

        let a_id = keyhive_peer_id(&kh_a);
        let b_id = keyhive_peer_id(&kh_b);
        let server_id = keyhive_peer_id(&kh_server);

        let b_identifier: Identifier = kh_b.id().into();
        let b_agent = kh_a.get_agent(b_identifier).await.unwrap();

        let doc = kh_a
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = doc;
        let doc = kh_a
            .get_document(doc_id)
            .await
            .expect("generated document is present");
        let membered = Membered::Document(doc_id, doc.clone());
        let public_agent = Public;

        let (a_proto, a_kh, _) = make_protocol_with_shared_keyhive(kh_a).await;
        let (b_proto, _b_kh, _) = make_protocol_with_shared_keyhive(kh_b).await;
        let (server_proto, _server_kh, _) = make_protocol_with_shared_keyhive(kh_server).await;

        let (a_conn, server_conn_a) = create_channel_pair(a_id.clone(), &server_id);
        a_proto.add_peer(server_id.clone(), a_conn.clone()).await;
        server_proto
            .add_peer(a_id.clone(), server_conn_a.clone())
            .await;

        let (b_conn, server_conn_b) = create_channel_pair(b_id.clone(), &server_id);
        b_proto.add_peer(server_id.clone(), b_conn.clone()).await;
        server_proto
            .add_peer(b_id.clone(), server_conn_b.clone())
            .await;

        // Full delegation chain — each step generates CGKA Add/Remove ops implicitly.
        // Adding and revoking members creates CgkaOperation::Add and ::Remove events
        // in the document's CGKA tree.
        macro_rules! sync_a_server {
            () => {
                sync_pair_rounds(
                    &a_proto,
                    &server_proto,
                    &a_id,
                    &server_id,
                    &a_conn,
                    &server_conn_a,
                    3,
                )
                .await
            };
        }
        macro_rules! sync_b_server {
            () => {
                sync_pair_rounds(
                    &b_proto,
                    &server_proto,
                    &b_id,
                    &server_id,
                    &b_conn,
                    &server_conn_b,
                    3,
                )
                .await
            };
        }

        sync_a_server!();
        {
            a_kh.add_member(public_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(Public.id(), true, membered.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.add_member(b_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.revoke_member(b_identifier, true, membered.membered_id())
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();
        {
            a_kh.add_member(public_agent.id(), membered.membered_id(), Access::Edit, &[])
                .await
                .unwrap();
        }
        sync_a_server!();
        sync_b_server!();

        let snapshot = server_proto
            .all_agent_events(&BTreeSet::new())
            .await
            .unwrap();
        let public_peer = KeyhivePeerId::from_identifier(&Public.id());
        let public_hashes = snapshot.hashes_for(&public_peer).unwrap();

        let mut events: alloc::collections::BTreeMap<[u8; 32], StaticEvent<[u8; 32]>> =
            alloc::collections::BTreeMap::new();
        for h in public_hashes {
            if let Some(bytes) = snapshot.event_data.get(h) {
                events.insert(*h, bincode_deserialize(bytes).unwrap());
            }
        }

        let hash_set: alloc::collections::BTreeSet<[u8; 32]> =
            public_hashes.iter().copied().collect();
        let builtin = [Public.id()];

        // Standard delegation/revocation dep check.
        assert_event_deps_complete(
            &hash_set,
            &events,
            &builtin,
            "all_agent_events (cgka regression)",
        );

        // Additional check: every CgkaOperation event in the public set must
        // have at least one Delegated event also present in the set (confirming
        // the doc was delegated and the CGKA tree was bootstrapped). This guards
        // against the class of bug where CGKA ops exist in the keyhive but are
        // dropped from the per-agent event set during serialization.
        let cgka_count = events
            .values()
            .filter(|e| matches!(e, StaticEvent::CgkaOperation(_)))
            .count();
        if cgka_count > 0 {
            let has_any_delegation = events
                .values()
                .any(|e| matches!(e, StaticEvent::Delegated(_)));
            assert!(
                has_any_delegation,
                "public set has {cgka_count} CgkaOperation event(s) but no Delegated event — \
                 the CGKA ops are present but their bootstrapping delegation is missing",
            );
        }
        // At least some CGKA ops must be present after the delegation chain
        // (guards against the set being silently empty).
        assert!(
            cgka_count > 0,
            "expected at least one CgkaOperation in the public event set after \
             the add/revoke delegation chain, but found none"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::missing_panics_doc
)]
mod protocol_behavioural {
    use alloc::{sync::Arc, vec::Vec};

    use super::*;
    use crate::test_utils::{
        ChannelConnection, TwoPeerHarness, create_group_with_read_members,
        exchange_contact_cards_and_setup, run_sync_round,
    };

    fn deserialize_message(signed: &SignedMessage, expected_sender: &KeyhivePeerId) -> Message {
        let verified = signed
            .clone()
            .verify(expected_sender)
            .expect("verify signed message");
        ciborium::from_reader(verified.payload.as_slice()).expect("cbor decode message")
    }

    fn drain_channel(conn: &ChannelConnection, expected_sender: &KeyhivePeerId) -> Vec<Message> {
        core::iter::from_fn(|| conn.inbound_rx.try_recv().ok())
            .map(|msg| deserialize_message(&msg, expected_sender))
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn initiate_sync_with_peer_with_no_syncpoint_does_full_sync() {
        let TwoPeerHarness {
            alice_proto,
            alice_id,
            bob_id,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        let alice_proto = Arc::new(alice_proto);

        alice_proto
            .initiate_sync_with_peer(&bob_id)
            .await
            .expect("initiate_sync_with_peer");

        let messages = drain_channel(&bob_conn, &alice_id);
        assert!(
            matches!(messages.first(), Some(Message::SyncRequest { .. })),
            "expected SyncRequest, got {messages:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn initiate_sync_with_peer_with_syncpoint_does_sync_check() {
        let TwoPeerHarness {
            alice_proto,
            alice_id,
            bob_id,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        let alice_proto = Arc::new(alice_proto);

        // Settle the cache first: contact-card setup ingested events, so the
        // first initiate performs a full sync and publishes the current
        // structural generation (invalidating syncpoints there is expected).
        alice_proto
            .initiate_sync_with_peer(&bob_id)
            .await
            .expect("settle initiate_sync_with_peer");
        drop(drain_channel(&bob_conn, &alice_id));

        // Without pending drift, an existing syncpoint selects the cheap check.
        alice_proto.syncpoints.lock().await.set(bob_id.clone(), 0);

        alice_proto
            .initiate_sync_with_peer(&bob_id)
            .await
            .expect("initiate_sync_with_peer");

        let messages = drain_channel(&bob_conn, &alice_id);
        assert!(
            matches!(messages.first(), Some(Message::SyncCheck { .. })),
            "expected SyncCheck, got {messages:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn structural_drift_invalidates_syncpoint_before_short_circuit() {
        let TwoPeerHarness {
            alice_proto,
            alice_kh,
            alice_id,
            bob_id,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;
        let alice_proto = Arc::new(alice_proto);
        alice_proto.syncpoints.lock().await.set(bob_id.clone(), 0);

        alice_kh.generate_group(vec![]).await.unwrap();
        alice_proto
            .initiate_sync_with_peer(&bob_id)
            .await
            .expect("initiate_sync_with_peer after structural drift");

        let messages = drain_channel(&bob_conn, &alice_id);
        assert!(
            matches!(messages.first(), Some(Message::SyncRequest { .. })),
            "structural drift must invalidate the syncpoint before selection: {messages:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mutation_during_refresh_is_not_published_as_current() {
        let TwoPeerHarness {
            alice_proto,
            alice_kh,
            ..
        } = exchange_contact_cards_and_setup().await;
        let alice_proto = Arc::new(alice_proto);
        alice_kh.generate_group(vec![]).await.unwrap();
        alice_proto.refresh_cache().await.unwrap();
        let remote = crate::test_utils::make_keyhive().await;
        let remote_card = remote.generate_contact_card().await.unwrap();

        // Make the cache dirty, then prevent its walk from completing while a
        // second structural mutation advances the generation.
        alice_kh.expand_prekeys().await.unwrap();
        let groups_guard = alice_kh.groups().lock().await;
        let mut refresh = core::pin::pin!(alice_proto.refresh_cache());
        assert!(futures::poll!(refresh.as_mut()).is_pending());
        alice_kh.receive_contact_card(&remote_card).await.unwrap();
        drop(groups_guard);
        refresh.await.unwrap();

        assert_eq!(
            alice_proto
                .snapshot_state_generation
                .load(Ordering::Acquire),
            alice_kh.state_generation(),
            "a rebuild raced by mutation must retry instead of labeling stale data current"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_check_received_resolves_via_protocol() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;
        drop(drain_channel(&alice_conn, &bob_id));
        drop(drain_channel(&bob_conn, &alice_id));

        let alice_proto = Arc::new(alice_proto);
        let alice_total = alice_proto.total_ops().await;
        alice_proto
            .syncpoints
            .lock()
            .await
            .set(bob_id.clone(), alice_total);

        bob_proto
            .sync_check_keyhive(&alice_id, alice_total)
            .await
            .expect("bob sync_check_keyhive");

        let inbound = alice_conn
            .inbound_rx
            .try_recv()
            .expect("alice should receive sync-check");

        alice_proto
            .handle_message(&bob_id, inbound, Some(bob_conn.clone()))
            .await
            .expect("handle_message sync check");

        let confirmation = bob_conn
            .inbound_rx
            .try_recv()
            .expect("in-sync check should receive sync confirmation");
        let status = bob_proto
            .handle_message(&alice_id, confirmation, None)
            .await
            .expect("handle sync confirmation");
        assert!(matches!(status, SyncStatus::Done { .. }));
        let alice_messages = drain_channel(&bob_conn, &alice_id);
        assert!(
            alice_messages.is_empty(),
            "expected no additional outbound messages after sync confirmation, got {alice_messages:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn auto_registers_unknown_peer_on_sync_check() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_id,
            bob_id,
            alice_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        let alice_proto = Arc::new(alice_proto);

        alice_proto.remove_peer(&bob_id).await;
        assert!(!alice_proto.has_peer(&bob_id).await);

        bob_proto
            .sync_check_keyhive(&alice_id, 0)
            .await
            .expect("bob sync_check_keyhive");
        let inbound = alice_conn
            .inbound_rx
            .try_recv()
            .expect("alice should receive sync-check");

        alice_proto
            .handle_message(&bob_id, inbound, Some(alice_conn.clone()))
            .await
            .expect("handle_message sync check");

        assert!(
            alice_proto.has_peer(&bob_id).await,
            "auto-register should have added bob to the protocol's peer registry"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_refresh_populates_then_early_returns_on_unchanged() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            alice_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        {
            let kh = alice_kh.clone();
            create_group_with_read_members(&kh, &[&bob_id]).await;
        }
        run_sync_round(
            &alice_proto,
            &bob_proto,
            &alice_id,
            &bob_id,
            &alice_conn,
            &bob_conn,
        )
        .await;

        let alice_proto = Arc::new(alice_proto);

        alice_proto.refresh_cache().await.expect("first refresh");
        let (total_after_first, agent_count_after_first, public_hash_count_after_first) = {
            let cache = alice_proto.cache.lock().await;
            assert!(!cache.is_empty(), "cache populated after first refresh");
            let agent_count = cache.agent_count();
            assert!(agent_count >= 1, "at least the local agent is tracked");
            let total = cache
                .last_total_ops()
                .expect("last_total_ops should be Some after refresh");
            let public_count = cache.public_hashes().len();
            (total, agent_count, public_count)
        };

        alice_proto.refresh_cache().await.expect("second refresh");
        let cache = alice_proto.cache.lock().await;
        assert_eq!(cache.last_total_ops(), Some(total_after_first));
        assert_eq!(
            cache.agent_count(),
            agent_count_after_first,
            "agent count unchanged"
        );
        assert_eq!(
            cache.public_hashes().len(),
            public_hash_count_after_first,
            "public hash count unchanged"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preserves_other_peers_when_ingest_is_noop() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        {
            let kh = bob_kh.clone();
            create_group_with_read_members(&kh, &[&alice_id]).await;
        }
        run_sync_round(
            &bob_proto,
            &alice_proto,
            &bob_id,
            &alice_id,
            &bob_conn,
            &alice_conn,
        )
        .await;
        drop(drain_channel(&alice_conn, &bob_id));
        drop(drain_channel(&bob_conn, &alice_id));

        let alice_proto = Arc::new(alice_proto);

        // Settle alice's cache so the round below exercises exactly the
        // no-drift path: structural changes ingested during the previous round
        // must publish (and legitimately invalidate) once, up front — they must
        // not be conflated with this round's no-op ingest.
        alice_proto
            .initiate_sync_with_peer(&bob_id)
            .await
            .expect("settle initiate_sync_with_peer");
        drop(drain_channel(&alice_conn, &bob_id));
        drop(drain_channel(&bob_conn, &alice_id));

        let carol_id = KeyhivePeerId::from_bytes([0xCC; 32]);
        alice_proto
            .syncpoints
            .lock()
            .await
            .set(carol_id.clone(), 42);

        alice_proto
            .sync_keyhive(Some(&bob_id))
            .await
            .expect("alice sync_keyhive");

        let sync_request = bob_conn
            .inbound_rx
            .try_recv()
            .expect("bob should receive sync request");
        bob_proto
            .handle_message(&alice_id, sync_request, None)
            .await
            .expect("bob handle sync request");

        let sync_response = alice_conn
            .inbound_rx
            .try_recv()
            .expect("alice should receive sync response");
        alice_proto
            .handle_message(&bob_id, sync_response, None)
            .await
            .expect("alice handle sync response");

        drop(drain_channel(&bob_conn, &alice_id));
        drop(drain_channel(&alice_conn, &bob_id));

        let map = alice_proto.syncpoints.lock().await;
        assert!(
            map.get(&bob_id).is_some(),
            "alice should record a syncpoint for bob after the round"
        );
        assert_eq!(
            map.get(&carol_id),
            Some(42),
            "carol's syncpoint should survive: ingest was a no-op so \
             total_ops didn't advance and invalidation should be skipped"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalidates_other_peers_when_ops_ingested() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        // Initial sync so both sides share the baseline.
        run_sync_round(
            &bob_proto,
            &alice_proto,
            &bob_id,
            &alice_id,
            &bob_conn,
            &alice_conn,
        )
        .await;
        drop(drain_channel(&alice_conn, &bob_id));
        drop(drain_channel(&bob_conn, &alice_id));

        // Bob creates new ops AFTER the initial sync.
        {
            let kh = bob_kh.clone();
            create_group_with_read_members(&kh, &[&alice_id]).await;
        }

        let alice_proto = Arc::new(alice_proto);

        let carol_id = KeyhivePeerId::from_bytes([0xCC; 32]);
        alice_proto
            .syncpoints
            .lock()
            .await
            .set(carol_id.clone(), 42);

        // Alice initiates sync — Bob has new ops so Alice will ingest,
        // advancing total_ops.
        alice_proto
            .sync_keyhive(Some(&bob_id))
            .await
            .expect("alice sync_keyhive");

        let sync_request = bob_conn
            .inbound_rx
            .try_recv()
            .expect("bob should receive sync request");
        bob_proto
            .handle_message(&alice_id, sync_request, None)
            .await
            .expect("bob handle sync request");

        let sync_response = alice_conn
            .inbound_rx
            .try_recv()
            .expect("alice should receive sync response");
        alice_proto
            .handle_message(&bob_id, sync_response, None)
            .await
            .expect("alice handle sync response");

        drop(drain_channel(&bob_conn, &alice_id));
        drop(drain_channel(&alice_conn, &bob_id));

        let map = alice_proto.syncpoints.lock().await;
        assert!(
            map.get(&bob_id).is_some(),
            "alice should record a syncpoint for bob after the round"
        );
        assert_eq!(
            map.get(&carol_id),
            None,
            "carol's syncpoint should be invalidated: alice ingested new \
             ops so total_ops advanced and all stale syncpoints are cleared"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_cache_rebuilds_on_demand_after_stale() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        let alice_proto = Arc::new(alice_proto);

        // Populate cache with baseline state.
        alice_proto.refresh_cache().await.expect("initial refresh");

        // Bob creates new ops.
        {
            let kh = bob_kh.clone();
            create_group_with_read_members(&kh, &[&alice_id]).await;
        }

        // Sync Bob's new ops into Alice's keyhive (but not her cache).
        bob_proto
            .sync_keyhive(Some(&alice_id))
            .await
            .expect("bob sync_keyhive");
        let sync_request = alice_conn
            .inbound_rx
            .try_recv()
            .expect("alice receives sync request");
        alice_proto
            .handle_message(&bob_id, sync_request, None)
            .await
            .expect("alice handles sync request");
        let sync_response = bob_conn
            .inbound_rx
            .try_recv()
            .expect("bob receives sync response");
        bob_proto
            .handle_message(&alice_id, sync_response, None)
            .await
            .expect("bob handles sync response");
        drop(drain_channel(&alice_conn, &bob_id));
        drop(drain_channel(&bob_conn, &alice_id));

        // Before refresh: cache is stale (doesn't reflect Bob's new ops).
        let stale_gen = alice_proto
            .snapshot_state_generation
            .load(Ordering::Acquire);

        // refresh_cache on demand should bring the cache current.
        alice_proto
            .refresh_cache()
            .await
            .expect("on-demand refresh");

        let fresh_gen = alice_proto
            .snapshot_state_generation
            .load(Ordering::Acquire);
        let current_gen = alice_proto.keyhive.state_generation();
        assert_eq!(
            fresh_gen, current_gen,
            "published generation catches up to current generation"
        );
        assert!(
            fresh_gen >= stale_gen,
            "published generation advances or stays same"
        );

        // Verify the cache actually serves the pair.
        let pair = alice_proto.cached_events_for_pair_with_peer(&bob_id).await;
        assert!(
            pair.is_some(),
            "pair should be non-None after on-demand refresh"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inbound_contact_card_refreshes_cache_before_pair_capture() {
        let TwoPeerHarness {
            alice_proto,
            bob_proto,
            bob_kh,
            alice_id,
            bob_id,
            alice_conn,
            bob_conn,
            ..
        } = exchange_contact_cards_and_setup().await;

        let alice_proto = Arc::new(alice_proto);

        // Populate cache with baseline events.
        alice_proto.refresh_cache().await.expect("initial refresh");

        // Bob creates new ops so we can detect staleness/ freshness.
        {
            let kh = bob_kh.clone();
            create_group_with_read_members(&kh, &[&alice_id]).await;
        }

        // Sync Bob's new ops into Alice's keyhive (leaving cache stale).
        bob_proto
            .sync_keyhive(Some(&alice_id))
            .await
            .expect("bob sync_keyhive");
        let sync_request = alice_conn
            .inbound_rx
            .try_recv()
            .expect("alice receives sync request");
        alice_proto
            .handle_message(&bob_id, sync_request, None)
            .await
            .expect("alice handles sync request");
        let sync_response = bob_conn
            .inbound_rx
            .try_recv()
            .expect("bob receives sync response");
        bob_proto
            .handle_message(&alice_id, sync_response, None)
            .await
            .expect("bob handles sync response");
        drop(drain_channel(&alice_conn, &bob_id));
        drop(drain_channel(&bob_conn, &alice_id));

        // Cache is now stale (Alice's keyhive advanced but cache not rebuilt).
        let gen_keyhive_changed = alice_proto.keyhive.state_generation();

        // Bob sends a SyncRequest WITH his contact card.
        // Building the message manually so we control include_contact_card.
        let msg = Message::SyncRequest {
            sender_id: bob_id.clone(),
            target_id: alice_id.clone(),
            request_id: RequestId {
                requestor: bob_id.clone(),
                nonce: alice_proto
                    .next_request_nonce
                    .fetch_add(1, Ordering::Relaxed),
            },
            found: Vec::new(),
            pending: Vec::new(),
        };
        bob_proto
            .sign_and_send(&alice_id, msg, true)
            .await
            .expect("bob signs and sends with contact card");
        let msg_with_cc = alice_conn
            .inbound_rx
            .try_recv()
            .expect("message with contact card");

        // Alice handles the message; internally the contact card is ingested
        // (a no-op here since cards were exchanged at setup), then
        // ensure_cache_current refreshes the cache, then the cached pair is
        // captured and handed to the sync handler.  If the pair were captured
        // *before* the refresh it would still reflect the stale snapshot.
        let status = alice_proto
            .handle_message(&bob_id, msg_with_cc, None)
            .await
            .expect("handle_message with contact card");

        // The cache must be fully current after handle_message returns.
        let gen_after_handle = alice_proto.keyhive.state_generation();
        let pub_after_handle = alice_proto
            .snapshot_state_generation
            .load(Ordering::Acquire);
        assert_eq!(
            pub_after_handle, gen_after_handle,
            "cache is current after handle_message (published == generation)"
        );
        assert!(
            gen_after_handle >= gen_keyhive_changed,
            "cache generation advanced or stayed same"
        );

        // The cached pair for Alice+Bob should now be non-empty,
        // proving the snapshot captured inside handle_message is fresh.
        let pair = alice_proto.cached_events_for_pair_with_peer(&bob_id).await;
        assert!(
            pair.is_some(),
            "cached pair for Alice+Bob is Some after inbound handle_message"
        );
        assert!(
            pair.as_ref().is_some_and(|m| !m.is_empty()),
            "cached pair for Alice+Bob is non-empty after inbound handle_message"
        );

        drop(status);
    }
}

/// INSTR: logs the wall time of a sync handler when it returns.
struct InstrHandlerTimer(&'static str, std::time::Instant); // INSTR
impl Drop for InstrHandlerTimer { // INSTR
    fn drop(&mut self) { tracing::warn!(handler = self.0, wall = ?self.1.elapsed(), "INSTR keyhive handler timing"); } // INSTR
} // INSTR
