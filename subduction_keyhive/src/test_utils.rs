//! Test utilities for the keyhive protocol crate.

use alloc::{sync::Arc, vec, vec::Vec};

use async_channel::{Receiver, Sender};
use async_lock::Mutex;
use alloc::collections::{BTreeMap, BTreeSet};
use future_form::{FutureForm, Local};
use futures::{FutureExt, future::LocalBoxFuture};
use keyhive_content::store::memory::MemoryCiphertextStore;
use keyhive_core::{
    content::heads::ContentHeads, keyhive::Keyhive, listener::no_listener::NoListener,
    principal::group::id::GroupId, store::memory::MemoryKeyhiveStore,
};
use keyhive_crypto::{identifier::Identifier, signer::memory::MemorySigner};
use keyline::power::Power;
use keyline_memory::MemoryKeyline;
use rand::rngs::OsRng;

use crate::{
    access::{AgentEventIndex, ArchiveBytes, KeyhiveAccess, NotIngested, Undecodable},
    message::{EventBytes, EventHash},
    connection::KeyhiveConnection,
    peer_id::KeyhivePeerId,
    protocol::{KeyhiveProtocol, MessageOutcome},
    signed_message::SignedMessage,
    storage::MemoryKeyhiveStorage,
};

#[cfg(all(feature = "runtime", feature = "test-utils"))]
pub mod node;

/// The in-memory Keyline store used in tests.
pub type TestKeyline = MemoryKeyline<ContentHeads<[u8; 32]>>;

/// Type alias for the simple keyhive type used in tests.
pub type SimpleKeyhive = Keyhive<
    Local,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    OsRng,
    TestKeyline,
    MemoryKeyhiveStore<[u8; 32]>,
>;

/// An in-memory connection using async channels for testing.
#[derive(Debug, Clone)]
pub struct ChannelConnection {
    remote_peer_id: KeyhivePeerId,
    pub outbound_tx: Sender<SignedMessage>,
    pub inbound_rx: Receiver<SignedMessage>,
}

impl ChannelConnection {
    /// Create a new channel connection with the given channels.
    pub const fn new(
        remote_peer_id: KeyhivePeerId,
        outbound_tx: Sender<SignedMessage>,
        inbound_rx: Receiver<SignedMessage>,
    ) -> Self {
        Self {
            remote_peer_id,
            outbound_tx,
            inbound_rx,
        }
    }
}

/// Channel is closed, cannot send.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("channel closed: cannot send")]
pub struct ChannelSendError;

/// Create a pair of connected channel connections.
///
/// Returns `(conn_a_to_b, conn_b_to_a)` where:
/// * `conn_a_to_b` sends messages from A that B receives
/// * `conn_b_to_a` sends messages from B that A receives
pub fn create_channel_pair(
    peer_a: KeyhivePeerId,
    peer_b: &KeyhivePeerId,
) -> (ChannelConnection, ChannelConnection) {
    let (a_to_b_tx, a_to_b_rx) = async_channel::unbounded();
    let (b_to_a_tx, b_to_a_rx) = async_channel::unbounded();

    let conn_a = ChannelConnection::new(peer_b.clone(), a_to_b_tx, b_to_a_rx);
    let conn_b = ChannelConnection::new(peer_a, b_to_a_tx, a_to_b_rx);

    (conn_a, conn_b)
}

impl KeyhiveConnection<Local> for ChannelConnection {
    type SendError = ChannelSendError;

    fn peer_id(&self) -> KeyhivePeerId {
        self.remote_peer_id.clone()
    }

    fn send(&self, message: SignedMessage) -> LocalBoxFuture<'_, Result<(), Self::SendError>> {
        let tx = self.outbound_tx.clone();
        async move { tx.send(message).await.map_err(|_| ChannelSendError) }.boxed_local()
    }
}

/// Create a simple keyhive instance for testing.
pub async fn make_keyhive() -> SimpleKeyhive {
    make_keyhive_over(MemoryKeyhiveStore::default()).await
}

/// [`make_keyhive`] over `store`, a handle the caller keeps to put into the
/// store what the keyhive should find there when it hydrates.
pub async fn make_keyhive_over(store: MemoryKeyhiveStore<[u8; 32]>) -> SimpleKeyhive {
    let mut csprng = OsRng;
    let sk = MemorySigner::generate(&mut csprng);
    Keyhive::generate(
        sk,
        MemoryCiphertextStore::new(),
        NoListener,
        TestKeyline::new(),
        store,
        csprng,
    )
    .await
    .expect("failed to create keyhive")
}

/// Get the peer ID for a keyhive instance.
pub fn keyhive_peer_id(keyhive: &SimpleKeyhive) -> KeyhivePeerId {
    let id: Identifier = keyhive.id().into();
    KeyhivePeerId::from_bytes(id.to_bytes())
}

/// Type alias for the test protocol type.
pub type TestProtocol =
    KeyhiveProtocol<SimpleKeyhive, ChannelConnection, MemoryKeyhiveStorage, Local>;

/// Create a test protocol with a shared keyhive reference.
///
/// Unlike `make_protocol()` in the protocol tests, this does NOT clone the
/// keyhive. The returned `Arc<Mutex<SimpleKeyhive>>` is the same one the
/// protocol uses, so mutations made through the Arc are visible to the
/// protocol.
pub async fn make_protocol_with_shared_keyhive(
    keyhive: SimpleKeyhive,
) -> (
    TestProtocol,
    Arc<Mutex<SimpleKeyhive>>,
    MemoryKeyhiveStorage,
) {
    let peer_id = keyhive_peer_id(&keyhive);
    let cc = keyhive
        .generate_contact_card()
        .await
        .expect("failed to get contact card");
    let storage = MemoryKeyhiveStorage::new();
    let shared = Arc::new(Mutex::new(keyhive));
    let protocol = TestProtocol::new(shared.clone(), storage.clone(), peer_id, cc.to_bytes());
    (protocol, shared, storage)
}

/// Run a complete sync round from initiator to responder.
///
/// Executes the sync protocol:
/// 1. Initiator sends `SyncRequest`
/// 2. Responder replies with `SyncResponse`
/// 3. Initiator sends `SyncOps` (if any were requested)
/// 4. Confirmation messages are forwarded and handled
///
/// Returns the outcome of handling messages at each side, as
/// `(at_initiator, at_responder)`.
pub async fn run_sync_round(
    initiator_proto: &TestProtocol,
    responder_proto: &TestProtocol,
    initiator_id: &KeyhivePeerId,
    responder_id: &KeyhivePeerId,
    initiator_conn: &ChannelConnection,
    responder_conn: &ChannelConnection,
) -> (MessageOutcome, MessageOutcome) {
    // 1. Initiator sends SyncRequest
    initiator_proto
        .sync_keyhive(Some(responder_id))
        .await
        .expect("initiator sync_keyhive failed");

    // 2. Forward SyncRequest to responder
    let sync_request = responder_conn
        .inbound_rx
        .recv()
        .await
        .expect("failed to receive sync request");
    let mut at_responder = responder_proto
        .handle_message(initiator_id, sync_request, None)
        .await
        .expect("responder failed to handle sync request");

    // 3. Forward SyncResponse to initiator
    let sync_response = initiator_conn
        .inbound_rx
        .recv()
        .await
        .expect("failed to receive sync response");
    let mut at_initiator = initiator_proto
        .handle_message(responder_id, sync_response, None)
        .await
        .expect("initiator failed to handle sync response");

    // 4. Forward any remaining messages (SyncOps, then confirmations)
    //    until both channels are empty.
    loop {
        let mut handled = false;

        if let Ok(msg) = responder_conn.inbound_rx.try_recv() {
            let outcome = responder_proto
                .handle_message(initiator_id, msg, None)
                .await
                .expect("responder failed to handle message");
            at_responder = either(at_responder, outcome);
            handled = true;
        }

        if let Ok(msg) = initiator_conn.inbound_rx.try_recv() {
            let outcome = initiator_proto
                .handle_message(responder_id, msg, None)
                .await
                .expect("initiator failed to handle message");
            at_initiator = either(at_initiator, outcome);
            handled = true;
        }

        if !handled {
            break;
        }
    }

    (at_initiator, at_responder)
}

/// Combine two outcomes, setting each flag that either one sets.
const fn either(a: MessageOutcome, b: MessageOutcome) -> MessageOutcome {
    MessageOutcome {
        ingested: a.ingested || b.ingested,
        confirmed: a.confirmed || b.confirmed,
    }
}

/// Run `rounds` bidirectional sync exchanges between two peers.
///
/// Each round runs `a→b` then `b→a`, matching the pattern used by
/// the three-peer server tests.
pub async fn sync_pair_rounds(
    proto_a: &TestProtocol,
    proto_b: &TestProtocol,
    id_a: &KeyhivePeerId,
    id_b: &KeyhivePeerId,
    conn_a: &ChannelConnection,
    conn_b: &ChannelConnection,
    rounds: usize,
) {
    for _ in 0..rounds {
        run_sync_round(proto_a, proto_b, id_a, id_b, conn_a, conn_b).await;
        run_sync_round(proto_b, proto_a, id_b, id_a, conn_b, conn_a).await;
    }
}

/// Harness for a two-peer test setup with shared keyhives.
pub struct TwoPeerHarness {
    /// Alice's protocol handler.
    pub alice_proto: TestProtocol,
    /// Bob's protocol handler.
    pub bob_proto: TestProtocol,
    /// Shared reference to Alice's keyhive.
    pub alice_kh: Arc<Mutex<SimpleKeyhive>>,
    /// Shared reference to Bob's keyhive.
    pub bob_kh: Arc<Mutex<SimpleKeyhive>>,
    /// Alice's peer ID.
    pub alice_id: KeyhivePeerId,
    /// Bob's peer ID.
    pub bob_id: KeyhivePeerId,
    /// Alice's channel connection (her end of the pair).
    pub alice_conn: ChannelConnection,
    /// Bob's channel connection (his end of the pair).
    pub bob_conn: ChannelConnection,
}

/// Exchange contact cards between two fresh keyhives and set up protocols
/// and channel pairs. Returns a [`TwoPeerHarness`] with everything wired up.
pub async fn exchange_contact_cards_and_setup() -> TwoPeerHarness {
    let alice_keyhive = make_keyhive().await;
    let bob_keyhive = make_keyhive().await;

    // Exchange contact cards at the keyhive level
    let alice_cc = alice_keyhive
        .generate_contact_card()
        .await
        .expect("alice contact card");
    let bob_cc = bob_keyhive
        .generate_contact_card()
        .await
        .expect("bob contact card");
    alice_keyhive
        .receive_contact_card(&bob_cc)
        .await
        .expect("alice receive bob cc");
    bob_keyhive
        .receive_contact_card(&alice_cc)
        .await
        .expect("bob receive alice cc");

    let alice_id = keyhive_peer_id(&alice_keyhive);
    let bob_id = keyhive_peer_id(&bob_keyhive);

    let (alice_proto, alice_kh, _) = make_protocol_with_shared_keyhive(alice_keyhive).await;
    let (bob_proto, bob_kh, _) = make_protocol_with_shared_keyhive(bob_keyhive).await;

    let (alice_conn, bob_conn) = create_channel_pair(alice_id.clone(), &bob_id);

    alice_proto
        .add_peer(bob_id.clone(), alice_conn.clone())
        .await;
    bob_proto.add_peer(alice_id.clone(), bob_conn.clone()).await;

    TwoPeerHarness {
        alice_proto,
        bob_proto,
        alice_kh,
        bob_kh,
        alice_id,
        bob_id,
        alice_conn,
        bob_conn,
    }
}

/// Exchange contact cards between every pair of keyhives.
pub async fn exchange_all_contact_cards(keyhives: &[&SimpleKeyhive]) {
    let mut cards = Vec::new();
    for kh in keyhives {
        cards.push(kh.generate_contact_card().await.expect("contact_card"));
    }
    for (i, kh) in keyhives.iter().enumerate() {
        for (j, cc) in cards.iter().enumerate() {
            if i != j {
                kh.receive_contact_card(cc)
                    .await
                    .expect("receive_contact_card");
            }
        }
    }
}

/// Create a group and add the given peers as Read members.
pub async fn create_group_with_read_members(
    kh: &SimpleKeyhive,
    member_ids: &[&KeyhivePeerId],
) -> GroupId {
    let group_id = kh.generate_group(vec![]).await.expect("generate_group");
    for member_id in member_ids {
        let identifier = member_id.to_identifier().expect("to_identifier");
        kh.add_member(identifier, group_id, Power::Read)
            .await
            .expect("add_member");
    }
    group_id
}

/// A [`SimpleKeyhive`] that remembers who each ingest came from, for tests of what the protocol
/// tells its keyhive.
#[derive(Clone)]
pub struct RecordingKeyhive {
    pub inner: SimpleKeyhive,
    /// The `from` of every [`KeyhiveAccess::ingest_events`] call, in order.
    pub sources: Arc<std::sync::Mutex<Vec<Option<KeyhivePeerId>>>>,
}

impl RecordingKeyhive {
    /// Wrap `inner`.
    pub fn new(inner: SimpleKeyhive) -> Self {
        Self {
            inner,
            sources: Arc::default(),
        }
    }
}

impl dupe::Dupe for RecordingKeyhive {}

impl KeyhiveAccess<Local> for RecordingKeyhive {
    type Error = <SimpleKeyhive as KeyhiveAccess<Local>>::Error;

    fn total_ops(&self) -> <Local as FutureForm>::Future<'_, Result<u64, Self::Error>> {
        KeyhiveAccess::<Local>::total_ops(&self.inner)
    }

    fn pending_event_hashes(
        &self,
    ) -> <Local as FutureForm>::Future<'_, Result<Vec<EventHash>, Self::Error>> {
        KeyhiveAccess::<Local>::pending_event_hashes(&self.inner)
    }

    fn is_known_agent(
        &self,
        id: Identifier,
    ) -> <Local as FutureForm>::Future<'_, Result<bool, Self::Error>> {
        KeyhiveAccess::<Local>::is_known_agent(&self.inner, id)
    }

    fn events_for_agent<'a>(
        &'a self,
        id: Identifier,
        within: Option<&'a BTreeSet<EventHash>>,
    ) -> <Local as FutureForm>::Future<'a, Result<BTreeMap<EventHash, EventBytes>, Self::Error>>
    {
        KeyhiveAccess::<Local>::events_for_agent(&self.inner, id, within)
    }

    fn event_hashes_for_agent(
        &self,
        id: Identifier,
    ) -> <Local as FutureForm>::Future<'_, Result<BTreeSet<EventHash>, Self::Error>> {
        KeyhiveAccess::<Local>::event_hashes_for_agent(&self.inner, id)
    }

    fn all_agent_events<'a>(
        &'a self,
        skip: &'a BTreeSet<EventHash>,
    ) -> <Local as FutureForm>::Future<'a, Result<AgentEventIndex, Self::Error>> {
        KeyhiveAccess::<Local>::all_agent_events(&self.inner, skip)
    }

    fn sign_bytes(
        &self,
        payload: Vec<u8>,
    ) -> <Local as FutureForm>::Future<'_, Result<Vec<u8>, Self::Error>> {
        KeyhiveAccess::<Local>::sign_bytes(&self.inner, payload)
    }

    fn ingest_events(
        &self,
        from: Option<&KeyhivePeerId>,
        events: Vec<EventBytes>,
    ) -> <Local as FutureForm>::Future<'_, Result<NotIngested, Self::Error>> {
        self.sources.lock().unwrap().push(from.cloned());
        KeyhiveAccess::<Local>::ingest_events(&self.inner, from, events)
    }

    fn receive_contact_card<'a>(
        &'a self,
        card: &'a [u8],
    ) -> <Local as FutureForm>::Future<'a, Result<EventBytes, Self::Error>> {
        KeyhiveAccess::<Local>::receive_contact_card(&self.inner, card)
    }

    fn to_archive(
        &self,
    ) -> <Local as FutureForm>::Future<'_, Result<ArchiveBytes, Self::Error>> {
        KeyhiveAccess::<Local>::to_archive(&self.inner)
    }

    fn is_current_archive(&self, archive: &[u8]) -> Result<bool, Self::Error> {
        KeyhiveAccess::<Local>::is_current_archive(&self.inner, archive)
    }

    fn ingest_archive<'a>(
        &'a self,
        archive: &'a [u8],
    ) -> <Local as FutureForm>::Future<'a, Result<Result<(), Undecodable>, Self::Error>> {
        KeyhiveAccess::<Local>::ingest_archive(&self.inner, archive)
    }
}
