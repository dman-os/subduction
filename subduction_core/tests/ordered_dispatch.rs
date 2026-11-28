//! A handler can ask for the messages of a connection that matter in sequence to be handled in
//! the order they arrived (`Handler::is_ordered`), while every other message stays concurrent.
//!
//! The handler marks `HeadsUpdate`s whose id starts with `ORDERED` as ordered and records the
//! order in which handling *finished*, with the first ordered message slow. Without ordering the
//! fast second message finishes first; with it, the second does not start before the first ends.
//! An unordered message sent last finishes before both, so ordering delays only what asks for it.

#![allow(clippy::expect_used, clippy::panic)]

use core::time::Duration;
use std::sync::{Arc, Mutex};

use future_form::Sendable;
use sedimentree_core::{depth::CountLeadingZeroBytes, id::SedimentreeId};
use subduction_core::{
    authenticated::Authenticated,
    connection::{
        message::SyncMessage,
        test_utils::{ChannelMockConnection, InstantTimeout, TokioSpawn, test_signer},
    },
    effects::config::Config,
    handler::sync::SyncHandler,
    peer::{id::PeerId, session::Session},
    policy::open::OpenPolicy,
    remote_heads::{RemoteHeads, RemoteHeadsNotifier},
    storage::memory::MemoryStorage,
    subduction::builder::SubductionBuilder,
};
use subduction_crypto::signer::memory::MemorySigner;
use testresult::TestResult;

type Conn = ChannelMockConnection<SyncMessage>;
type InnerHandler = SyncHandler<
    Sendable,
    Config<MemoryStorage, OpenPolicy, MemorySigner, InstantTimeout, TokioSpawn>,
    Conn,
    CountLeadingZeroBytes,
>;

const ORDERED: u8 = 1;
const UNORDERED: u8 = 2;

/// The first byte is the kind, the second the sequence number.
fn tag(message: &SyncMessage) -> (u8, u8) {
    let SyncMessage::HeadsUpdate { id, .. } = message else {
        panic!("the test sends only heads updates");
    };
    (id.as_bytes()[0], id.as_bytes()[1])
}

struct Recording {
    inner: Arc<InnerHandler>,
    finished: Arc<Mutex<Vec<(u8, u8)>>>,
}

impl subduction_core::handler::Handler<Sendable, Conn> for Recording {
    type Message = SyncMessage;
    type HandlerError =
        <InnerHandler as subduction_core::handler::Handler<Sendable, Conn>>::HandlerError;

    fn handle<'a>(
        &'a self,
        _conn: &'a Authenticated<Conn, Sendable>,
        message: Self::Message,
    ) -> <Sendable as future_form::FutureForm>::Future<'a, Result<(), Self::HandlerError>> {
        <Sendable as future_form::FutureForm>::from_future(async move {
            let (kind, seq) = tag(&message);
            if kind == ORDERED && seq == 0 {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            self.finished.lock().expect("never poisoned").push((kind, seq));
            Ok(())
        })
    }

    fn is_ordered(&self, message: &Self::Message) -> bool {
        tag(message).0 == ORDERED
    }

    fn on_peer_disconnect(
        &self,
        session: Session,
    ) -> <Sendable as future_form::FutureForm>::Future<'_, ()> {
        self.inner.on_peer_disconnect(session)
    }
}

impl RemoteHeadsNotifier for Recording {
    fn notify_remote_heads(&self, id: SedimentreeId, peer: PeerId, heads: RemoteHeads) {
        self.inner.notify_remote_heads(id, peer, heads);
    }
}

fn message(kind: u8, seq: u8) -> SyncMessage {
    let mut id = [0_u8; 32];
    id[0] = kind;
    id[1] = seq;
    SyncMessage::HeadsUpdate {
        id: SedimentreeId::new(id),
        heads: RemoteHeads::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordered_messages_of_a_connection_finish_in_arrival_order_and_others_stay_concurrent()
-> TestResult {
    let peer = PeerId::new([0xA1; 32]);
    let finished = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&finished);

    let (sd, listener, manager, ()) = SubductionBuilder::new()
        .signer(test_signer())
        .storage(MemoryStorage::new(), Arc::new(OpenPolicy))
        .spawner(TokioSpawn)
        .timer(InstantTimeout)
        .build_composed::<Sendable, Conn, Recording, ()>(|sync_handler| {
            (
                Arc::new(Recording {
                    inner: sync_handler,
                    finished: recorded,
                }),
                (),
            )
        });
    let listener_task = tokio::spawn(listener);
    let manager_task = tokio::spawn(manager);

    let (conn, handle) = ChannelMockConnection::new_with_handle(peer);
    sd.add_connection(conn.authenticated()).await?;

    // the slow ordered message first, then a fast ordered one, then an unordered one
    for message in [message(ORDERED, 0), message(ORDERED, 1), message(UNORDERED, 0)] {
        handle.inbound_tx.send(message).await?;
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while finished.lock().expect("never poisoned").len() < 3 {
        assert!(std::time::Instant::now() < deadline, "the messages were never handled");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert_eq!(
        *finished.lock().expect("never poisoned"),
        vec![(UNORDERED, 0), (ORDERED, 0), (ORDERED, 1)],
        "the unordered message is not held back, and the ordered ones finish as they arrived"
    );

    listener_task.abort();
    manager_task.abort();
    Ok(())
}
