//! Subduction [`Handler`] for keyhive frames.
//!
//! [`KeyhiveHandler`] runs [`KeyhiveProtocol`]s over Subduction's own
//! connections. It shares Subduction's connection map and reaches each
//! session through a [`PeerConnections`], which sends on whichever of the
//! session's connections accepts the frame.
//!
//! A [`Session`] is a remote peer under one of our local principals, and a
//! protocol speaks as exactly one principal: it signs as that keyhive and
//! sends the events that keyhive and the remote can both see. The handler
//! therefore keeps one protocol per local principal and runs each session on
//! the protocol of the principal that authenticated it, so a session as a
//! shared principal asks for what that principal sees, never the node's view.
//! A frame on a session whose principal has no protocol is an error.
//!
//! Subduction tells handlers when a session's last connection drops, but not
//! when a session connects. Whoever adds a connection to Subduction calls
//! [`KeyhiveHandler::add_peer`] for a session it had no connection of before.

use alloc::{sync::Arc, vec::Vec};

use async_lock::Mutex;
use dupe::Dupe;
use future_form::{FutureForm, Local, Sendable, future_form};
use nonempty::NonEmpty;
use sedimentree_core::collections::Map;
use subduction_core::{
    authenticated::Authenticated,
    connection::Connection,
    handler::Handler,
    peer::{id::PeerId, session::Session},
};

use crate::{
    KeyhiveAccess, KeyhiveMessage, KeyhivePeerId, KeyhiveProtocol, KeyhiveProtocolError,
    MessageOutcome, SignedMessage, WireDecodeError, connection::KeyhiveConnection,
    storage::KeyhiveStorage,
};

/// Subduction's connections, by session.
pub type Connections<Conn, Async> = Arc<Mutex<Map<Session, NonEmpty<Authenticated<Conn, Async>>>>>;

/// Receives the [`MessageOutcome`] of each keyhive frame a [`KeyhiveHandler`]
/// handles without error.
pub trait OutcomeObserver {
    /// Called with the outcome of a frame on `session`.
    fn on_outcome(&self, session: Session, outcome: MessageOutcome);
}

impl OutcomeObserver for () {
    fn on_outcome(&self, _session: Session, _outcome: MessageOutcome) {}
}

/// A session's keyhive connection. It sends each frame on the session's
/// Subduction connections in turn until one accepts it since a connection
/// can close before Subduction removes it. It never uses a connection of
/// another session to the same peer.
pub struct PeerConnections<Conn: Clone, Async: FutureForm> {
    session: Session,
    connections: Connections<Conn, Async>,
}

impl<Conn: Clone, Async: FutureForm> Clone for PeerConnections<Conn, Async> {
    fn clone(&self) -> Self {
        Self {
            session: self.session,
            connections: self.connections.clone(),
        }
    }
}

impl<Conn: Clone, Async: FutureForm> core::fmt::Debug for PeerConnections<Conn, Async> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerConnections")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

/// Why [`PeerConnections`] could not send a frame.
#[derive(Debug, thiserror::Error)]
pub enum PeerSendError<E: core::error::Error + 'static> {
    /// Subduction has no connection of the session.
    #[error("the session is not connected")]
    NotConnected,

    /// Every connection of the session refused the frame. This is the last
    /// connection's error.
    #[error("send keyhive frame: {0}")]
    Transport(#[source] E),
}

#[future_form(
    Sendable where
        Conn: Connection<Sendable, KeyhiveMessage> + Send + Sync,
        Conn::SendError: Send + 'static,
    Local where
        Conn: Connection<Local, KeyhiveMessage>,
        Conn::SendError: 'static
)]
impl<Async: FutureForm, Conn> KeyhiveConnection<Async> for PeerConnections<Conn, Async> {
    type SendError = PeerSendError<Conn::SendError>;

    fn peer_id(&self) -> KeyhivePeerId {
        keyhive_peer(self.session.remote())
    }

    fn send(&self, message: SignedMessage) -> Async::Future<'_, Result<(), Self::SendError>> {
        Async::from_future(async move {
            let frame = KeyhiveMessage::from_signed(&message);
            let conns: Vec<Authenticated<Conn, Async>> = self
                .connections
                .lock()
                .await
                .get(&self.session)
                .map(|conns| conns.iter().cloned().collect())
                .unwrap_or_default();
            let mut error = PeerSendError::NotConnected;
            for conn in conns {
                match conn.send(&frame).await {
                    Ok(()) => return Ok(()),
                    Err(e) => error = PeerSendError::Transport(e),
                }
            }
            Err(error)
        })
    }
}

/// The protocol a [`KeyhiveHandler`] runs.
pub type HandlerProtocol<K, Store, Conn, Async> =
    KeyhiveProtocol<K, PeerConnections<Conn, Async>, Store, Async>;

/// A session authenticated as a principal that no protocol of the
/// [`KeyhiveHandler`] speaks for.
///
/// A protocol speaks for a principal by holding a keyhive that owns that
/// principal's signer. Only the node's own principal has one today. Routing
/// keyhive frames per principal is in place ([`KeyhiveHandler::with_principal`]),
/// but giving a *shared* principal a keyhive of its own, so that it can sign
/// keyhive operations, is not: sessions authenticated as a shared principal
/// are refused with this error until then.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("no keyhive protocol for the principal {0}")]
pub struct UnknownPrincipal(pub PeerId);

/// Errors from handling a keyhive frame.
#[derive(Debug, thiserror::Error)]
pub enum HandleError<E: core::error::Error + 'static> {
    /// The session authenticated as a principal this handler has no protocol
    /// for.
    #[error(transparent)]
    UnknownPrincipal(#[from] UnknownPrincipal),

    /// The frame's payload is not a signed message.
    #[error("failed to decode keyhive payload")]
    Decode(#[from] WireDecodeError),

    /// The keyhive protocol returned an error. Events can already have been
    /// ingested.
    #[error("keyhive protocol error: {0}")]
    Protocol(#[source] E),
}

/// [`Handler`] that runs the keyhive sync protocol for keyhive frames
/// arriving on Subduction's connections, on the protocol of the principal
/// each session authenticated as.
pub struct KeyhiveHandler<Async, K, Store, Conn, Obs = ()>
where
    Async: FutureForm,
    K: KeyhiveAccess<Async>,
    Store: KeyhiveStorage<Async>,
    Conn: Clone,
    PeerConnections<Conn, Async>: KeyhiveConnection<Async>,
{
    protocols: Map<PeerId, Arc<HandlerProtocol<K, Store, Conn, Async>>>,
    /// The principal [`KeyhiveHandler::new`] was given a protocol for: the
    /// node's own.
    primary: PeerId,
    connections: Connections<Conn, Async>,
    observer: Obs,
}

impl<Async, K, Store, Conn, Obs> Clone for KeyhiveHandler<Async, K, Store, Conn, Obs>
where
    Async: FutureForm,
    K: KeyhiveAccess<Async>,
    Store: KeyhiveStorage<Async>,
    Conn: Clone,
    PeerConnections<Conn, Async>: KeyhiveConnection<Async>,
    Obs: Clone,
{
    fn clone(&self) -> Self {
        Self {
            protocols: self.protocols.clone(),
            primary: self.primary,
            connections: self.connections.clone(),
            observer: self.observer.clone(),
        }
    }
}

impl<Async, K, Store, Conn, Obs> core::fmt::Debug for KeyhiveHandler<Async, K, Store, Conn, Obs>
where
    Async: FutureForm,
    K: KeyhiveAccess<Async>,
    Store: KeyhiveStorage<Async>,
    Conn: Clone,
    PeerConnections<Conn, Async>: KeyhiveConnection<Async>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyhiveHandler").finish_non_exhaustive()
    }
}

impl<Async, K, Store, Conn, Obs> KeyhiveHandler<Async, K, Store, Conn, Obs>
where
    Async: FutureForm,
    K: KeyhiveAccess<Async> + Dupe,
    Store: KeyhiveStorage<Async>,
    Conn: Clone,
    PeerConnections<Conn, Async>: KeyhiveConnection<Async>,
    <PeerConnections<Conn, Async> as KeyhiveConnection<Async>>::SendError: 'static,
{
    /// A handler for `protocol` over `connections`, the map Subduction keeps
    /// (see [`SyncHandler::connections`]). `protocol` speaks for the
    /// principal whose keyhive it holds, which is its [`peer_id`]. `observer`
    /// receives the outcome of each frame.
    ///
    /// [`SyncHandler::connections`]: subduction_core::handler::sync::SyncHandler::connections
    /// [`peer_id`]: KeyhiveProtocol::peer_id
    #[must_use]
    pub fn new(
        protocol: Arc<HandlerProtocol<K, Store, Conn, Async>>,
        connections: Connections<Conn, Async>,
        observer: Obs,
    ) -> Self {
        Self {
            protocols: Map::new(),
            primary: PeerId::new(*protocol.peer_id().verifying_key()),
            connections,
            observer,
        }
        .with_principal(protocol)
    }

    /// The protocol of the principal [`new`](Self::new) was given: the node's
    /// own, for starting rounds, refreshing its cache and serving its contact
    /// card.
    ///
    /// # Panics
    ///
    /// Never: `new` registers the primary protocol and nothing removes it.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn primary(&self) -> &Arc<HandlerProtocol<K, Store, Conn, Async>> {
        self.protocols
            .get(&self.primary)
            .expect("`new` registers the primary protocol")
    }

    /// Also run sessions authenticated as the principal whose keyhive
    /// `protocol` holds, on `protocol`. A later protocol for the same
    /// principal replaces the earlier one.
    #[must_use]
    pub fn with_principal(mut self, protocol: Arc<HandlerProtocol<K, Store, Conn, Async>>) -> Self {
        self.protocols
            .insert(PeerId::new(*protocol.peer_id().verifying_key()), protocol);
        self
    }

    /// The protocol for `principal`, for starting rounds and refreshing its
    /// cache.
    #[must_use]
    pub fn protocol(
        &self,
        principal: &PeerId,
    ) -> Option<&Arc<HandlerProtocol<K, Store, Conn, Async>>> {
        self.protocols.get(principal)
    }

    /// Register `session` with the protocol of its principal. Call it when
    /// Subduction adds the first connection of `session`.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownPrincipal`] if no protocol speaks for the session's
    /// principal.
    pub async fn add_peer(&self, session: Session) -> Result<(), UnknownPrincipal> {
        let protocol = self
            .protocols
            .get(&session.local())
            .ok_or(UnknownPrincipal(session.local()))?;
        protocol
            .add_peer(
                keyhive_peer(session.remote()),
                self.peer_connections(session),
            )
            .await;
        Ok(())
    }

    /// Unregister `session` unless it has a connection again.
    ///
    /// Subduction removes a session's last connection before it reports the
    /// disconnect, so the session can connect again, and be registered, in
    /// between. A session of a principal with no protocol was never
    /// registered, so there is nothing to remove.
    pub async fn remove_peer(&self, session: Session) {
        if self.connections.lock().await.contains_key(&session) {
            return;
        }
        if let Some(protocol) = self.protocols.get(&session.local()) {
            protocol.remove_peer(&keyhive_peer(session.remote())).await;
        }
    }

    fn peer_connections(&self, session: Session) -> PeerConnections<Conn, Async> {
        PeerConnections {
            session,
            connections: self.connections.clone(),
        }
    }
}

const fn keyhive_peer(peer: PeerId) -> KeyhivePeerId {
    KeyhivePeerId::from_bytes(*peer.as_bytes())
}

#[future_form(
    Sendable where
        K: KeyhiveAccess<Sendable> + Dupe + Send + Sync + 'static,
        Store: KeyhiveStorage<Sendable> + Send + Sync + 'static,
        Conn: Connection<Sendable, KeyhiveMessage> + Send + Sync + 'static,
        Conn::SendError: Send + Sync + 'static,
        Obs: OutcomeObserver + Send + Sync,
    Local where
        K: KeyhiveAccess<Local> + Dupe,
        Store: KeyhiveStorage<Local>,
        Conn: Connection<Local, KeyhiveMessage> + 'static,
        Conn::SendError: 'static,
        Obs: OutcomeObserver
)]
impl<Async: FutureForm, K, Store, Conn, Obs> Handler<Async, Conn>
    for KeyhiveHandler<Async, K, Store, Conn, Obs>
{
    type Message = KeyhiveMessage;
    type HandlerError = HandleError<KeyhiveProtocolError<K, PeerConnections<Conn, Async>, Async>>;

    fn handle<'a>(
        &'a self,
        conn: &'a Authenticated<Conn, Async>,
        message: KeyhiveMessage,
    ) -> Async::Future<'a, Result<(), Self::HandlerError>> {
        Async::from_future(async move {
            let signed = message.into_signed()?;
            let session = conn.session();
            let protocol = self
                .protocols
                .get(&session.local())
                .ok_or(UnknownPrincipal(session.local()))?;
            let outcome = protocol
                .handle_message(
                    &keyhive_peer(session.remote()),
                    signed,
                    Some(self.peer_connections(session)),
                )
                .await
                .map_err(HandleError::Protocol)?;
            self.observer.on_outcome(session, outcome);
            Ok(())
        })
    }

    fn on_peer_disconnect(&self, session: Session) -> Async::Future<'_, ()> {
        Async::from_future(self.remove_peer(session))
    }
}

#[cfg(all(test, feature = "test-utils"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use alloc::vec;

    use subduction_core::{
        authenticated::Direction,
        connection::test_utils::{ChannelMockConnection, ChannelMockConnectionHandle},
    };

    use super::*;
    use crate::{
        MemoryKeyhiveStorage,
        test_utils::{SimpleKeyhive, keyhive_peer_id, make_keyhive},
    };

    type MockConn = ChannelMockConnection<KeyhiveMessage>;
    type TestHandler = KeyhiveHandler<Local, SimpleKeyhive, MemoryKeyhiveStorage, MockConn>;
    type TestProtocol = HandlerProtocol<SimpleKeyhive, MemoryKeyhiveStorage, MockConn, Local>;

    const PEER: PeerId = PeerId::new([7; 32]);

    async fn make_protocol() -> (Arc<TestProtocol>, PeerId) {
        let keyhive = make_keyhive().await;
        let peer_id = keyhive_peer_id(&keyhive);
        let principal = PeerId::new(*peer_id.verifying_key());
        let card = keyhive.generate_contact_card().await.unwrap();
        let protocol = KeyhiveProtocol::new(
            Arc::new(Mutex::new(keyhive)),
            MemoryKeyhiveStorage::new(),
            peer_id,
            card.to_bytes(),
        );
        (Arc::new(protocol), principal)
    }

    /// A handler speaking for one principal, which it returns.
    async fn make_handler() -> (TestHandler, PeerId) {
        let (protocol, principal) = make_protocol().await;
        (KeyhiveHandler::new(protocol, Arc::default(), ()), principal)
    }

    /// Open a connection of the session of `PEER` as `principal`.
    async fn connect(
        handler: &TestHandler,
        principal: PeerId,
    ) -> ChannelMockConnectionHandle<KeyhiveMessage> {
        let (conn, handle) = MockConn::new_with_handle(PEER);
        let conn = Authenticated::new_for_test_as(conn, PEER, principal, Direction::Dialed);
        let session = conn.session();
        let mut connections = handler.connections.lock().await;
        match connections.get_mut(&session) {
            Some(conns) => conns.push(conn),
            None => {
                connections.insert(session, NonEmpty::new(conn));
            }
        }
        handle
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remove_peer_keeps_a_session_that_has_a_connection_again() {
        let (handler, principal) = make_handler().await;
        let session = Session::new(PEER, principal);
        let protocol = handler.protocol(&principal).unwrap().clone();
        let _handle = connect(&handler, principal).await;
        handler.add_peer(session).await.unwrap();

        handler.remove_peer(session).await;
        assert!(protocol.has_peer(&keyhive_peer(PEER)).await);

        handler.connections.lock().await.clear();
        handler.remove_peer(session).await;
        assert!(!protocol.has_peer(&keyhive_peer(PEER)).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_frame_is_sent_on_the_first_connection_that_accepts_it() {
        let (handler, principal) = make_handler().await;
        drop(connect(&handler, principal).await);
        let open = connect(&handler, principal).await;
        let message = SignedMessage::new(vec![1, 2, 3]);

        handler
            .peer_connections(Session::new(PEER, principal))
            .send(message.clone())
            .await
            .unwrap();

        let sent = open.outbound_rx.recv().await.unwrap();
        assert_eq!(sent.into_signed().unwrap(), message);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_frame_never_leaves_on_another_principals_session_to_the_same_peer() {
        let (handler, principal) = make_handler().await;
        let shared = PeerId::new([9; 32]);
        let node_side = connect(&handler, principal).await;
        let shared_side = connect(&handler, shared).await;
        let message = SignedMessage::new(vec![4, 5, 6]);

        handler
            .peer_connections(Session::new(PEER, shared))
            .send(message.clone())
            .await
            .unwrap();

        let sent = shared_side.outbound_rx.recv().await.unwrap();
        assert_eq!(sent.into_signed().unwrap(), message);
        assert!(node_side.outbound_rx.is_empty());

        // The session that was not connected has no connection to fall back on.
        let unconnected = Session::new(PEER, PeerId::new([10; 32]));
        assert!(matches!(
            handler
                .peer_connections(unconnected)
                .send(message)
                .await
                .unwrap_err(),
            PeerSendError::NotConnected
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn each_principal_registers_on_its_own_protocol() {
        let (node_protocol, node) = make_protocol().await;
        let (shared_protocol, shared) = make_protocol().await;
        let handler: TestHandler = KeyhiveHandler::new(node_protocol.clone(), Arc::default(), ())
            .with_principal(shared_protocol.clone());

        handler.add_peer(Session::new(PEER, shared)).await.unwrap();
        assert!(shared_protocol.has_peer(&keyhive_peer(PEER)).await);
        assert!(!node_protocol.has_peer(&keyhive_peer(PEER)).await);

        // Dropping the shared session leaves a node session registered.
        handler.add_peer(Session::new(PEER, node)).await.unwrap();
        handler.remove_peer(Session::new(PEER, shared)).await;
        assert!(!shared_protocol.has_peer(&keyhive_peer(PEER)).await);
        assert!(node_protocol.has_peer(&keyhive_peer(PEER)).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_session_as_an_unknown_principal_is_refused() {
        let (handler, _) = make_handler().await;
        let stranger = PeerId::new([11; 32]);

        let refused = handler
            .add_peer(Session::new(PEER, stranger))
            .await
            .unwrap_err();
        assert_eq!(refused.0, stranger);

        // Removing a session that was never registered is not an error.
        handler.remove_peer(Session::new(PEER, stranger)).await;
    }
}
