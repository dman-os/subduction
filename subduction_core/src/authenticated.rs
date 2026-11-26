//! Authenticated connection wrapper.
//!
//! Provides [`Authenticated<Conn, Async>`], a witness type proving that a connection
//! has completed cryptographic handshake verification.

use core::marker::PhantomData;

use future_form::FutureForm;
use sedimentree_core::codec::{decode::Decode, encode::Encode};

use crate::{
    connection::{Connection, Reconnect},
    peer::{id::PeerId, session::Session},
};

/// A connection that has completed handshake verification.
///
/// This is a witness type proving the connection was authenticated.
/// The inner connection has been verified via cryptographic handshake,
/// the `peer_id` is the verified identity of the remote end from the
/// handshake, and `local_id` is the local principal that signed it. Together
/// they name the [`Session`].
///
/// # Type Parameters
///
/// * `Conn` — The connection type (struct bound relaxed to `Clone`)
/// * `Async` — The [`FutureForm`] (e.g., [`Sendable`] or [`Local`])
///
/// [`Sendable`]: future_form::Sendable
/// [`Local`]: future_form::Local
///
/// # Construction
///
/// Use [`handshake::initiate`] or [`handshake::respond`] to perform
/// handshake verification and obtain an `Authenticated` connection.
///
/// [`handshake::initiate`]: super::handshake::initiate
/// [`handshake::respond`]: super::handshake::respond
pub struct Authenticated<Conn: Clone, Async: FutureForm> {
    inner: Conn,
    peer_id: PeerId,
    local_id: PeerId,
    direction: Direction,
    _marker: PhantomData<fn() -> Async>,
}

/// Which side of the handshake this node was on.
///
/// A node dials its upstream peers (a client dials a sync server, a relay
/// dials the server behind it) and accepts from the peers it serves. Both
/// ends of a simultaneous open are `Dialed`.
///
/// The direction is fixed for the life of the wrapper; [`Reconnect`] swaps
/// only the inner connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// This node initiated the handshake (`handshake::initiate`).
    Dialed,
    /// This node accepted the handshake (`handshake::respond`).
    Accepted,
}

impl<Conn: Clone, Async: FutureForm> Clone for Authenticated<Conn, Async> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            peer_id: self.peer_id,
            local_id: self.local_id,
            direction: self.direction,
            _marker: PhantomData,
        }
    }
}

impl<Conn: Clone + PartialEq, Async: FutureForm> PartialEq for Authenticated<Conn, Async> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<Conn: Clone + core::fmt::Debug, Async: FutureForm> core::fmt::Debug
    for Authenticated<Conn, Async>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authenticated")
            .field("peer_id", &self.peer_id)
            .field("local_id", &self.local_id)
            .field("direction", &self.direction)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<Conn: Clone, Async: FutureForm> Authenticated<Conn, Async> {
    /// Construct from a successful handshake.
    ///
    /// This is only accessible within the `connection` module.
    /// Use [`handshake::initiate`] or [`handshake::respond`] to obtain
    /// an `Authenticated` connection.
    ///
    /// [`handshake::initiate`]: super::handshake::initiate
    /// [`handshake::respond`]: super::handshake::respond
    pub(crate) fn from_handshake(
        inner: Conn,
        peer_id: PeerId,
        local_id: PeerId,
        direction: Direction,
    ) -> Self {
        Self {
            inner,
            peer_id,
            local_id,
            direction,
            _marker: PhantomData,
        }
    }

    /// The verified peer identity, established during the handshake.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The local principal that signed this connection's handshake.
    ///
    /// This is the node's own key for an ordinary session, or a shared
    /// principal's key for a session opened under one. The remote authorizes
    /// the session by this principal's power, not by the node's.
    pub const fn local_id(&self) -> PeerId {
        self.local_id
    }

    /// The session this connection belongs to: the remote peer and the local
    /// principal that authenticated it.
    pub const fn session(&self) -> Session {
        Session::new(self.peer_id, self.local_id)
    }

    /// Which side of the handshake this node was on.
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Transform the inner connection while preserving the authentication proof.
    ///
    /// This is useful when wrapping an authenticated connection in a higher-level
    /// type (e.g., `WebSocket` → `UnifiedWebSocket`) while preserving the
    /// proof that the underlying connection completed handshake verification.
    #[must_use]
    pub fn map<D: Clone>(self, f: impl FnOnce(Conn) -> D) -> Authenticated<D, Async> {
        Authenticated {
            inner: f(self.inner),
            peer_id: self.peer_id,
            local_id: self.local_id,
            direction: self.direction,
            _marker: PhantomData,
        }
    }

    /// Construct for testing purposes only, as the [`TEST_LOCAL`] principal.
    ///
    /// This bypasses handshake verification and should only be used in tests.
    /// Callers state which side of the (skipped) handshake this end is on,
    /// since propagation behavior depends on it.
    ///
    /// [`TEST_LOCAL`]: crate::peer::session::TEST_LOCAL
    #[cfg(any(test, feature = "test_utils"))]
    pub fn new_for_test(inner: Conn, peer_id: PeerId, direction: Direction) -> Self {
        Self::new_for_test_as(inner, peer_id, crate::peer::session::TEST_LOCAL, direction)
    }

    /// Like [`new_for_test`](Self::new_for_test), for a session as an
    /// explicit local principal.
    #[cfg(any(test, feature = "test_utils"))]
    pub fn new_for_test_as(
        inner: Conn,
        peer_id: PeerId,
        local_id: PeerId,
        direction: Direction,
    ) -> Self {
        Self {
            inner,
            peer_id,
            local_id,
            direction,
            _marker: PhantomData,
        }
    }

    /// Access the inner connection.
    pub const fn inner(&self) -> &Conn {
        &self.inner
    }

    /// Consume and return the inner connection.
    pub fn into_inner(self) -> Conn {
        self.inner
    }
}

// ── Delegation impls ────────────────────────────────────────────────────

impl<Conn: Connection<Async, WireMsg>, Async: FutureForm, WireMsg: Encode + Decode>
    Connection<Async, WireMsg> for Authenticated<Conn, Async>
{
    type DisconnectionError = Conn::DisconnectionError;
    type SendError = Conn::SendError;
    type RecvError = Conn::RecvError;

    fn disconnect(&self) -> Async::Future<'_, Result<(), Self::DisconnectionError>> {
        self.inner.disconnect()
    }

    fn send(&self, message: &WireMsg) -> Async::Future<'_, Result<(), Self::SendError>> {
        self.inner.send(message)
    }

    fn recv(&self) -> Async::Future<'_, Result<WireMsg, Self::RecvError>> {
        self.inner.recv()
    }
}

impl<Conn: Reconnect<Async, WireMsg>, Async: FutureForm, WireMsg: Encode + Decode>
    Reconnect<Async, WireMsg> for Authenticated<Conn, Async>
{
    type ReconnectionError = Conn::ReconnectionError;

    fn reconnect(&mut self) -> Async::Future<'_, Result<(), Self::ReconnectionError>> {
        self.inner.reconnect()
    }

    fn should_retry(&self, error: &Self::ReconnectionError) -> bool {
        self.inner.should_retry(error)
    }
}
