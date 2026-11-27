//! The handler.

use alloc::sync::Arc;
use core::fmt::Debug;

use future_form::{FutureForm, Local, Sendable, future_form};
use sedimentree_core::{
    codec::{decode::Decode, encode::Encode},
    id::SedimentreeId,
};
use subduction_core::{
    authenticated::Authenticated,
    connection::{Connection, message::SyncMessage},
    handler::Handler,
    peer::{id::PeerId, session::Session},
    remote_heads::{RemoteHeads, RemoteHeadsNotifier},
    storage::traits::Storage,
    subduction::error::{IoError, ListenError},
};
use subduction_ephemeral::message::EphemeralMessage;
use subduction_keyhive::KeyhiveMessage;

use crate::Wire;

/// Routes each family of [`Wire`] to its handler. `on_peer_disconnect` goes to all three.
pub struct WireHandler<SyncH, KeyhiveH, EphemeralH> {
    sync: SyncH,
    keyhive: KeyhiveH,
    ephemeral: EphemeralH,
}

impl<S, K, E> WireHandler<S, K, E> {
    /// A handler over the three families' handlers.
    #[must_use]
    pub const fn new(sync: S, keyhive: K, ephemeral: E) -> Self {
        Self {
            sync,
            keyhive,
            ephemeral,
        }
    }

    /// The sync handler.
    #[must_use]
    pub const fn sync(&self) -> &S {
        &self.sync
    }

    /// The keyhive handler.
    #[must_use]
    pub const fn keyhive(&self) -> &K {
        &self.keyhive
    }

    /// The ephemeral handler.
    #[must_use]
    pub const fn ephemeral(&self) -> &E {
        &self.ephemeral
    }
}

impl<S: Debug, K: Debug, E: Debug> Debug for WireHandler<S, K, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WireHandler")
            .field("sync", &self.sync)
            .field("keyhive", &self.keyhive)
            .field("ephemeral", &self.ephemeral)
            .finish()
    }
}

impl<S: RemoteHeadsNotifier, K, E> RemoteHeadsNotifier for WireHandler<S, K, E> {
    fn notify_remote_heads(&self, id: SedimentreeId, peer: PeerId, heads: RemoteHeads) {
        self.sync.notify_remote_heads(id, peer, heads);
    }
}

/// Which family's handler failed.
#[derive(Debug, thiserror::Error)]
pub enum WireHandlerError<S: core::error::Error, K: core::error::Error, E: core::error::Error> {
    /// The sync handler failed.
    #[error("sync: {0}")]
    Sync(S),

    /// The keyhive handler failed.
    #[error("keyhive: {0}")]
    Keyhive(K),

    /// The ephemeral handler failed.
    #[error("ephemeral: {0}")]
    Ephemeral(E),
}

#[future_form(
    Sendable where
        C: Clone + Send + Sync + 'static,
        S: Handler<Sendable, C, Message = SyncMessage> + Send + Sync,
        S::HandlerError: Send + 'static,
        K: Handler<Sendable, C, Message = KeyhiveMessage> + Send + Sync,
        K::HandlerError: Send + 'static,
        E: Handler<Sendable, C, Message = EphemeralMessage> + Send + Sync,
        E::HandlerError: Send + 'static,
    Local where
        C: Clone + 'static,
        S: Handler<Local, C, Message = SyncMessage>,
        K: Handler<Local, C, Message = KeyhiveMessage>,
        E: Handler<Local, C, Message = EphemeralMessage>,
)]
impl<Async: FutureForm, C, S, K, E> Handler<Async, C> for WireHandler<S, K, E>
where
    S: Handler<Async, C, Message = SyncMessage>,
    K: Handler<Async, C, Message = KeyhiveMessage>,
    E: Handler<Async, C, Message = EphemeralMessage>,
{
    type Message = Wire;
    type HandlerError = WireHandlerError<S::HandlerError, K::HandlerError, E::HandlerError>;

    fn handle<'a>(
        &'a self,
        conn: &'a Authenticated<C, Async>,
        message: Wire,
    ) -> Async::Future<'a, Result<(), Self::HandlerError>> {
        Async::from_future(async move {
            match message {
                Wire::Sync(message) => self
                    .sync
                    .handle(conn, *message)
                    .await
                    .map_err(WireHandlerError::Sync),
                Wire::Keyhive(message) => self
                    .keyhive
                    .handle(conn, message)
                    .await
                    .map_err(WireHandlerError::Keyhive),
                Wire::Ephemeral(message) => self
                    .ephemeral
                    .handle(conn, message)
                    .await
                    .map_err(WireHandlerError::Ephemeral),
            }
        })
    }

    fn on_peer_disconnect(&self, session: Session) -> Async::Future<'_, ()> {
        Async::from_future(async move {
            self.sync.on_peer_disconnect(session).await;
            self.keyhive.on_peer_disconnect(session).await;
            self.ephemeral.on_peer_disconnect(session).await;
        })
    }
}

/// The handler of a family this node does not serve: it accepts the frame and drops it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ignore<M>(core::marker::PhantomData<fn() -> M>);

impl<M> Ignore<M> {
    /// An ignoring handler.
    #[must_use]
    pub const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

#[future_form(
    Sendable where
        C: Clone + Send + Sync + 'static,
        M: Encode + Decode + Clone + Send + Debug + 'static + subduction_core::connection::message::TryAsBatchSyncResponse + subduction_core::connection::message::TryAsSubscribeRequest,
    Local where
        C: Clone + 'static,
        M: Encode + Decode + Clone + Send + Debug + 'static + subduction_core::connection::message::TryAsBatchSyncResponse + subduction_core::connection::message::TryAsSubscribeRequest,
)]
impl<Async: FutureForm, C, M> Handler<Async, C> for Ignore<M> {
    type Message = M;
    type HandlerError = core::convert::Infallible;

    fn handle<'a>(
        &'a self,
        _conn: &'a Authenticated<C, Async>,
        _message: M,
    ) -> Async::Future<'a, Result<(), Self::HandlerError>> {
        Async::from_future(async { Ok(()) })
    }

    fn on_peer_disconnect(&self, _session: Session) -> Async::Future<'_, ()> {
        Async::from_future(async {})
    }
}

/// The sync handler `SubductionBuilder::build_composed` hands out is an `Arc`, which is not a
/// [`Handler`]: this is the handler a [`WireHandler`] can hold.
pub struct Shared<H>(pub Arc<H>);

#[future_form(
    Sendable where
        H: Handler<Sendable, C, Message = SyncMessage> + Send + Sync,
        C: Clone + 'static,
    Local where
        H: Handler<Local, C, Message = SyncMessage>,
        C: Clone + 'static,
)]
impl<Async: FutureForm, H, C> Handler<Async, C> for Shared<H> {
    type Message = SyncMessage;
    type HandlerError = H::HandlerError;

    fn handle<'a>(
        &'a self,
        conn: &'a Authenticated<C, Async>,
        message: SyncMessage,
    ) -> Async::Future<'a, Result<(), Self::HandlerError>> {
        self.0.handle(conn, message)
    }

    fn on_peer_disconnect(&self, session: Session) -> Async::Future<'_, ()> {
        self.0.on_peer_disconnect(session)
    }
}

impl<H: RemoteHeadsNotifier> RemoteHeadsNotifier for Shared<H> {
    fn notify_remote_heads(&self, id: SedimentreeId, peer: PeerId, heads: RemoteHeads) {
        self.0.notify_remote_heads(id, peer, heads);
    }
}

/// A listen error of the composed handler is the sync listen error retyped over [`Wire`] (the
/// transport's error types do not depend on the message type), and a keyhive or ephemeral
/// handler's failure is not fatal to the connection, so it becomes a generic handler failure.
impl<Async, Store, Conn, WireMsg, KErr, EErr>
    From<WireHandlerError<ListenError<Async, Store, Conn, SyncMessage>, KErr, EErr>>
    for ListenError<Async, Store, Conn, WireMsg>
where
    Async: FutureForm + Debug,
    Store: Storage<Async> + Debug,
    Conn: Connection<Async, SyncMessage> + Connection<Async, WireMsg> + Debug,
    WireMsg: Encode + Decode,
    Store::Error: Debug,
    <Conn as Connection<Async, SyncMessage>>::SendError:
        Debug + Into<<Conn as Connection<Async, WireMsg>>::SendError>,
    <Conn as Connection<Async, SyncMessage>>::RecvError:
        Debug + Into<<Conn as Connection<Async, WireMsg>>::RecvError>,
    <Conn as Connection<Async, WireMsg>>::SendError: Debug,
    <Conn as Connection<Async, WireMsg>>::RecvError: Debug,
    KErr: core::error::Error,
    EErr: core::error::Error,
{
    fn from(
        error: WireHandlerError<ListenError<Async, Store, Conn, SyncMessage>, KErr, EErr>,
    ) -> Self {
        match error {
            WireHandlerError::Sync(ListenError::IoError(io)) => ListenError::IoError(match io {
                IoError::Storage(e) => IoError::Storage(e),
                IoError::StorageInterrupted => IoError::StorageInterrupted,
                IoError::Load(error) => IoError::Load(error),
                IoError::ConnSend(e) => IoError::ConnSend(e.into()),
                IoError::ConnRecv(e) => IoError::ConnRecv(e.into()),
                IoError::ConnCall(e) => IoError::ConnCall(e.map_send(Into::into)),
                IoError::BlobMismatch(e) => IoError::BlobMismatch(e),
            }),
            WireHandlerError::Sync(ListenError::TrySendError)
            | WireHandlerError::Keyhive(_)
            | WireHandlerError::Ephemeral(_) => ListenError::TrySendError,
        }
    }
}
