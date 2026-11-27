//! One wire envelope and one handler for everything a Subduction connection carries: sync,
//! keyhive and ephemeral frames.
//!
//! Subduction's transport is generic over the message type, and its listen loop hands each
//! inbound message to one [`Handler`]. A node that speaks more than sync therefore needs an
//! envelope type that holds each family's message ([`Wire`], which decodes by the 4-byte schema
//! header the families already carry: `SUM\x00`, `SUE\x00`, `SUK\x00`) and a handler that routes
//! each family to its own ([`WireHandler`]). `subduction_wasm` had one of each, private to the
//! browser build; this crate is the shared one, so native nodes, the browser and embedders such
//! as big_hive speak the same envelope and one handler serves a connection.
//!
//! # Absent families
//!
//! A node that serves no keyhive (or no ephemeral) frames fills that slot with [`Ignore`], which
//! accepts a frame and drops it. A peer that sends a family we do not serve gets no answer, as it
//! would from any node that does not speak it.
//!
//! # The sync handler
//!
//! [`SubductionBuilder::build_composed`] hands the sync handler out as an `Arc`, which is not a
//! [`Handler`] itself: [`Shared`] is the handler that holds it.
//!
//! [`SubductionBuilder::build_composed`]: subduction_core::subduction::builder::SubductionBuilder
//! [`Handler`]: subduction_core::handler::Handler

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod handler;
mod wire;

pub use handler::{Ignore, Shared, WireHandler, WireHandlerError};
pub use wire::Wire;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]
mod tests {
    use alloc::{sync::Arc, vec};
    use core::sync::atomic::{AtomicUsize, Ordering};

    use future_form::{FutureForm, Local};
    use sedimentree_core::codec::{decode::Decode, encode::Encode};
    use subduction_core::{
        authenticated::{Authenticated, Direction},
        connection::{message::SyncMessage, test_utils::ChannelMockConnection},
        handler::Handler,
        peer::{id::PeerId, session::Session},
    };
    use subduction_ephemeral::message::EphemeralMessage;
    use subduction_keyhive::{KeyhiveMessage, SignedMessage};

    use super::*;

    type Conn = ChannelMockConnection<Wire>;

    fn keyhive_frame() -> KeyhiveMessage {
        KeyhiveMessage::from_signed(&SignedMessage::new(vec![1, 2, 3]))
    }

    #[test]
    fn a_keyhive_frame_round_trips_as_its_own_variant() {
        let wire = Wire::from(keyhive_frame());
        let bytes = wire.encode();
        assert!(matches!(Wire::try_decode(&bytes).unwrap(), Wire::Keyhive(_)));
        assert_eq!(Wire::try_decode(&bytes).unwrap(), wire);
    }

    #[test]
    fn an_unknown_or_truncated_schema_is_refused() {
        let mut bytes = Wire::from(keyhive_frame()).encode();
        assert!(Wire::try_decode(&bytes[..2]).is_err());
        bytes[..4].copy_from_slice(b"XXXX");
        assert!(Wire::try_decode(&bytes).is_err());
    }

    /// What a slot counted: the frames it handled and the disconnects it heard.
    #[derive(Default)]
    struct Counts {
        frames: AtomicUsize,
        disconnects: AtomicUsize,
    }

    /// A handler of one family that counts the frames it handles and the disconnects it hears.
    macro_rules! counting {
        ($name:ident, $message:ty) => {
            struct $name(Arc<Counts>);

            impl Handler<Local, Conn> for $name {
                type Message = $message;
                type HandlerError = core::convert::Infallible;

                fn handle<'a>(
                    &'a self,
                    _: &'a Authenticated<Conn, Local>,
                    _: $message,
                ) -> <Local as FutureForm>::Future<'a, Result<(), Self::HandlerError>> {
                    self.0.frames.fetch_add(1, Ordering::SeqCst);
                    Local::from_future(async { Ok(()) })
                }

                fn on_peer_disconnect(
                    &self,
                    _: Session,
                ) -> <Local as FutureForm>::Future<'_, ()> {
                    self.0.disconnects.fetch_add(1, Ordering::SeqCst);
                    Local::from_future(async {})
                }
            }

        };
    }
    counting!(SyncSlot, SyncMessage);
    counting!(KeyhiveSlot, KeyhiveMessage);
    counting!(EphemeralSlot, EphemeralMessage);

    #[tokio::test(flavor = "current_thread")]
    async fn a_frame_reaches_only_its_familys_handler_and_a_disconnect_reaches_all() {
        let peer = PeerId::new([7; 32]);
        let (conn, _handle) = Conn::new_with_handle(peer);
        let conn = Authenticated::new_for_test_as(conn, peer, PeerId::new([8; 32]), Direction::Dialed);
        let (sync, keyhive, ephemeral) = (
            Arc::new(Counts::default()),
            Arc::new(Counts::default()),
            Arc::new(Counts::default()),
        );
        let handler = WireHandler::new(
            SyncSlot(sync.clone()),
            KeyhiveSlot(keyhive.clone()),
            EphemeralSlot(ephemeral.clone()),
        );

        Handler::<Local, Conn>::handle(&handler, &conn, Wire::from(keyhive_frame()))
            .await
            .unwrap();
        Handler::<Local, Conn>::handle(&handler, &conn, Wire::from(keyhive_frame()))
            .await
            .unwrap();
        assert_eq!(
            (
                sync.frames.load(Ordering::SeqCst),
                keyhive.frames.load(Ordering::SeqCst),
                ephemeral.frames.load(Ordering::SeqCst)
            ),
            (0, 2, 0)
        );

        Handler::<Local, Conn>::on_peer_disconnect(&handler, conn.session()).await;
        assert_eq!(
            (
                sync.disconnects.load(Ordering::SeqCst),
                keyhive.disconnects.load(Ordering::SeqCst),
                ephemeral.disconnects.load(Ordering::SeqCst)
            ),
            (1, 1, 1)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_ignored_family_accepts_and_drops_its_frames() {
        let peer = PeerId::new([7; 32]);
        let (conn, _handle) = Conn::new_with_handle(peer);
        let conn = Authenticated::new_for_test_as(conn, peer, PeerId::new([8; 32]), Direction::Dialed);
        let keyhive = Arc::new(Counts::default());
        let handler = WireHandler::new(
            Ignore::<SyncMessage>::new(),
            KeyhiveSlot(keyhive.clone()),
            Ignore::<EphemeralMessage>::new(),
        );

        Handler::<Local, Conn>::handle(&handler, &conn, Wire::from(keyhive_frame()))
            .await
            .unwrap();
        assert_eq!(keyhive.frames.load(Ordering::SeqCst), 1);
    }
}
