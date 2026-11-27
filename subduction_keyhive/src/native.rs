//! [`KeyhiveAccess`] for `keyhive_core`'s [`Keyhive`].

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::error::Error;

use future_form::{FutureForm, Local, Sendable, future_form};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_content::{
    reference::ContentRef,
    store::{CiphertextStore, CiphertextStoreExt},
};
use keyhive_core::{
    archive::Archive,
    certificate::KeylineStorageError,
    contact_card::{ContactCard, ContactCardError},
    content::heads::ContentHeads,
    event::{Event, static_event::StaticEvent},
    keyhive::{Keyhive, ReceiveStaticEventError},
    listener::membership::MembershipListener,
    principal::{
        document::id::DocumentId,
        individual::{ReceivePrekeyOpError, id::IndividualId},
    },
    store::{HydrateError, KeyhiveStore},
};
use keyhive_crypto::{
    digest::Digest, identifier::Identifier, signer::async_signer::AsyncSigner, verified::SignError,
};
use keyline::contract::Keyline;

use crate::{
    access::{AgentEventIndex, ArchiveBytes, KeyhiveAccess, NotIngested, Undecodable},
    message::{EventBytes, EventHash},
};

/// An error from a [`Keyhive`] operation. `E` is the Keyline store's error.
///
/// Each variant displays and reports its source as the underlying error
/// does.
#[derive(Debug, thiserror::Error)]
pub enum NativeKeyhiveError<E: Error + 'static> {
    /// Reading or writing the Keyline store failed.
    #[error(transparent)]
    Storage(#[from] KeylineStorageError<E>),

    /// Signing failed.
    #[error(transparent)]
    Sign(#[from] SignError),

    /// A received contact card does not decode or verify.
    #[error(transparent)]
    ContactCard(#[from] ContactCardError),

    /// Keyhive rejected a received contact card.
    #[error(transparent)]
    ReceiveContactCard(#[from] ReceivePrekeyOpError),

    /// Keyhive rejected an archive.
    #[error(transparent)]
    IngestArchive(#[from] ReceiveStaticEventError<E>),

    /// Loading state from the Keyhive store failed. The state is not "absent"; it was
    /// not read.
    #[error(transparent)]
    Hydrate(#[from] HydrateError),
}

/// Encode a value with Keyhive's canonical codec.
fn encode_value<V: Encode>(value: &V) -> Vec<u8> {
    value.encode().into_bytes()
}

/// Decode a value with Keyhive's canonical codec, accepting only its
/// canonical encoding.
fn decode_value<V: Decode>(bytes: &[u8]) -> Result<V, Undecodable> {
    V::decode(bytes).map_err(|_| Undecodable)
}

const fn digest_to_bytes<U>(digest: &Digest<U>) -> EventHash {
    *digest.raw.as_bytes()
}

#[future_form(
    Sendable where
        S: Send + Sync,
        T: Send + Sync + 'static,
        P: Send + Sync,
        C: Send + Sync,
        L: Send + Sync,
        R: Send + Sync,
        K: Send + Sync,
        H: Send + Sync,
    Local
)]
impl<F, S, T, P, C, L, R, K, H> KeyhiveAccess<F> for Keyhive<F, S, T, P, C, L, R, K, H>
where
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: Decode,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: rand::CryptoRng + rand::RngCore,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    H: KeyhiveStore<F, T>,
    K::Error: Send + Sync + 'static,
{
    type Error = NativeKeyhiveError<K::Error>;

    fn total_ops(&self) -> F::Future<'_, Result<u64, NativeKeyhiveError<K::Error>>> {
        // The protocol compares two counts to see whether an ingest changed
        // anything, so all it needs is a count that grows with what keyhive
        // holds. Keyhive reads it from one counter in its store, so it does not
        // move when a document is loaded and loads none itself.
        F::from_future(async move { Ok(Keyhive::total_ops(self).await?) })
    }

    fn pending_event_hashes(
        &self,
    ) -> F::Future<'_, Result<Vec<EventHash>, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            let digests = Keyhive::pending_event_hashes(self).await;
            Ok(digests.into_iter().map(|d| digest_to_bytes(&d)).collect())
        })
    }

    fn is_known_agent(
        &self,
        id: Identifier,
    ) -> F::Future<'_, Result<bool, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            // `has_agent` answers from what is loaded for a document or an
            // individual, and from Keyline for any other subject. Load `id` as
            // each kind, which stays absent if the store holds nothing for it.
            self.hydrate(DocumentId::from(id)).await?;
            self.hydrate_individuals(&[IndividualId(id)]).await?;
            Ok(self.has_agent(id).await?)
        })
    }

    fn events_for_agent<'a>(
        &'a self,
        id: Identifier,
        within: Option<&'a BTreeSet<EventHash>>,
    ) -> F::Future<'a, Result<BTreeMap<EventHash, EventBytes>, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            Ok(Keyhive::static_events_for_agent(self, id)
                .await
                .map_err(NativeKeyhiveError::from)?
                .into_iter()
                .filter_map(|(digest, event)| {
                    let hash = digest_to_bytes(&digest);
                    within
                        .is_none_or(|within| within.contains(&hash))
                        .then(|| (hash, encode_value(&event)))
                })
                .collect())
        })
    }

    fn event_hashes_for_agent(
        &self,
        id: Identifier,
    ) -> F::Future<'_, Result<BTreeSet<EventHash>, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            Ok(Keyhive::static_events_for_agent(self, id)
                .await
                .map_err(NativeKeyhiveError::from)?
                .keys()
                .map(digest_to_bytes)
                .collect())
        })
    }

    fn all_agent_events<'a>(
        &'a self,
        skip: &'a BTreeSet<EventHash>,
    ) -> F::Future<'a, Result<AgentEventIndex, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            let all = Keyhive::all_agent_events(self)
                .await
                .map_err(NativeKeyhiveError::from)?;

            let events = all
                .events
                .iter()
                .filter_map(|(digest, event)| {
                    let h = digest_to_bytes(digest);
                    (!skip.contains(&h))
                        .then(|| (h, encode_value(&StaticEvent::from(event.clone()))))
                })
                .collect();

            let agent_hashes = all
                .agents()
                .into_iter()
                .map(|agent| {
                    let hashes = all.digests_for(agent).iter().map(digest_to_bytes).collect();
                    (agent.to_bytes(), hashes)
                })
                .collect();

            Ok(AgentEventIndex {
                events,
                agent_hashes,
            })
        })
    }

    fn sign_bytes(
        &self,
        payload: Vec<u8>,
    ) -> F::Future<'_, Result<Vec<u8>, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            let signed = Keyhive::sign_bytes(self, payload)
                .await
                .map_err(NativeKeyhiveError::from)?;
            Ok(encode_value(signed.signed().as_ref()))
        })
    }

    fn ingest_events(
        &self,
        _from: Option<&crate::peer_id::KeyhivePeerId>,
        events: Vec<EventBytes>,
    ) -> F::Future<'_, Result<NotIngested, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            let mut decoded = Vec::with_capacity(events.len());
            let mut undecodable = Vec::new();
            for bytes in events {
                match decode_value::<StaticEvent<T>>(&bytes) {
                    Ok(event) => decoded.push(event),
                    Err(Undecodable) => undecodable.push(bytes),
                }
            }
            // A CGKA operation for a document that is not loaded is neither merged nor
            // dropped: keyhive keeps it pending, as if its predecessors were missing.
            // Load the documents the events name before it sees them. The payload is
            // decoded unverified, which is enough to choose a document to load: keyhive
            // verifies the operation itself, and a forged document id only loads a
            // document in vain. One that does not decode is dropped by keyhive.
            let docs: BTreeSet<DocumentId> = decoded
                .iter()
                .filter_map(|event| {
                    let StaticEvent::CgkaOperation(op) = event else {
                        return None;
                    };
                    op.encoded().decode().ok()
                })
                .map(|op| DocumentId::from(op.doc_id))
                .collect();
            // Likewise the documents of events that wait: a CGKA operation for a
            // document that was not loaded waits as if its predecessors were
            // missing, and replays only once the document is.
            let waiting = Keyhive::pending_documents(self).await;
            for doc in docs.into_iter().chain(waiting) {
                self.hydrate(doc).await?;
            }
            // And the individuals whose prekey operations arrive: keyhive merges them
            // into the individual it holds in memory, which must hold what the store
            // does or the merge would diverge from the stored prekey state.
            let issuers: Vec<IndividualId> = decoded
                .iter()
                .filter_map(|event| match event {
                    StaticEvent::PrekeysExpanded(op) => Some(IndividualId(op.issuer())),
                    StaticEvent::PrekeyRotated(op) => Some(IndividualId(op.issuer())),
                    _ => None,
                })
                .collect();
            self.hydrate_individuals(&issuers).await?;
            let pending = self
                .ingest_unsorted_static_events(decoded)
                .await
                .iter()
                .map(|event| encode_value(event.as_ref()))
                .collect();
            Ok(NotIngested {
                pending,
                undecodable,
            })
        })
    }

    fn receive_contact_card<'a>(
        &'a self,
        card: &'a [u8],
    ) -> F::Future<'a, Result<EventBytes, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            let card = ContactCard::from_bytes(card).map_err(NativeKeyhiveError::from)?;
            // The store may hold prekeys for this individual that are not loaded;
            // receiving the card into a fresh state would diverge from them.
            self.hydrate_individuals(&[card.id()]).await?;
            Keyhive::receive_contact_card(self, &card)
                .await
                .map_err(NativeKeyhiveError::from)?;
            Ok(encode_value(&StaticEvent::from(Event::<T>::from(
                card.op().clone(),
            ))))
        })
    }

    fn to_archive(&self) -> F::Future<'_, Result<ArchiveBytes, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            // An archive of what is in memory would drop every unloaded document, and
            // storage keeps it as the whole state.
            self.hydrate_all().await?;
            // The archive holds this replica's secret keys.
            // `encode_zeroizing` writes them into one exact-sized buffer, so
            // no reallocation leaves a copy behind, and the buffer moves out
            // without another copy.
            Keyhive::into_archive(self)
                .await
                .map(|archive| core::mem::take(&mut *archive.encode_zeroizing()))
                .map_err(NativeKeyhiveError::from)
        })
    }

    fn is_current_archive(&self, archive: &[u8]) -> Result<bool, NativeKeyhiveError<K::Error>> {
        Ok(archive
            .split_first_chunk::<4>()
            .is_some_and(|(magic, rest)| {
                *magic == Archive::<T>::MAGIC && rest.first() == Some(&Archive::<T>::FORMAT)
            }))
    }

    fn ingest_archive<'a>(
        &'a self,
        archive: &'a [u8],
    ) -> F::Future<'a, Result<Result<(), Undecodable>, NativeKeyhiveError<K::Error>>> {
        F::from_future(async move {
            let Ok(archive) = decode_value::<Archive<T>>(archive) else {
                return Ok(Err(Undecodable));
            };
            // An archive carries operations for any document, and its fields are not
            // readable here to say which, so load every document the store holds before
            // its operations merge. This is the one place that genuinely needs them all.
            self.hydrate_all().await?;
            Keyhive::ingest_archive(self, archive)
                .await
                .map(|_pending| Ok(()))
                .map_err(NativeKeyhiveError::from)
        })
    }
}

#[cfg(all(test, feature = "test-utils"))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::test_utils::make_keyhive_over;
    use future_form::Local;
    use keyhive_core::store::memory::MemoryKeyhiveStore;
    use nonempty::nonempty;
    use testresult::TestResult;

    /// Serving a document that is in the store but not in memory does not load
    /// it, and sends the same events as serving it loaded: keyhive reads the
    /// store's rows.
    #[tokio::test(flavor = "current_thread")]
    async fn serving_an_unloaded_document_does_not_hydrate_it() -> TestResult {
        let store = MemoryKeyhiveStore::<[u8; 32]>::default();
        let keyhive = make_keyhive_over(store.clone()).await;
        let me: Identifier = keyhive.id().into();

        let doc = keyhive.generate_doc(vec![], nonempty![[1; 32]]).await?;
        let ops = keyhive
            .cgka_ops_for_doc(&doc)
            .await
            .expect("the founder holds the document's CGKA graph");
        assert!(!ops.is_empty());
        KeyhiveStore::<Local, [u8; 32]>::append_cgka_ops(&store, doc, &ops).await?;

        let served = KeyhiveAccess::<Local>::event_hashes_for_agent(&keyhive, me).await?;
        let count = KeyhiveAccess::<Local>::total_ops(&keyhive).await?;

        keyhive.evict(doc).await;
        assert!(!keyhive.has_document(doc).await);
        assert!(
            keyhive.cgka_ops_for_doc(&doc).await.is_none(),
            "the document is still in memory"
        );

        let after = KeyhiveAccess::<Local>::event_hashes_for_agent(&keyhive, me).await?;
        assert_eq!(after, served);
        assert_eq!(
            KeyhiveAccess::<Local>::all_agent_events(&keyhive, &BTreeSet::new())
                .await?
                .agent_hashes[&me.to_bytes()],
            served
        );
        assert_eq!(KeyhiveAccess::<Local>::total_ops(&keyhive).await?, count);
        assert!(
            !keyhive.has_document(doc).await && keyhive.cgka_ops_for_doc(&doc).await.is_none(),
            "serving loaded the evicted document"
        );

        // Ingesting an operation of an unloaded document loads it rather than
        // leaving the operation pending on a document keyhive reports as absent.
        keyhive.evict(doc).await;
        let encoded: Vec<EventBytes> = ops
            .iter()
            .map(|op| {
                encode_value(&StaticEvent::<[u8; 32]>::CgkaOperation(Box::new(
                    op.signed().as_ref().clone(),
                )))
            })
            .collect();
        let not_ingested = KeyhiveAccess::<Local>::ingest_events(&keyhive, None, encoded).await?;
        assert_eq!(not_ingested, NotIngested::default());
        assert!(keyhive.has_document(doc).await);
        Ok(())
    }
}
