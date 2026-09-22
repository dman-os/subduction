//! Storage powerbox for capability-gated access.
//!
//! The [`StoragePowerbox`] wraps a storage backend and policy, enforcing that all
//! operations go through capabilities ([`Fetcher`]/[`Putter`]/[`Destroyer`]).
//!
//! For startup hydration only, use [`hydration_access`][StoragePowerbox::hydration_access].

use alloc::sync::Arc;

use future_form::FutureForm;
use sedimentree_core::id::SedimentreeId;

use super::{
    destroyer::Destroyer, fetcher::Fetcher, local_access::LocalStorageAccess, putter::Putter,
    traits::Storage,
};
use crate::{peer::id::PeerId, policy::storage::StoragePolicy};
use subduction_crypto::verified_author::VerifiedAuthor;

/// A powerbox that wraps storage and policy, only allowing access through capabilities.
///
/// This struct enforces the capability pattern at compile time: the underlying
/// storage is not directly accessible. Peer-facing operations must go through:
/// - [`get_fetcher`][Self::get_fetcher] for authorized reads
/// - [`get_putter`][Self::get_putter] for authorized writes
/// - [`local_destroyer`][Self::local_destroyer] for local cleanup
///
/// For startup hydration, use [`hydration_access`][Self::hydration_access] (crate-internal).
///
/// The powerbox holds both the storage backend and the authorization policy,
/// making it the single trust boundary for capability minting.
#[derive(Debug)]
pub struct StoragePowerbox<Store, Auth> {
    storage: Arc<Store>,
    policy: Arc<Auth>,
}

impl<Store, Auth> StoragePowerbox<Store, Auth> {
    /// Create a new powerbox wrapping the given storage and policy.
    pub fn new(storage: Store, policy: Arc<Auth>) -> Self {
        Self {
            storage: Arc::new(storage),
            policy,
        }
    }

    /// Get a reference to the policy.
    ///
    /// This is useful for connection policy decisions outside of storage access.
    #[must_use]
    pub fn policy(&self) -> &Auth {
        &self.policy
    }

    /// Get a clone of the policy Arc.
    ///
    /// This is useful when you need shared ownership of the policy.
    #[must_use]
    pub fn policy_arc(&self) -> Arc<Auth> {
        self.policy.clone()
    }

    /// Create a destroyer for local cleanup operations.
    ///
    /// Use this for compaction, garbage collection, and other local-only
    /// delete operations. Never hand this capability to peers.
    #[must_use]
    pub fn local_destroyer<Async: FutureForm>(
        &self,
        sedimentree_id: SedimentreeId,
    ) -> Destroyer<Async, Store>
    where
        Store: Storage<Async>,
    {
        Destroyer::new(self.storage.clone(), sedimentree_id)
    }

    /// Create a fetch capability for a peer to access a sedimentree.
    ///
    /// Checks authorization via the policy before minting the capability.
    ///
    /// # Errors
    ///
    /// Returns the policy's `FetchDisallowed` error if authorization fails.
    pub async fn get_fetcher<Async: FutureForm>(
        &self,
        peer: PeerId,
        sedimentree_id: SedimentreeId,
    ) -> Result<Fetcher<Async, Store>, Auth::FetchDisallowed>
    where
        Store: Storage<Async>,
        Auth: StoragePolicy<Async>,
    {
        self.policy.authorize_fetch(peer, sedimentree_id).await?;
        Ok(Fetcher::new(self.storage.clone(), sedimentree_id))
    }

    /// Create a put capability for a remote peer's data.
    ///
    /// Requires a [`VerifiedAuthor`] — the compiler enforces that the
    /// author's signing key has been cryptographically verified before
    /// authorization.
    ///
    /// For local operations (the node writing its own data), use
    /// [`local_putter`](Self::local_putter) instead.
    ///
    /// # Errors
    ///
    /// Returns the policy's `PutDisallowed` error if authorization fails.
    pub async fn get_putter<Async: FutureForm>(
        &self,
        requestor: PeerId,
        author: VerifiedAuthor,
        sedimentree_id: SedimentreeId,
    ) -> Result<Putter<Async, Store>, Auth::PutDisallowed>
    where
        Store: Storage<Async>,
        Auth: StoragePolicy<Async>,
    {
        self.policy
            .authorize_put(requestor, author, sedimentree_id)
            .await?;
        Ok(Putter::new(self.storage.clone(), sedimentree_id))
    }

    /// Create a put capability for local operations.
    ///
    /// The node trusts itself — no policy check is performed. Use this
    /// for locally-authored data (e.g., [`add_commit`], [`add_fragment`]).
    ///
    /// For remote data, use [`get_putter`](Self::get_putter) which
    /// requires a [`VerifiedAuthor`].
    ///
    /// [`add_commit`]: crate::subduction::Subduction::add_commit
    /// [`add_fragment`]: crate::subduction::Subduction::add_fragment
    #[must_use]
    pub(crate) fn local_putter<Async: FutureForm>(
        &self,
        sedimentree_id: SedimentreeId,
    ) -> Putter<Async, Store>
    where
        Store: Storage<Async>,
    {
        Putter::new(self.storage.clone(), sedimentree_id)
    }

    /// Get direct storage access for hydration (startup data loading).
    ///
    /// This bypasses the capability model and should only be used from
    /// [`hydrate`][crate::subduction::Subduction::hydrate] to rebuild
    /// in-memory state from storage.
    ///
    /// All other access should go through [`get_fetcher`](Self::get_fetcher)
    /// or [`get_putter`](Self::get_putter).
    #[must_use]
    pub(crate) fn hydration_access(&self) -> LocalStorageAccess<Store> {
        LocalStorageAccess::new(self.storage.clone())
    }
}

impl<Store, Auth> Clone for StoragePowerbox<Store, Auth> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            policy: self.policy.clone(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::{sync::Arc, vec::Vec};
    use future_form::Local;
    use sedimentree_core::{
        blob::{Blob, BlobMeta},
        loose_commit::{LooseCommit, id::CommitId},
    };
    use subduction_crypto::{signed::Signed, signer::memory::MemorySigner};

    use super::*;
    use crate::{policy::storage::StoragePolicy, storage::memory::MemoryStorage};

    /// A [`StoragePolicy`] double that records every put authorization it is asked for and allows
    /// exactly one author, so the plumbing around it can be asserted on with no keyhive and no
    /// network.
    struct RecordingPolicy {
        allowed: PeerId,
        decisions: async_lock::Mutex<Vec<(PeerId, VerifiedAuthor, SedimentreeId)>>,
    }

    impl RecordingPolicy {
        fn new(allowed: PeerId) -> Self {
            Self {
                allowed,
                decisions: async_lock::Mutex::new(Vec::new()),
            }
        }

        async fn decisions(&self) -> Vec<(PeerId, VerifiedAuthor, SedimentreeId)> {
            self.decisions.lock().await.clone()
        }
    }

    /// Returned when the double refuses a put.
    #[derive(Debug, Clone, Copy)]
    struct PutRefused;

    impl core::fmt::Display for PutRefused {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("put refused by the policy")
        }
    }

    impl core::error::Error for PutRefused {}

    impl StoragePolicy<Local> for RecordingPolicy {
        type FetchDisallowed = PutRefused;
        type PutDisallowed = PutRefused;

        fn authorize_fetch(
            &self,
            _peer: PeerId,
            _sedimentree_id: SedimentreeId,
        ) -> <Local as FutureForm>::Future<'_, Result<(), Self::FetchDisallowed>> {
            Local::from_future(async { Ok(()) })
        }

        fn authorize_put(
            &self,
            requestor: PeerId,
            author: VerifiedAuthor,
            sedimentree_id: SedimentreeId,
        ) -> <Local as FutureForm>::Future<'_, Result<(), Self::PutDisallowed>> {
            Local::from_future(async move {
                self.decisions
                    .lock()
                    .await
                    .push((requestor, author, sedimentree_id));
                if PeerId::from(*author.verifying_key()) == self.allowed {
                    Ok(())
                } else {
                    Err(PutRefused)
                }
            })
        }

        fn filter_authorized_fetch(
            &self,
            _peer: PeerId,
            ids: Vec<SedimentreeId>,
        ) -> <Local as FutureForm>::Future<'_, Vec<SedimentreeId>> {
            Local::from_future(async { ids })
        }
    }

    /// Mint the only kind of [`VerifiedAuthor`] that can exist: one extracted from a signature that
    /// was verified.
    async fn author_for(seed: u8) -> VerifiedAuthor {
        let signer = MemorySigner::from_bytes(&[seed; 32]);
        let blob = Blob::new(alloc::vec![seed]);
        let commit = LooseCommit::new(
            SedimentreeId::new([seed; 32]),
            CommitId::new([seed; 32]),
            alloc::collections::BTreeSet::new(),
            BlobMeta::new(&blob),
        );
        Signed::seal::<Local, _>(&signer, commit)
            .await
            .verified_author()
    }

    /// The powerbox hands the policy the requestor and the author as separate arguments, and mints
    /// a putter only after the policy agrees.
    ///
    /// This is the seam `subduction_keyhive::authorize_put_with` is reached through, and the
    /// distinction it carries is what lets a relay forward a commit it has no access to: the
    /// requestor is the sender of this hop, the author is the signer of the commit. Nothing below
    /// the powerbox may collapse the two — a decision taken on the sender would refuse every
    /// relayed write.
    #[tokio::test]
    async fn get_putter_separates_requestor_from_author_at_the_boundary() {
        let author = author_for(0xCC).await;
        let allowed = PeerId::from(*author.verifying_key());
        let policy = Arc::new(RecordingPolicy::new(allowed));
        let powerbox = StoragePowerbox::new(MemoryStorage::new(), Arc::clone(&policy));

        let sedimentree_id = SedimentreeId::new([0xCC; 32]);
        let relay = PeerId::new([0x11; 32]);

        // The relay has no access of its own; the author is the one the policy allows. The putter
        // must be minted, and the policy must have seen both identities, separately.
        powerbox
            .get_putter::<Local>(relay, author, sedimentree_id)
            .await
            .expect("the author is allowed, so the requestor's own access is irrelevant");

        let decisions = policy.decisions().await;
        assert_eq!(decisions.len(), 1, "exactly one authorization per putter");
        // Read through `first` rather than `[0]`: the length assertion above is the
        // contract, and this keeps the access total so no index can panic.
        let decision = decisions
            .first()
            .expect("the length assertion above pins exactly one decision");
        assert_eq!(decision.0, relay, "the requestor is passed through as-is");
        assert_eq!(
            decision.1.verifying_key(),
            author.verifying_key(),
            "the verified author is passed through as-is"
        );
        assert_eq!(decision.2, sedimentree_id, "the tree under decision");

        // A second, unauthorized author is refused, and the refusal is still a recorded decision —
        // a rejection must not look like a putter that was never asked for.
        let stranger = author_for(0xDD).await;
        assert!(
            powerbox
                .get_putter::<Local>(relay, stranger, sedimentree_id)
                .await
                .is_err(),
            "an author the policy does not allow must not get a putter"
        );
        assert_eq!(
            policy.decisions().await.len(),
            2,
            "the refusal is a recorded decision, not an unasked question"
        );
    }
}
