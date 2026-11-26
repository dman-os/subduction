//! Per-peer outcome of a broadcast / sync round.
//!
//! [`PerSessionSync`] is the return type of
//! [`sync_with_all_peers`](super::Subduction::sync_with_all_peers) and the
//! round-trip `add_*` combinators, letting callers observe which peers acked and
//! which failed. It is a thin newtype over a [`Map`] keyed by [`Session`].

use alloc::vec::Vec;
use core::{fmt, ops::Deref};

use future_form::FutureForm;
use sedimentree_core::collections::Map;

use crate::{
    authenticated::Authenticated,
    connection::{managed::CallError, stats::SyncStats},
    peer::session::Session,
};

/// The per-session value in a [`PerSessionSync`]: `(succeeded, stats, per-connection
/// call errors)`.
pub type PeerSyncEntry<Conn, Async, SendErr> = (
    bool,
    SyncStats,
    Vec<(Authenticated<Conn, Async>, CallError<SendErr>)>,
);

/// The underlying map of a [`PerSessionSync`], keyed by [`Session`].
pub type PerSessionSyncMap<Conn, Async, SendErr> =
    Map<Session, PeerSyncEntry<Conn, Async, SendErr>>;

/// Per-peer outcome of a broadcast / sync round, keyed by [`Session`].
///
/// Returned by [`sync_with_all_peers`](super::Subduction::sync_with_all_peers)
/// and the round-trip `add_*` combinators
/// ([`add_built_batch`](super::Subduction::add_built_batch),
/// [`add_sedimentree`](super::Subduction::add_sedimentree)) so callers can
/// observe which peers acked and which failed.
///
/// Each entry's value is a [`PeerSyncEntry`]. The newtype [`Deref`]s to the
/// underlying [`Map`], so `.get(&peer)`, `.iter()`, `.is_empty()`, etc. work
/// directly; it also implements [`IntoIterator`] and [`FromIterator`].
pub struct PerSessionSync<Conn: Clone, Async: FutureForm, SendErr: core::error::Error>(
    PerSessionSyncMap<Conn, Async, SendErr>,
);

impl<Conn: Clone, Async: FutureForm, SendErr: core::error::Error>
    PerSessionSync<Conn, Async, SendErr>
{
    /// Wrap a per-peer map.
    #[must_use]
    pub(crate) const fn new(map: PerSessionSyncMap<Conn, Async, SendErr>) -> Self {
        Self(map)
    }

    /// The inner per-peer map.
    #[must_use]
    pub const fn as_map(&self) -> &PerSessionSyncMap<Conn, Async, SendErr> {
        &self.0
    }

    /// Consume into the inner per-peer map.
    #[must_use]
    pub fn into_map(self) -> PerSessionSyncMap<Conn, Async, SendErr> {
        self.0
    }
}

impl<Conn: Clone, Async: FutureForm, SendErr: core::error::Error> fmt::Debug
    for PerSessionSync<Conn, Async, SendErr>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PerSessionSync")
            .field("peers", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl<Conn: Clone, Async: FutureForm, SendErr: core::error::Error> Default
    for PerSessionSync<Conn, Async, SendErr>
{
    fn default() -> Self {
        Self(Map::new())
    }
}

impl<Conn: Clone, Async: FutureForm, SendErr: core::error::Error> Deref
    for PerSessionSync<Conn, Async, SendErr>
{
    type Target = PerSessionSyncMap<Conn, Async, SendErr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Conn: Clone, Async: FutureForm, SendErr: core::error::Error> IntoIterator
    for PerSessionSync<Conn, Async, SendErr>
{
    type Item = (Session, PeerSyncEntry<Conn, Async, SendErr>);
    type IntoIter = <PerSessionSyncMap<Conn, Async, SendErr> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Conn: Clone, Async: FutureForm, SendErr: core::error::Error>
    FromIterator<(Session, PeerSyncEntry<Conn, Async, SendErr>)>
    for PerSessionSync<Conn, Async, SendErr>
{
    fn from_iter<T: IntoIterator<Item = (Session, PeerSyncEntry<Conn, Async, SendErr>)>>(
        iter: T,
    ) -> Self {
        Self(iter.into_iter().collect())
    }
}
