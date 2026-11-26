//! Session identity: which remote peer, as which local principal.

use core::fmt;

use super::id::PeerId;

/// A session is one authenticated connection pair, named by the remote peer
/// and the local principal that signed the handshake.
///
/// A node may reach one remote peer under several principals at once: its own
/// node key, and any number of *shared* principals whose private key is
/// deliberately held by more than one party (an invite link, for example).
/// The remote peer is the same in each, but the remote authorizes each session
/// by the power of the principal that signed it, so two sessions to one peer
/// are not interchangeable. Every registry on the dialing side, and every API
/// that addresses "a peer", is keyed by a [`Session`] so a request cannot be
/// routed over a connection that authenticated as a different principal.
///
/// - `remote` is the verified identity of the other end: the responder's
///   signing key on a dialed session, the dialer's signing key on an accepted
///   one.
/// - `local` is the principal this node signed the handshake with.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "bolero", derive(bolero::generator::TypeGenerator))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Session {
    remote: PeerId,
    local: PeerId,
}

impl Session {
    /// The session between `remote` and our principal `local`.
    #[must_use]
    pub const fn new(remote: PeerId, local: PeerId) -> Self {
        Self { remote, local }
    }

    /// The verified identity of the other end of the session.
    #[must_use]
    pub const fn remote(&self) -> PeerId {
        self.remote
    }

    /// The local principal that signed this session's handshake.
    #[must_use]
    pub const fn local(&self) -> PeerId {
        self.local
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.remote, self.local)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The local principal that [`Authenticated::new_for_test`] sessions are
/// authenticated as, for tests that do not care which principal they run under.
///
/// [`Authenticated::new_for_test`]: crate::authenticated::Authenticated::new_for_test
#[cfg(any(test, feature = "test_utils"))]
pub const TEST_LOCAL: PeerId = PeerId::new([0xA5; 32]);
