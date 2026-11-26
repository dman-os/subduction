//! # Subduction Iroh Transport
//!
//! A QUIC transport layer for the Subduction sync protocol using [iroh].
//!
//! Iroh provides peer-to-peer QUIC connections with NAT traversal via relay
//! servers and hole punching. This crate bridges iroh's connection model to
//! Subduction's [`Transport`](subduction_core::transport::Transport) trait.
//!
//! # Authentication
//!
//! This crate runs the full Subduction handshake (`Signed<Challenge>` /
//! `Signed<Response>`) over the QUIC bi-directional stream. While iroh
//! already provides mutual TLS authentication at the transport layer, the
//! Subduction handshake proves that the peer holds the expected _Subduction_
//! signing key. Which key may sign is the caller's declaration, a
//! [`SessionPrincipal`]: the node's own principal must be the endpoint's key,
//! and anything else is a shared principal, recorded as that principal in the
//! resulting [`Session`](subduction_core::peer::session::Session).
//!
//! # Architecture
//!
//! Each connection uses a single QUIC bi-directional stream with
//! length-prefixed framing:
//!
//! ```text
//! [handshake: Challenge/Response exchange]
//!       |
//!       v
//! send()  --> outbound_tx --> [sender task] --> QUIC SendStream
//! QUIC RecvStream --> [listener task] --> inbound_writer --> recv()
//! ```
//!
//! The `call()` method uses the same pending-map + oneshot pattern as
//! the WebSocket and HTTP transports for request-response correlation.
//!
//! # Example
//!
//! ```ignore
//! use iroh::{Endpoint, EndpointAddr};
//! use subduction_iroh::client;
//! use subduction_core::handshake::audience::Audience;
//! use std::time::Duration;
//!
//! // Connect to a peer
//! let ep = Endpoint::bind().await?;
//! let result = client::connect(
//!     &ep, addr, &signer, SessionPrincipal::Node, Audience::known(peer_id),
//! ).await?;
//! tokio::spawn(result.listener_task);
//! tokio::spawn(result.sender_task);
//! subduction.add_connection(result.authenticated).await?;
//! ```
//!
//! [iroh]: https://iroh.computer/

extern crate alloc;

pub mod client;
pub mod error;
pub mod handshake;
pub mod tasks;
pub mod transport;

#[cfg(feature = "server")]
pub mod server;

/// Which principal an iroh session is signed as.
///
/// The remote always sees our endpoint's key as the QUIC peer. The key that
/// signs the Subduction handshake is separate, and the remote authorizes the
/// session by it. A shared principal's private key is deliberately held by more
/// than one party (an invite link, say), so it can never be the endpoint's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPrincipal {
    /// The node's own principal. The signer must be the endpoint's key, which
    /// the connect and accept functions check before touching the network.
    Node,
    /// A principal whose key is shared and is not the endpoint's. Any signer is
    /// accepted, and the session is recorded as that principal.
    Shared,
}

impl SessionPrincipal {
    pub(crate) fn check<S: subduction_crypto::signer::Signer<future_form::Sendable>>(
        self,
        endpoint: &iroh::Endpoint,
        signer: &S,
    ) -> Result<(), error::PrincipalNotEndpoint> {
        let principal = subduction_core::peer::id::PeerId::from(signer.verifying_key());
        let endpoint = subduction_core::peer::id::PeerId::new(*endpoint.id().as_bytes());
        if self == Self::Node && principal != endpoint {
            return Err(error::PrincipalNotEndpoint {
                principal,
                endpoint,
            });
        }
        Ok(())
    }
}

/// ALPN protocol identifier for Subduction over Iroh.
///
/// Both sides must agree on this during the QUIC/TLS handshake.
pub const ALPN: &[u8] = b"subduction/0";
