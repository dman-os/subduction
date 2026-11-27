//! The envelope.

use alloc::{boxed::Box, vec::Vec};

use sedimentree_core::{
    codec::{
        decode::Decode,
        encode::Encode,
        error::{DecodeError, InvalidSchema},
    },
    id::SedimentreeId,
};
use subduction_core::connection::message::{
    BatchSyncResponse, MESSAGE_SCHEMA, SyncMessage, TryAsBatchSyncResponse, TryAsSubscribeRequest,
};
use subduction_ephemeral::message::{EPHEMERAL_SCHEMA, EphemeralMessage};
use subduction_keyhive::{KEYHIVE_SCHEMA, KeyhiveMessage};

/// A message of any family a connection carries.
///
/// Encoding delegates to the inner message, whose schema header is distinct per family. Decoding
/// reads the 4-byte header and dispatches; an unknown schema is an
/// [`InvalidSchema`](sedimentree_core::codec::error::InvalidSchema).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wire {
    /// A sync-protocol message.
    Sync(Box<SyncMessage>),

    /// An ephemeral-protocol message.
    Ephemeral(EphemeralMessage),

    /// A keyhive-protocol message.
    Keyhive(KeyhiveMessage),
}

impl From<SyncMessage> for Wire {
    fn from(message: SyncMessage) -> Self {
        Self::Sync(Box::new(message))
    }
}

impl From<EphemeralMessage> for Wire {
    fn from(message: EphemeralMessage) -> Self {
        Self::Ephemeral(message)
    }
}

impl From<KeyhiveMessage> for Wire {
    fn from(message: KeyhiveMessage) -> Self {
        Self::Keyhive(message)
    }
}

/// Only sync traffic answers a batch sync request, so the listen loop routes the other families
/// through their handlers.
impl TryAsBatchSyncResponse for Wire {
    fn try_as_batch_sync_response(&self) -> Option<&BatchSyncResponse> {
        match self {
            Self::Sync(message) => message.try_as_batch_sync_response(),
            Self::Ephemeral(_) | Self::Keyhive(_) => None,
        }
    }
}

impl TryAsSubscribeRequest for Wire {
    fn try_as_subscribe_request(&self) -> Option<SedimentreeId> {
        match self {
            Self::Sync(message) => message.try_as_subscribe_request(),
            Self::Ephemeral(_) | Self::Keyhive(_) => None,
        }
    }
}

impl Encode for Wire {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Sync(message) => Encode::encode(message.as_ref()),
            Self::Ephemeral(message) => message.encode(),
            Self::Keyhive(message) => message.encode(),
        }
    }

    fn encoded_size(&self) -> usize {
        match self {
            Self::Sync(message) => message.encoded_size(),
            Self::Ephemeral(message) => message.encoded_size(),
            Self::Keyhive(message) => message.encoded_size(),
        }
    }
}

impl Decode for Wire {
    /// The schema (4 bytes) and the total size (4 bytes).
    const MIN_SIZE: usize = 8;

    fn try_decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let schema: [u8; 4] = buf
            .get(0..4)
            .and_then(|schema| schema.try_into().ok())
            .ok_or(DecodeError::MessageTooShort {
                type_name: "Wire schema",
                need: 4,
                have: buf.len(),
            })?;
        match schema {
            MESSAGE_SCHEMA => SyncMessage::try_decode(buf).map(Self::from),
            EPHEMERAL_SCHEMA => EphemeralMessage::try_decode(buf).map(Self::from),
            KEYHIVE_SCHEMA => KeyhiveMessage::try_decode(buf).map(Self::from),
            got => Err(InvalidSchema {
                expected: MESSAGE_SCHEMA,
                got,
            }
            .into()),
        }
    }
}
