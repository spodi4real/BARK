//! Reading and writing control messages on a QUIC stream.
//!
//! Control traffic is low rate and shape-changing, so it is length-prefixed and
//! serialised rather than hand-encoded. The length prefix is bounded before a
//! single byte is allocated, because the peer on the other end of this stream
//! is not yet trusted when the first messages arrive.
//!
//! Video and input do **not** go through here. They have their own formats in
//! `bark-proto`, for the reasons set out there.

use bark_core::{BarkError, Result};
use bark_proto::wire::{self, WireError};
use quinn::{RecvStream, SendStream};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Largest control message accepted. Matches the protocol-level limit.
pub use bark_proto::wire::MAX_MESSAGE;

/// Writes one length-prefixed message.
pub async fn write_message<T: Serialize>(stream: &mut SendStream, message: &T) -> Result<()> {
    let bytes = wire::encode_framed(message).map_err(BarkError::from)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| BarkError::Network(format!("could not send on the connection: {e}")))?;
    Ok(())
}

/// Writes a message and closes the stream, for one-shot exchanges.
pub async fn write_message_and_finish<T: Serialize>(
    stream: &mut SendStream,
    message: &T,
) -> Result<()> {
    write_message(stream, message).await?;
    stream
        .finish()
        .map_err(|e| BarkError::Network(format!("could not close the stream: {e}")))?;
    Ok(())
}

/// Reads one length-prefixed message, waiting for it to arrive in full.
///
/// Returns `Ok(None)` when the peer closed the stream cleanly between messages,
/// which is a normal end of conversation rather than an error.
pub async fn read_message<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(()) => {}
        // A clean close at a message boundary is how conversations end.
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => {
            return Err(BarkError::Network(format!(
                "the connection ended while waiting for a message: {e}"
            )))
        }
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE {
        // Refuse before allocating. A hostile peer must not be able to make us
        // reserve gigabytes by claiming a large length.
        return Err(BarkError::from(WireError::TooLarge { claimed: len, limit: MAX_MESSAGE }));
    }

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.map_err(|e| {
        BarkError::Network(format!("the connection ended part way through a message: {e}"))
    })?;

    let value = wire::decode_exact(&body).map_err(BarkError::from)?;
    Ok(Some(value))
}

/// Reads one message, failing rather than returning `None` if the stream ends.
/// Used where a reply is mandatory, such as the answer to a challenge.
pub async fn read_expected<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<T> {
    read_message(stream).await?.ok_or_else(|| {
        BarkError::Network("the other computer closed the connection without replying".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_length_limit_matches_the_protocol_limit() {
        assert_eq!(MAX_MESSAGE, bark_proto::wire::MAX_MESSAGE);
        assert_eq!(MAX_MESSAGE, 1 << 20);
    }

    #[test]
    fn an_oversized_length_prefix_maps_to_a_clear_error() {
        let e = BarkError::from(WireError::TooLarge { claimed: usize::MAX, limit: MAX_MESSAGE });
        let text = format!("{e}");
        assert!(text.contains("limit"), "got {text}");
    }
}
