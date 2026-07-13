//! Length-prefixed CBOR framing: every message is a 4-byte big-endian length
//! followed by exactly that many bytes of CBOR. The reader knows the frame
//! boundary before parsing any content and enforces [`MAX_FRAME_BODY_LEN`] before
//! allocating.
//!
//! The wire logic lives in crate-private pure functions (`encode_frame`,
//! `decode_header`, `decode_body`); the public API is the frame I/O
//! functions. Two sets of thin I/O wrappers share the pure core: blocking
//! ones over `std::io` for the synchronous server, and — behind the `client`
//! feature — async ones over tokio for async consumers.

use crate::error::IpcError;
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use zeroize::Zeroize as _;

/// Size of the frame header (big-endian u32 body length).
pub(crate) const FRAME_HEADER_LEN: usize = 4;

/// Upper bound on a frame body, enforced on both sides. Generous: the largest
/// legitimate message (a wrapped-root-key response) is well under 1 KiB.
pub const MAX_FRAME_BODY_LEN: usize = 64 * 1024;

/// Blocking read of one frame. `Ok(None)` means the peer closed the stream
/// before starting a frame (normal end of connection); EOF *inside* a frame
/// is an error.
pub fn read_frame_blocking<R, T>(reader: &mut R) -> Result<Option<T>, IpcError>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    match reader.read_exact(&mut header) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut body = vec![0u8; decode_header(header)?];
    reader.read_exact(&mut body)?;
    let decoded = decode_body(&body);
    // Frames can carry key material; scrub the transport copy either way.
    body.zeroize();
    decoded.map(Some)
}

/// Blocking write of one frame (length prefix + CBOR body) and flush.
pub fn write_frame_blocking<W, T>(writer: &mut W, message: &T) -> Result<(), IpcError>
where
    W: Write,
    T: Serialize,
{
    let mut frame = encode_frame(message)?;
    let result = writer.write_all(&frame).and_then(|()| writer.flush());
    frame.zeroize();
    result.map_err(IpcError::Io)
}

/// Async read of one frame; same semantics as [`read_frame_blocking`].
#[cfg(feature = "client")]
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, IpcError>
where
    R: tokio::io::AsyncRead + Unpin,
    T: DeserializeOwned,
{
    use tokio::io::AsyncReadExt as _;

    let mut header = [0u8; FRAME_HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut body = vec![0u8; decode_header(header)?];
    reader.read_exact(&mut body).await?;
    let decoded = decode_body(&body);
    body.zeroize();
    decoded.map(Some)
}

/// Async write of one frame; same semantics as [`write_frame_blocking`].
#[cfg(feature = "client")]
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), IpcError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    use tokio::io::AsyncWriteExt as _;

    let mut frame = encode_frame(message)?;
    let result = async {
        writer.write_all(&frame).await?;
        writer.flush().await
    }
    .await;
    frame.zeroize();
    result.map_err(IpcError::Io)
}

/// Encode one message into a complete wire frame (header + CBOR body).
///
/// The returned buffer may carry key material; callers must zeroize it after
/// writing, as the write helpers do.
pub(crate) fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, IpcError> {
    // Reserve the whole frame bound up front and serialize straight after the
    // header, so any in-bounds message is one allocation and the secret bytes
    // exist in one place — a realloc would strand an unzeroized copy in freed
    // memory. The calls are rare enough (single-digit per process lifetime)
    // that always reserving MAX_FRAME_BODY_LEN costs nothing.
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + MAX_FRAME_BODY_LEN);
    frame.resize(FRAME_HEADER_LEN, 0);
    if let Err(e) = ciborium::ser::into_writer(message, &mut frame) {
        frame.zeroize();
        return Err(IpcError::Encode(format!("{e}")));
    }
    let body_len = frame.len() - FRAME_HEADER_LEN;
    if body_len > MAX_FRAME_BODY_LEN {
        frame.zeroize();
        return Err(IpcError::FrameTooLarge { len: body_len });
    }
    frame[..FRAME_HEADER_LEN].copy_from_slice(&(body_len as u32).to_be_bytes());
    Ok(frame)
}

/// Parse a frame header into the body length, enforcing [`MAX_FRAME_BODY_LEN`]
/// so the caller rejects an oversize frame before allocating for it.
pub(crate) fn decode_header(header: [u8; FRAME_HEADER_LEN]) -> Result<usize, IpcError> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_BODY_LEN {
        return Err(IpcError::FrameTooLarge { len });
    }
    Ok(len)
}

/// Decode one frame body. The buffer may carry key material; callers must
/// zeroize it afterwards, as the read helpers do.
pub(crate) fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, IpcError> {
    ciborium::de::from_reader(body).map_err(|e| IpcError::Decode(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{Request, Response};

    // The sync path a std-only host would use: pure functions, no I/O.
    #[test]
    fn pure_encode_decode_roundtrips_without_io() {
        let frame = encode_frame(&Request::GetTxIoKeypair { epoch: 9 }).expect("encode");
        let header: [u8; FRAME_HEADER_LEN] = frame[..FRAME_HEADER_LEN].try_into().expect("header");
        let body_len = decode_header(header).expect("header length");
        assert_eq!(body_len, frame.len() - FRAME_HEADER_LEN);
        let decoded: Request = decode_body(&frame[FRAME_HEADER_LEN..]).expect("decode");
        let Request::GetTxIoKeypair { epoch } = decoded else {
            panic!("wrong variant");
        };
        assert_eq!(epoch, 9);
    }

    #[test]
    fn blocking_roundtrip_over_in_memory_stream() {
        let mut wire = Vec::new();
        write_frame_blocking(&mut wire, &Request::Ping).expect("write");
        write_frame_blocking(&mut wire, &Response::Pong).expect("write");

        let mut reader = wire.as_slice();
        let first: Request = read_frame_blocking(&mut reader)
            .expect("read")
            .expect("some");
        assert!(matches!(first, Request::Ping));
        let second: Response = read_frame_blocking(&mut reader)
            .expect("read")
            .expect("some");
        assert!(matches!(second, Response::Pong));
        // Clean EOF after the last frame.
        let end: Option<Request> = read_frame_blocking(&mut reader).expect("read");
        assert!(end.is_none());
    }

    #[test]
    fn blocking_oversize_header_is_rejected() {
        let wire = ((MAX_FRAME_BODY_LEN as u32) + 1).to_be_bytes().to_vec();
        let result: Result<Option<Request>, _> = read_frame_blocking(&mut wire.as_slice());
        assert!(matches!(result, Err(IpcError::FrameTooLarge { .. })));
    }

    #[test]
    fn blocking_truncated_body_is_an_error_not_eof() {
        let mut wire = 100u32.to_be_bytes().to_vec();
        wire.extend_from_slice(&[0u8; 10]);
        let result: Result<Option<Request>, _> = read_frame_blocking(&mut wire.as_slice());
        assert!(matches!(result, Err(IpcError::Io(_))));
    }

    #[test]
    fn blocking_unknown_variant_is_a_decode_error() {
        // A well-formed CBOR map that is not any Request variant.
        let bogus = ciborium::Value::Map(vec![(
            ciborium::Value::Text("NoSuchMethod".into()),
            ciborium::Value::Integer(1.into()),
        )]);
        let mut wire = Vec::new();
        write_frame_blocking(&mut wire, &bogus).expect("write");
        let result: Result<Option<Request>, _> = read_frame_blocking(&mut wire.as_slice());
        assert!(matches!(result, Err(IpcError::Decode(_))));
    }

    #[test]
    fn oversize_write_is_rejected() {
        let blob = serde_bytes::ByteBuf::from(vec![0u8; MAX_FRAME_BODY_LEN + 1]);
        let result = write_frame_blocking(&mut Vec::new(), &blob);
        assert!(matches!(result, Err(IpcError::FrameTooLarge { .. })));
    }

    // The async wrappers must be byte-identical to the blocking ones: write
    // async, read blocking (and vice versa).
    #[cfg(feature = "client")]
    mod async_wrappers {
        use super::*;
        use tokio::io::AsyncWriteExt as _;

        #[tokio::test]
        async fn async_and_blocking_interoperate() {
            let (mut client, mut server) = tokio::io::duplex(1024);
            write_frame(&mut client, &Request::GetTxIoKeypair { epoch: 3 })
                .await
                .expect("write");
            let decoded: Request = read_frame(&mut server).await.expect("read").expect("some");
            let frame = encode_frame(&decoded).expect("encode");
            let roundtrip: Request = read_frame_blocking(&mut frame.as_slice())
                .expect("read")
                .expect("some");
            let Request::GetTxIoKeypair { epoch } = roundtrip else {
                panic!("wrong variant");
            };
            assert_eq!(epoch, 3);
        }

        #[tokio::test]
        async fn clean_eof_reads_as_none() {
            let (client, mut server) = tokio::io::duplex(1024);
            drop(client);
            let decoded: Option<Request> = read_frame(&mut server).await.expect("read");
            assert!(decoded.is_none());
        }

        #[tokio::test]
        async fn oversize_header_is_rejected_before_reading_body() {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let len = (MAX_FRAME_BODY_LEN as u32) + 1;
            client.write_all(&len.to_be_bytes()).await.expect("write");
            let result: Result<Option<Request>, _> = read_frame(&mut server).await;
            assert!(matches!(result, Err(IpcError::FrameTooLarge { .. })));
        }

        #[tokio::test]
        async fn truncated_body_is_an_error_not_eof() {
            let (mut client, mut server) = tokio::io::duplex(1024);
            client
                .write_all(&100u32.to_be_bytes())
                .await
                .expect("write");
            client.write_all(&[0u8; 10]).await.expect("write");
            drop(client);
            let result: Result<Option<Request>, _> = read_frame(&mut server).await;
            assert!(matches!(result, Err(IpcError::Io(_))));
        }
    }
}
