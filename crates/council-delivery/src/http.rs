//! Council HTTP transport: one unframed CBOR message per POST body.
//!
//! Envelope storage and signing formats are independent of this transport.
//! The optional synchronous client is shared by the CLI and observer custodians.

use anyhow::{Result, anyhow, ensure};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Cursor, Read};
use zeroize::Zeroizing;

pub const COUNCIL_PATH: &str = "/v1/council";
pub const CBOR_CONTENT_TYPE: &str = "application/cbor";
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Bound reads even when Content-Length is absent or inaccurate. Callers must
/// supply a reader with a transport deadline; this limits bytes, not time.
pub fn read_body(reader: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BODY_BYTES, "council body exceeds 64 KiB");
    Ok(bytes)
}

pub fn encode<T: Serialize>(message: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    ciborium::into_writer(message, &mut *bytes)?;
    ensure!(bytes.len() <= MAX_BODY_BYTES, "council body exceeds 64 KiB");
    Ok(bytes)
}

/// Reject trailing data and avoid echoing parser diagnostics containing secrets.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX_BODY_BYTES, "council body exceeds 64 KiB");
    let mut reader = Cursor::new(bytes);
    let message =
        ciborium::from_reader(&mut reader).map_err(|_| anyhow!("invalid council CBOR body"))?;
    ensure!(
        reader.position() == bytes.len() as u64,
        "trailing council CBOR data"
    );
    Ok(message)
}

#[cfg(feature = "http-client")]
mod client {
    use super::*;
    use crate::{CouncilRequest, CouncilResponse};
    use anyhow::Context as _;
    use std::time::Duration;
    use url::{Host, Url};

    pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// HTTPS base URL with an optional proxy prefix; HTTP is allowed only on
    /// loopback for a local service or secure tunnel. No credentials or queries.
    pub fn endpoint_url(base: &str) -> Result<Url> {
        let mut url =
            Url::parse(base).map_err(|_| anyhow!("expected an HTTPS council base URL"))?;
        ensure!(url.host().is_some(), "council URL requires a host");
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "council URL must not contain credentials, a query, or a fragment"
        );
        let loopback = match url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain(name)) => name == "localhost",
            None => false,
        };
        ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && loopback),
            "use HTTPS; plain HTTP is allowed only on loopback (local service or tunnel)"
        );
        let path = format!("{}{COUNCIL_PATH}", url.path().trim_end_matches('/'));
        url.set_path(&path);
        Ok(url)
    }

    /// Blocking client with certificate verification, no redirects, no automatic
    /// environment proxy, no compression, and bounded request/response bodies.
    pub struct CouncilHttpClient {
        endpoint: Url,
        agent: ureq::Agent,
    }

    impl CouncilHttpClient {
        pub fn new(base: &str) -> Result<Self> {
            Self::with_timeout(base, REQUEST_TIMEOUT)
        }

        pub fn with_timeout(base: &str, timeout: Duration) -> Result<Self> {
            let endpoint = endpoint_url(base)?;
            let agent = ureq::Agent::config_builder()
                .proxy(None)
                .max_redirects(0)
                .http_status_as_error(false)
                .timeout_connect(Some(CONNECT_TIMEOUT.min(timeout)))
                .timeout_global(Some(timeout))
                .build()
                .new_agent();
            Ok(Self { endpoint, agent })
        }

        pub fn call(&self, request: &CouncilRequest) -> Result<CouncilResponse> {
            let bytes = encode(request)?;
            let mut response = self
                .agent
                .post(self.endpoint.as_str())
                .header("Content-Type", CBOR_CONTENT_TYPE)
                .header("Accept", CBOR_CONTENT_TYPE)
                .header("Cache-Control", "no-store")
                .send(bytes.as_slice())
                .context("council HTTP request failed")?;
            // Never include response bodies in errors: they can contain root keys.
            ensure!(
                response.status().as_u16() == 200,
                "council HTTP status {}",
                response.status().as_u16()
            );
            ensure!(
                response
                    .headers()
                    .get("Content-Type")
                    .and_then(|v| v.to_str().ok())
                    == Some(CBOR_CONTENT_TYPE),
                "expected application/cbor response"
            );
            if let Some(length) = response.headers().get("Content-Length") {
                let length: u64 = length.to_str()?.parse()?;
                ensure!(
                    length <= MAX_BODY_BYTES as u64,
                    "council body exceeds 64 KiB"
                );
            }
            let bytes = read_body(response.body_mut().as_reader())
                .context("reading council HTTP response")?;
            decode(&bytes)
        }
    }
}

#[cfg(feature = "http-client")]
pub use client::{CONNECT_TIMEOUT, CouncilHttpClient, REQUEST_TIMEOUT, endpoint_url};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CouncilRequest;

    #[test]
    fn cbor_is_unframed_and_strictly_bounded() {
        let mut body = encode(&CouncilRequest::Ping).unwrap();
        assert!(matches!(
            decode::<CouncilRequest>(&body).unwrap(),
            CouncilRequest::Ping
        ));
        body.push(0);
        assert!(decode::<CouncilRequest>(&body).is_err());
        assert!(read_body(&vec![0; MAX_BODY_BYTES + 1][..]).is_err());
        assert!(
            decode::<CouncilRequest>(b"secret not valid CBOR")
                .unwrap_err()
                .to_string()
                == "invalid council CBOR body"
        );
    }

    #[cfg(feature = "http-client")]
    #[test]
    fn validates_urls_and_preserves_proxy_prefix() {
        for (base, expected) in [
            ("https://example.com", "https://example.com/v1/council"),
            (
                "https://example.com/custodian/",
                "https://example.com/custodian/v1/council",
            ),
            ("http://127.0.0.1:7876", "http://127.0.0.1:7876/v1/council"),
            (
                "http://[::1]:7876/prefix",
                "http://[::1]:7876/prefix/v1/council",
            ),
        ] {
            assert_eq!(endpoint_url(base).unwrap().as_str(), expected);
        }
        for bad in [
            "node:7876",
            "tls://node:7443",
            "http://example.com",
            "https://user:secret@example.com",
            "https://example.com?key=secret",
            "https://example.com/#fragment",
        ] {
            assert!(endpoint_url(bad).is_err(), "accepted {bad}");
        }
    }
}
