//! `council-signer` — the security council's key-delivery tool.
//!
//! Speaks the centralized custodian's council port (length-prefixed CBOR
//! over TCP — NOT HTTP) and performs the whole rotation ceremony: generate a
//! key, check a node's status, sign a delivery (with a locally held council
//! key, or by emitting EIP-712 typed data for an external wallet like `cast`
//! or MetaMask and attaching its signature), and deliver.
//!
//! Deliveries carry the epoch root key in PLAINTEXT: only ever connect
//! through the deployment's TLS terminator or tunnel, never a bare
//! untrusted wire.
//! `--node tls://host[:port]` speaks TLS directly to a terminator that
//! proxies raw TCP to the council port (nginx `stream`, stunnel, haproxy
//! `mode tcp`). An HTTP reverse-proxy location with a URL path cannot front
//! this protocol.

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, DeliveryPayload, SignedDeliveryEnvelope,
    network_id_from_chain_id, seal_delivery, typed_data_json,
};
use seismic_custodian_ipc::{read_frame_blocking, write_frame_blocking};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    version,
    about = "Security-council key delivery for the centralized custodian"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh 32-byte epoch root key and print it as 0x-hex.
    GenKey,
    /// Query a node's delivery status: network id and next expected epochs.
    Status {
        /// The node's council port: `host:port` for plain TCP (a tunnel),
        /// or `tls://host[:port]` for a TLS terminator (default port 443).
        #[arg(long)]
        node: String,
    },
    /// Print the EIP-712 typed data (eth_signTypedData_v4 JSON) for a
    /// delivery, for signing with an external wallet:
    /// `cast wallet sign --data '<json>'` or MetaMask. Contains the key's
    /// keccak-256 commitment, never the key.
    TypedData {
        #[command(flatten)]
        delivery: DeliveryArgs,
    },
    /// Sign (or attach a wallet signature to) a delivery and send it.
    Deliver {
        /// The node's council port: `host:port` for plain TCP (a tunnel),
        /// or `tls://host[:port]` for a TLS terminator (default port 443).
        #[arg(long)]
        node: String,
        #[command(flatten)]
        delivery: DeliveryArgs,
        /// Council secret key (0x + 64 hex) to sign locally. Mutually
        /// exclusive with --signature.
        #[arg(long, env = "COUNCIL_SIGNER_KEY", conflicts_with = "signature")]
        council_key: Option<String>,
        /// A wallet-produced 65-byte signature (0x + 130 hex) over this
        /// delivery's typed data (see the typed-data subcommand).
        #[arg(long)]
        signature: Option<String>,
    },
}

#[derive(clap::Args)]
struct DeliveryArgs {
    /// The EVM chain id the target network runs with (must match the node's
    /// --chain-id).
    #[arg(long, env = "SEISMIC_CHAIN_ID")]
    chain_id: u64,
    /// The epoch to install; must be exactly the node's current epoch + 1.
    #[arg(long)]
    epoch: u64,
    /// The 32-byte epoch root key (0x + 64 hex) all purpose keys of this
    /// epoch derive from. This is the secret being rotated in — prefer the
    /// env var over the flag to keep it out of shell history.
    #[arg(long, env = "COUNCIL_ROOT_KEY")]
    key: String,
}

impl DeliveryArgs {
    fn payload(&self) -> Result<DeliveryPayload> {
        Ok(DeliveryPayload {
            network_id: *network_id_from_chain_id(self.chain_id).as_bytes(),
            epoch: self.epoch,
            key: parse_hex32(&self.key).context("--key")?,
        })
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::GenKey => {
            use rand::{TryRngCore as _, rngs::OsRng};
            loop {
                let mut key = [0u8; 32];
                OsRng.try_fill_bytes(&mut key).context("OS RNG")?;
                if secp256k1::SecretKey::from_byte_array(&key).is_ok() {
                    println!("0x{}", hex::encode(key));
                    return Ok(());
                }
            }
        }
        Command::Status { node } => {
            let CouncilResponse::Status(status) = call(&node, &CouncilRequest::GetStatus)? else {
                bail!("unexpected response to GetStatus");
            };
            println!("network_id: 0x{}", hex::encode(status.network_id));
            println!(
                "epoch {} (next delivery: {})",
                status.epoch,
                status.epoch + 1
            );
            Ok(())
        }
        Command::TypedData { delivery } => {
            println!("{}", typed_data_json(&delivery.payload()?));
            Ok(())
        }
        Command::Deliver {
            node,
            delivery,
            council_key,
            signature,
        } => {
            let payload = delivery.payload()?;
            let envelope = match (council_key, signature) {
                (Some(council_key), None) => {
                    let sk = secp256k1::SecretKey::from_byte_array(
                        &parse_hex32(&council_key).context("--council-key")?,
                    )
                    .map_err(|_| anyhow!("--council-key is not a valid secp256k1 scalar"))?;
                    seal_delivery(
                        &sk,
                        &network_id_from_chain_id(delivery.chain_id),
                        delivery.epoch,
                        &payload.key,
                    )
                }
                (None, Some(signature)) => SignedDeliveryEnvelope {
                    payload,
                    signature: parse_hex65(&signature).context("--signature")?,
                },
                _ => bail!("provide exactly one of --council-key or --signature"),
            };
            match call(&node, &CouncilRequest::DeliverEpochKey(envelope))? {
                CouncilResponse::Delivered { epoch } => {
                    println!("delivered: root key for epoch {epoch}");
                    Ok(())
                }
                CouncilResponse::AlreadyDelivered { epoch } => {
                    println!("already delivered: epoch {epoch} (idempotent retry)");
                    Ok(())
                }
                CouncilResponse::Rejected { code, message } => {
                    bail!("rejected ({code:?}): {message}")
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
    }
}

/// One request/response exchange over the council port.
fn call(node: &str, request: &CouncilRequest) -> Result<CouncilResponse> {
    let mut stream = NodeSpec::parse(node)?.connect()?;
    write_frame_blocking(&mut stream, request).context("sending request")?;
    read_frame_blocking(&mut stream)
        .context("reading response")?
        .ok_or_else(|| anyhow!("node closed the connection without a response"))
}

/// How to reach a node's council port. The protocol is length-prefixed CBOR
/// over a byte stream — plain TCP through a tunnel, or TLS straight to a
/// terminator that proxies raw TCP (nginx `stream`, stunnel, haproxy
/// `mode tcp`). It is not HTTP, so URL paths have nowhere to go.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeSpec {
    Tcp { host_port: String },
    Tls { host: String, port: u16 },
}

impl NodeSpec {
    fn parse(node: &str) -> Result<Self> {
        if let Some(rest) = node.strip_prefix("http://").or_else(|| {
            node.strip_prefix("https://")
                .filter(|rest| rest.contains('/'))
        }) {
            let host = rest.split(['/', ':']).next().unwrap_or(rest);
            bail!(
                "the council protocol is raw TCP, not HTTP — an HTTP reverse-proxy \
                 URL (http://, or a path like /custodian) cannot front it. \
                 Terminate TLS with an nginx `stream` block (or stunnel/haproxy \
                 `mode tcp`) that proxies raw TCP to the node's council port, then \
                 use --node tls://{host}:<port>"
            );
        }
        if let Some(rest) = node
            .strip_prefix("tls://")
            .or_else(|| node.strip_prefix("https://"))
        {
            let rest = rest.strip_suffix('/').unwrap_or(rest);
            let (host, port) = match rest.rsplit_once(':') {
                Some((host, port)) => (
                    host,
                    port.parse::<u16>()
                        .with_context(|| format!("invalid port in '{node}'"))?,
                ),
                None => (rest, 443),
            };
            if host.is_empty() {
                bail!("missing host in '{node}'");
            }
            return Ok(NodeSpec::Tls {
                host: host.to_string(),
                port,
            });
        }
        if let Some(rest) = node.strip_prefix("tcp://") {
            return Ok(NodeSpec::Tcp {
                host_port: rest.to_string(),
            });
        }
        if !node.contains(':') {
            bail!(
                "'{node}' has no port: use host:port for plain TCP, or \
                 tls://host[:port] for a TLS terminator"
            );
        }
        Ok(NodeSpec::Tcp {
            host_port: node.to_string(),
        })
    }

    fn connect(&self) -> Result<Box<dyn ReadWrite>> {
        match self {
            NodeSpec::Tcp { host_port } => {
                let stream = TcpStream::connect(host_port)
                    .with_context(|| format!("connecting to {host_port}"))?;
                Ok(Box::new(stream))
            }
            NodeSpec::Tls { host, port } => {
                let roots = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                    .with_context(|| format!("'{host}' is not a valid TLS server name"))?;
                let connection = rustls::ClientConnection::new(Arc::new(config), server_name)
                    .context("initializing TLS")?;
                let tcp = TcpStream::connect((host.as_str(), *port))
                    .with_context(|| format!("connecting to {host}:{port}"))?;
                Ok(Box::new(rustls::StreamOwned::new(connection, tcp)))
            }
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn parse_hex32(value: &str) -> Result<[u8; 32]> {
    let hex_str = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("value must start with 0x"))?;
    hex::decode(hex_str)
        .context("not valid hex")?
        .try_into()
        .map_err(|b: Vec<u8>| anyhow!("must be 32 bytes, got {}", b.len()))
}

fn parse_hex65(value: &str) -> Result<[u8; 65]> {
    let hex_str = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("value must start with 0x"))?;
    hex::decode(hex_str)
        .context("not valid hex")?
        .try_into()
        .map_err(|b: Vec<u8>| anyhow!("must be 65 bytes, got {}", b.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_parses() {
        Cli::command().debug_assert();
    }

    #[test]
    fn node_spec_parses() {
        assert_eq!(
            NodeSpec::parse("10.0.0.1:7876").unwrap(),
            NodeSpec::Tcp {
                host_port: "10.0.0.1:7876".to_string()
            }
        );
        assert_eq!(
            NodeSpec::parse("tcp://node.example.com:7876").unwrap(),
            NodeSpec::Tcp {
                host_port: "node.example.com:7876".to_string()
            }
        );
        assert_eq!(
            NodeSpec::parse("tls://node.example.com:7443").unwrap(),
            NodeSpec::Tls {
                host: "node.example.com".to_string(),
                port: 7443
            }
        );
        // TLS defaults to 443; https:// without a path is accepted as TLS.
        for spec in ["tls://node.example.com", "https://node.example.com"] {
            assert_eq!(
                NodeSpec::parse(spec).unwrap(),
                NodeSpec::Tls {
                    host: "node.example.com".to_string(),
                    port: 443
                }
            );
        }

        // HTTP URLs (and https with a path) get the explanatory error.
        for bad in [
            "https://internal-0.seismictest.net/custodian",
            "http://node.example.com:7876",
        ] {
            let error = NodeSpec::parse(bad).unwrap_err().to_string();
            assert!(error.contains("raw TCP, not HTTP"), "{bad}: {error}");
            assert!(error.contains("tls://"), "{bad}: {error}");
        }

        // Bare host without a port stays an error, with guidance.
        let error = NodeSpec::parse("node.example.com").unwrap_err().to_string();
        assert!(error.contains("has no port"), "{error}");
        assert!(NodeSpec::parse("tls://node.example.com:notaport").is_err());
        assert!(NodeSpec::parse("tls://:443").is_err());
    }

    #[test]
    fn hex_parsers() {
        assert_eq!(
            parse_hex32(&format!("0x{}", hex::encode([7u8; 32]))).unwrap(),
            [7u8; 32]
        );
        assert!(parse_hex32("0x00").is_err());
        assert!(parse_hex65(&format!("0x{}", hex::encode([1u8; 65]))).is_ok());
    }
}
