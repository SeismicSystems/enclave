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
    canonical_envelope_bytes, envelope_from_bytes, network_id_from_chain_id, seal_delivery,
    typed_data_json,
};
use seismic_custodian_ipc::{read_frame_blocking, write_frame_blocking};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
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
    /// Query each node's delivery status: network id and next expected
    /// epoch.
    Status {
        #[command(flatten)]
        target: Target,
    },
    /// Print the EIP-712 typed data (eth_signTypedData_v4 JSON) for a
    /// delivery, for signing with an external wallet:
    /// `cast wallet sign --data '<json>'` or MetaMask. Contains the key's
    /// keccak-256 commitment, never the key.
    TypedData {
        #[command(flatten)]
        delivery: DeliveryArgs,
    },
    /// Sign (or attach a wallet signature to) a delivery and send it to
    /// every target node.
    Deliver {
        #[command(flatten)]
        target: Target,
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
        /// Also save the sealed envelope as `<epoch>.cbor` in this directory
        /// (dir 0700, file 0600 — it contains the plaintext root key), so a
        /// node joining later can be brought current with deliver-batch. The
        /// file is written before sending, so it survives a failed send.
        #[arg(long, env = "COUNCIL_ENVELOPE_DIR")]
        save_dir: Option<PathBuf>,
    },
    /// Send every saved envelope each target node is missing, in epoch
    /// order — brings a freshly joined node (or a whole fleet) from its
    /// current epoch to the latest saved one in one command.
    DeliverBatch {
        #[command(flatten)]
        target: Target,
        /// Directory of `<epoch>.cbor` envelopes, as written by
        /// `deliver --save-dir`.
        #[arg(long, env = "COUNCIL_ENVELOPE_DIR")]
        envelope_dir: PathBuf,
    },
}

/// Where to send: one node, or every node in a TOML file. Exactly one.
#[derive(clap::Args)]
struct Target {
    /// One node's council port: `host:port` for plain TCP (a tunnel), or
    /// `tls://host[:port]` for a TLS terminator (default port 443).
    #[arg(
        long,
        required_unless_present = "nodes_file",
        conflicts_with = "nodes_file"
    )]
    node: Option<String>,
    /// TOML file listing every node's council port, in --node syntax:
    /// `nodes = ["10.0.0.1:7876", "tls://node-1.example.com:7443"]`.
    /// The command runs against each node in order, continues past
    /// per-node failures, and exits non-zero if any node failed.
    #[arg(long)]
    nodes_file: Option<PathBuf>,
}

impl Target {
    /// The node list, every entry validated upfront so a typo fails before
    /// anything is sent anywhere.
    fn resolve(&self) -> Result<Vec<String>> {
        let nodes = match (&self.node, &self.nodes_file) {
            (Some(node), None) => vec![node.clone()],
            (None, Some(path)) => {
                #[derive(serde::Deserialize)]
                struct NodesFile {
                    nodes: Vec<String>,
                }
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let file: NodesFile =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                if file.nodes.is_empty() {
                    bail!("{} lists no nodes", path.display());
                }
                file.nodes
            }
            _ => unreachable!("clap enforces exactly one of --node/--nodes-file"),
        };
        for node in &nodes {
            NodeSpec::parse(node).with_context(|| format!("invalid node '{node}'"))?;
        }
        Ok(nodes)
    }
}

/// Run one action per node, continuing past failures; error out at the end
/// naming every node that failed (so a down node never blocks the rest of
/// the fleet, and scripts still see a non-zero exit).
fn for_each_node(nodes: &[String], action: impl Fn(&str) -> Result<()>) -> Result<()> {
    let mut failed: Vec<String> = Vec::new();
    for node in nodes {
        if let Err(e) = action(node) {
            eprintln!("{node}: FAILED: {e:#}");
            failed.push(node.clone());
        }
    }
    if !failed.is_empty() {
        bail!(
            "failed for {} of {} node(s): {}",
            failed.len(),
            nodes.len(),
            failed.join(", ")
        );
    }
    Ok(())
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
        Command::Status { target } => for_each_node(&target.resolve()?, |node| {
            let CouncilResponse::Status(status) = call(node, &CouncilRequest::GetStatus)? else {
                bail!("unexpected response to GetStatus");
            };
            println!(
                "{node}: network_id 0x{}, epoch {} (next delivery: {})",
                hex::encode(status.network_id),
                status.epoch,
                status.epoch + 1
            );
            Ok(())
        }),
        Command::TypedData { delivery } => {
            println!("{}", typed_data_json(&delivery.payload()?));
            Ok(())
        }
        Command::Deliver {
            target,
            delivery,
            council_key,
            signature,
            save_dir,
        } => {
            let nodes = target.resolve()?;
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
            if let Some(dir) = &save_dir {
                let path = save_envelope(dir, &envelope)?;
                println!("saved: {}", path.display());
            }
            for_each_node(&nodes, |node| {
                match call(node, &CouncilRequest::DeliverEpochKey(envelope.clone()))? {
                    CouncilResponse::Delivered { epoch } => {
                        println!("{node}: delivered root key for epoch {epoch}");
                        Ok(())
                    }
                    CouncilResponse::AlreadyDelivered { epoch } => {
                        println!("{node}: already delivered epoch {epoch} (idempotent retry)");
                        Ok(())
                    }
                    CouncilResponse::Rejected { code, message } => {
                        bail!("rejected ({code:?}): {message}")
                    }
                    other => bail!("unexpected response: {other:?}"),
                }
            })
        }
        Command::DeliverBatch {
            target,
            envelope_dir,
        } => {
            let nodes = target.resolve()?;
            let envelopes = load_envelope_dir(&envelope_dir)?;
            if envelopes.is_empty() {
                bail!("no envelopes in {}", envelope_dir.display());
            }
            for_each_node(&nodes, |node| batch_to(node, &envelopes, &envelope_dir))
        }
    }
}

/// Bring one node from its current epoch to the latest saved envelope, over
/// a single connection (the port serves many requests per connection).
fn batch_to(node: &str, envelopes: &[SignedDeliveryEnvelope], dir: &Path) -> Result<()> {
    let latest = envelopes.last().expect("checked non-empty").payload.epoch;
    let mut stream = NodeSpec::parse(node)?.connect()?;
    let CouncilResponse::Status(status) = exchange(&mut stream, &CouncilRequest::GetStatus)? else {
        bail!("unexpected response to GetStatus");
    };
    if status.epoch >= latest {
        println!(
            "{node}: already at epoch {} (latest saved envelope: {latest})",
            status.epoch
        );
        return Ok(());
    }

    for epoch in (status.epoch + 1)..=latest {
        let envelope = envelopes
            .iter()
            .find(|e| e.payload.epoch == epoch)
            .ok_or_else(|| {
                anyhow!(
                    "the node needs epoch {epoch} but {} has no {epoch}.cbor \
                     (epochs are sequential; nothing past the gap can install)",
                    dir.display()
                )
            })?;
        match exchange(
            &mut stream,
            &CouncilRequest::DeliverEpochKey(envelope.clone()),
        )? {
            CouncilResponse::Delivered { epoch } => {
                println!("{node}: delivered root key for epoch {epoch}");
            }
            CouncilResponse::AlreadyDelivered { epoch } => {
                println!("{node}: already delivered epoch {epoch}");
            }
            CouncilResponse::Rejected { code, message } => {
                bail!("epoch {epoch} rejected ({code:?}): {message}")
            }
            other => bail!("unexpected response: {other:?}"),
        }
    }
    println!("{node}: now at epoch {latest}");
    Ok(())
}

/// Write one envelope as `<epoch>.cbor` (dir 0700, file 0600 — the bytes
/// contain the plaintext root key). Idempotent for the identical envelope; a
/// DIFFERENT envelope already saved for the epoch is an error, mirroring the
/// custodian's EpochConflict.
fn save_envelope(dir: &Path, envelope: &SignedDeliveryEnvelope) -> Result<PathBuf> {
    let bytes = canonical_envelope_bytes(envelope)?;
    create_private_dir(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{}.cbor", envelope.payload.epoch));
    match std::fs::read(&path) {
        Ok(existing) if existing == *bytes => return Ok(path), // idempotent re-run
        Ok(_) => bail!(
            "{} already holds a DIFFERENT envelope for epoch {}; refusing to overwrite",
            path.display(),
            envelope.payload.epoch
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    write_private_file(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Load every `<epoch>.cbor` in `dir`, sorted ascending by epoch. Each
/// file's payload epoch must match its name; anything else in the directory
/// is an error (this folder should hold envelopes and nothing else).
fn load_envelope_dir(dir: &Path) -> Result<Vec<SignedDeliveryEnvelope>> {
    let mut envelopes: Vec<SignedDeliveryEnvelope> = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry.context("reading directory entry")?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let epoch: u64 = name
            .strip_suffix(".cbor")
            .and_then(|stem| stem.parse().ok())
            .ok_or_else(|| {
                anyhow!(
                    "unexpected file {} (expecting <epoch>.cbor only)",
                    path.display()
                )
            })?;
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let envelope =
            envelope_from_bytes(&bytes).with_context(|| format!("decoding {}", path.display()))?;
        if envelope.payload.epoch != epoch {
            bail!(
                "{} holds an envelope for epoch {}, not {epoch}",
                path.display(),
                envelope.payload.epoch
            );
        }
        envelopes.push(envelope);
    }
    envelopes.sort_by_key(|e| e.payload.epoch);
    Ok(envelopes)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// One request/response exchange on an already-open connection.
fn exchange(stream: &mut Box<dyn ReadWrite>, request: &CouncilRequest) -> Result<CouncilResponse> {
    write_frame_blocking(stream, request).context("sending request")?;
    read_frame_blocking(stream)
        .context("reading response")?
        .ok_or_else(|| anyhow!("node closed the connection without a response"))
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

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "council-signer-test-{tag}-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sealed(epoch: u64, root: [u8; 32]) -> SignedDeliveryEnvelope {
        let sk = secp256k1::SecretKey::from_byte_array(&[0x77; 32]).unwrap();
        seal_delivery(&sk, &network_id_from_chain_id(5124), epoch, &root)
    }

    #[test]
    fn save_is_idempotent_and_refuses_conflicting_overwrites() {
        let dir = temp_dir("save");
        let envelope = sealed(1, [1; 32]);
        let path = save_envelope(&dir, &envelope).unwrap();
        assert_eq!(path, dir.join("1.cbor"));
        // Re-saving the identical envelope is fine (re-run of the ceremony).
        save_envelope(&dir, &envelope).unwrap();
        // A different envelope for the same epoch is refused.
        let error = save_envelope(&dir, &sealed(1, [2; 32])).unwrap_err();
        assert!(error.to_string().contains("DIFFERENT"), "{error}");
        // The original file is untouched.
        assert_eq!(
            envelope_from_bytes(&std::fs::read(&path).unwrap()).unwrap(),
            envelope
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_envelope_dir_sorts_and_validates() {
        let dir = temp_dir("load");
        // Save out of order; loading returns ascending epochs.
        for epoch in [3u64, 1, 2] {
            save_envelope(&dir, &sealed(epoch, [epoch as u8; 32])).unwrap();
        }
        let envelopes = load_envelope_dir(&dir).unwrap();
        assert_eq!(
            envelopes
                .iter()
                .map(|e| e.payload.epoch)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        // A stray file is an error: this folder holds envelopes only.
        std::fs::write(dir.join("notes.txt"), b"hello").unwrap();
        assert!(load_envelope_dir(&dir).is_err());
        std::fs::remove_file(dir.join("notes.txt")).unwrap();

        // A misnamed envelope (name/payload epoch mismatch) is an error.
        let bytes = canonical_envelope_bytes(&sealed(9, [9; 32])).unwrap();
        std::fs::write(dir.join("4.cbor"), &*bytes).unwrap();
        let error = load_envelope_dir(&dir).unwrap_err();
        assert!(error.to_string().contains("epoch 9, not 4"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn target(node: Option<&str>, nodes_file: Option<PathBuf>) -> Target {
        Target {
            node: node.map(str::to_string),
            nodes_file,
        }
    }

    #[test]
    fn target_resolves_single_node_and_nodes_file() {
        assert_eq!(
            target(Some("10.0.0.1:7876"), None).resolve().unwrap(),
            vec!["10.0.0.1:7876".to_string()]
        );

        let dir = temp_dir("nodes");
        let path = dir.join("nodes.toml");
        std::fs::write(
            &path,
            r#"
# fleet
nodes = [
    "10.0.0.1:7876",
    "tls://node-1.example.com:7443",
]
"#,
        )
        .unwrap();
        assert_eq!(
            target(None, Some(path.clone())).resolve().unwrap(),
            vec![
                "10.0.0.1:7876".to_string(),
                "tls://node-1.example.com:7443".to_string()
            ]
        );

        // An invalid node spec anywhere in the file fails upfront, before
        // anything would be sent.
        std::fs::write(&path, r#"nodes = ["https://x.example.com/custodian"]"#).unwrap();
        let error = target(None, Some(path.clone())).resolve().unwrap_err();
        assert!(
            format!("{error:#}").contains("raw TCP, not HTTP"),
            "{error:#}"
        );

        // An empty list is an error, as is a malformed file.
        std::fs::write(&path, "nodes = []").unwrap();
        assert!(target(None, Some(path.clone())).resolve().is_err());
        std::fs::write(&path, "not toml at all [").unwrap();
        assert!(target(None, Some(path)).resolve().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cli_requires_exactly_one_target() {
        // --node and --nodes-file conflict.
        assert!(
            Cli::try_parse_from([
                "council-signer",
                "status",
                "--node",
                "a:1",
                "--nodes-file",
                "/tmp/nodes.toml"
            ])
            .is_err()
        );
        // Neither is a parse error.
        assert!(Cli::try_parse_from(["council-signer", "status"]).is_err());
        // Each alone parses.
        assert!(Cli::try_parse_from(["council-signer", "status", "--node", "a:1"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "council-signer",
                "status",
                "--nodes-file",
                "/tmp/nodes.toml"
            ])
            .is_ok()
        );
    }

    #[test]
    fn saved_files_are_private_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = temp_dir("perm");
            let store = dir.join("envelopes");
            let path = save_envelope(&store, &sealed(1, [1; 32])).unwrap();
            let dir_mode = std::fs::metadata(&store).unwrap().permissions().mode();
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700);
            assert_eq!(file_mode & 0o777, 0o600);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}
