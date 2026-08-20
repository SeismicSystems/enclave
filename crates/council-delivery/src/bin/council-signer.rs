//! `council-signer` — the security council's key-delivery tool.
//!
//! Speaks the centralized custodian's council port (length-prefixed CBOR
//! over TCP) and performs the whole rotation ceremony: generate a key, check
//! a node's status, sign a delivery (with a locally held council key, or by
//! emitting EIP-712 typed data for an external wallet like `cast` or
//! MetaMask and attaching its signature), and deliver.
//!
//! Deliveries carry the purpose key in PLAINTEXT: only ever connect through
//! the deployment's TLS terminator or tunnel, never a bare untrusted wire.

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, DeliveryPayload, DeliveryPurpose, SignedDeliveryEnvelope,
    network_id_from_chain_id, seal_delivery, typed_data_json,
};
use seismic_custodian_ipc::{read_frame_blocking, write_frame_blocking};
use std::net::TcpStream;

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
    /// Generate a fresh 32-byte purpose key (a valid secp256k1 scalar, so it
    /// works for every purpose) and print it as 0x-hex.
    GenKey,
    /// Query a node's delivery status: network id and next expected epochs.
    Status {
        /// host:port of the node's council port (through its TLS/tunnel).
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
        /// host:port of the node's council port (through its TLS/tunnel).
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
    /// tx-io | rng-precompile | snapshot
    #[arg(long, value_parser = parse_purpose)]
    purpose: DeliveryPurpose,
    /// The epoch to install; must be exactly the node's current epoch + 1.
    #[arg(long)]
    epoch: u64,
    /// The 32-byte purpose key (0x + 64 hex). This is the secret being
    /// rotated in — prefer the env var over the flag to keep it out of
    /// shell history.
    #[arg(long, env = "COUNCIL_PURPOSE_KEY")]
    key: String,
}

impl DeliveryArgs {
    fn payload(&self) -> Result<DeliveryPayload> {
        Ok(DeliveryPayload {
            network_id: *network_id_from_chain_id(self.chain_id).as_bytes(),
            purpose: self.purpose,
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
            for (label, epoch) in [
                ("tx-io", status.tx_io_epoch),
                ("rng-precompile", status.rng_epoch),
                ("snapshot", status.snapshot_epoch),
            ] {
                println!("{label}: epoch {epoch} (next delivery: {})", epoch + 1);
            }
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
                        delivery.purpose,
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
                CouncilResponse::Delivered { purpose, epoch } => {
                    println!("delivered: {} epoch {epoch}", purpose.label());
                    Ok(())
                }
                CouncilResponse::AlreadyDelivered { purpose, epoch } => {
                    println!(
                        "already delivered: {} epoch {epoch} (idempotent retry)",
                        purpose.label()
                    );
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
    let mut stream = TcpStream::connect(node).with_context(|| format!("connecting to {node}"))?;
    write_frame_blocking(&mut stream, request).context("sending request")?;
    read_frame_blocking(&mut stream)
        .context("reading response")?
        .ok_or_else(|| anyhow!("node closed the connection without a response"))
}

fn parse_purpose(value: &str) -> Result<DeliveryPurpose> {
    DeliveryPurpose::ALL
        .into_iter()
        .find(|p| p.label() == value)
        .ok_or_else(|| {
            anyhow!("unknown purpose '{value}' (valid: tx-io, rng-precompile, snapshot)")
        })
}

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
    fn purpose_and_hex_parsers() {
        assert_eq!(parse_purpose("tx-io").unwrap(), DeliveryPurpose::TxIo);
        assert!(parse_purpose("storage").is_err());
        assert_eq!(
            parse_hex32(&format!("0x{}", hex::encode([7u8; 32]))).unwrap(),
            [7u8; 32]
        );
        assert!(parse_hex32("0x00").is_err());
        assert!(parse_hex65(&format!("0x{}", hex::encode([1u8; 65]))).is_ok());
    }
}
