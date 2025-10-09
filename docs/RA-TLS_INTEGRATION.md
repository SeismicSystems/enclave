# RA-TLS Integration Guide for Distributed Root Key Sharing

## Overview

This guide explains how to integrate RA-TLS (Remote Attestation with TLS) for secure root key sharing between enclave nodes in a distributed consensus network.

**Current State**: All nodes use hardcoded mock keys (`[0u8; 32]`) for testing.
**Goal**: Implement secure key distribution where:
1. Genesis node generates a unique root key
2. Joining nodes retrieve the key from the genesis node
3. RA-TLS ensures the genesis node is a genuine TEE before accepting its key

---

## Architecture Overview

### Key Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Genesis Node (TEE)                       │
│  1. Generates root key with OsRng                           │
│  2. Provides RA-TLS attestation proving it's in TEE         │
│  3. Encrypts root key for verified joining nodes            │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ RA-TLS Connection
                            │ + attestation verification
                            │
┌─────────────────────────────────────────────────────────────┐
│                   Joining Node (TEE)                        │
│  1. Connects to genesis node via RA-TLS                     │
│  2. Verifies genesis node's TEE attestation                 │
│  3. Receives encrypted root key                             │
│  4. Decrypts and uses shared root key                       │
└─────────────────────────────────────────────────────────────┘
```

### Current Flow (Without RA-TLS)

```rust
// In engine.rs:165-202
async fn boot_retrieve_root_key(&self, req: RetrieveRootKeyRequest)
    -> RpcResult<RetrieveRootKeyResponse>
{
    // 1. New node generates attestation with its public key
    let attestation_bytes = self.attestation_agent
        .get_evidence(&retriver_pk_bytes).await?;

    // 2. New node calls genesis node's boot_share_root_key
    let response = client.boot_share_root_key(ShareRootKeyRequest {
        retriever_pk,
        tee,
        evidence: attestation
    }).await?;

    // 3. Genesis node responds with encrypted root key
    // 4. New node decrypts and stores root key
}

// In engine.rs:207-243
async fn boot_share_root_key(&self, req: ShareRootKeyRequest)
    -> RpcResult<ShareRootKeyResponse>
{
    // 1. Verify the new node's attestation
    self.eval_attestation_evidence(req.into()).await?;

    // 2. Check TCB status against upgrade contract
    self.booter.check_upgrade_contract(&tcb_status).await?;

    // 3. Encrypt root key for new node
    let (nonce, ciphertext, pk) = self.booter
        .encrypt_root_key(&req.retriever_pk, &root_key)?;

    // 4. Return encrypted root key
    Ok(ShareRootKeyResponse { ciphertext, nonce, pk })
}
```

---

## Integration Points for RA-TLS

### 1. **Replace HTTP RPC with RA-TLS Connection**

**Location**: `crates/enclave/src/client/booter.rs` (when implementing boot_with_peer_discovery)

**Current**:
```rust
// Uses standard HTTP JSON-RPC
let client = EnclaveClient::builder()
    .ip(peer_addr.ip().to_string())
    .port(peer_addr.port())
    .build()?;

client.boot_retrieve_root_key(req).await?;
```

**With RA-TLS**:
```rust
// TODO: Replace with RA-TLS connection
let ratls_client = RatlsEnclaveClient::new(peer_addr)
    .with_attestation_verification(/* your RA-TLS verifier */)
    .connect().await?;

// Connection is now mutually attested via RA-TLS
ratls_client.boot_retrieve_root_key(req).await?;
```

**What to Hook In**:
- Your self-signed RA-TLS library that:
  - Establishes TLS connection
  - Exchanges TEE attestation quotes in TLS handshake
  - Verifies peer is running in genuine TEE
  - Provides verified RPC client

---

### 2. **Server-Side: Genesis Node RA-TLS Endpoint**

**Location**: `crates/enclave-server/src/server/server.rs:164-171`

**Current**:
```rust
impl<K> BuildableServer for EnclaveServer<K> {
    async fn start(self) -> Result<ServerHandle> {
        let addr = self.addr.clone();
        let handle = BuildableServer::start_rpc_server(self).await;
        info!(target: "rpc::enclave", "Server started at {}", addr);
        handle
    }
}
```

**With RA-TLS**:
```rust
impl<K> BuildableServer for EnclaveServer<K> {
    async fn start(self) -> Result<ServerHandle> {
        let addr = self.addr.clone();

        // TODO: Start RA-TLS server instead of plain HTTP
        let handle = if self.use_ratls {
            RatlsServer::new(addr)
                .with_attestation_generator(/* TEE quote generator */)
                .with_methods(self.methods())
                .start()
                .await?
        } else {
            // Fallback to plain HTTP for testing
            BuildableServer::start_rpc_server(self).await?
        };

        info!(target: "rpc::enclave", "Server started at {}", addr);
        handle
    }
}
```

**What to Hook In**:
- Your RA-TLS server library that:
  - Accepts TLS connections with embedded attestation
  - Provides its own TEE quote during handshake
  - Only allows connections from verified TEEs

---

### 3. **Attestation Verification in boot_share_root_key**

**Location**: `crates/enclave-server/src/server/engine.rs:212-227`

**Current**:
```rust
async fn boot_share_root_key(&self, req: ShareRootKeyRequest)
    -> RpcResult<ShareRootKeyResponse>
{
    // Verify new enclave's attestation
    let eval_response = self.eval_attestation_evidence(req.clone().into()).await?;

    // Check TCB status against upgrade contract
    let tcb_status = claims.tcb_status;
    let valid_upgrade = self.booter
        .check_upgrade_contract(&tcb_status).await?;

    if !valid_upgrade {
        return Err(rpc_bad_evidence_error(anyhow!(
            "Attestation TCB is not approved"
        )));
    }

    // ... encrypt and share key
}
```

**With RA-TLS**:
```rust
async fn boot_share_root_key(&self, req: ShareRootKeyRequest)
    -> RpcResult<ShareRootKeyResponse>
{
    // Option 1: Trust RA-TLS verification (connection already verified)
    // If you trust your RA-TLS layer, you may skip this step

    // Option 2: Double verification (defense in depth)
    // Still verify attestation even after RA-TLS handshake
    let eval_response = self.eval_attestation_evidence(req.clone().into()).await?;

    // TODO: Decide if upgrade contract check is still needed
    // RA-TLS may already enforce this in the handshake
    if self.config.verify_upgrade_contract {
        let tcb_status = claims.tcb_status;
        self.booter.check_upgrade_contract(&tcb_status).await?;
    }

    // ... encrypt and share key
}
```

**What to Hook In**:
- Decision: Do you trust RA-TLS alone, or want defense-in-depth?
- If defense-in-depth: Keep existing `eval_attestation_evidence` call
- If trusting RA-TLS: Can skip or simplify verification

---

### 4. **Upgrade Contract Integration**

**Location**: `crates/enclave-server/src/server/boot.rs:178-256`

The `check_upgrade_contract` function verifies TCB measurements against an on-chain smart contract.

**Current Behavior**:
- Extracts `pcr04`, `mr_td`, `mr_seam` from attestation
- Queries smart contract to check if these measurements are approved
- Only allows key sharing if approved

**With RA-TLS Options**:

**Option A**: Enforce in RA-TLS handshake (recommended)
```rust
// In your RA-TLS library's verification callback
fn verify_peer_attestation(quote: &AttestationQuote) -> Result<(), TlsError> {
    // Extract measurements from quote
    let measurements = extract_tcb_measurements(quote)?;

    // Check against upgrade contract
    let approved = query_upgrade_contract(
        measurements.pcr04,
        measurements.mr_td,
        measurements.mr_seam
    ).await?;

    if !approved {
        return Err(TlsError::UnapprovedTcb);
    }

    Ok(())
}
```

**Option B**: Keep application-level check
- Leave existing `check_upgrade_contract` logic in `boot_share_root_key`
- RA-TLS just verifies quote signature, app verifies measurements

---

## Implementation Checklist

### Phase 1: Disable Mock Keys (When Ready)

- [ ] **File**: `crates/enclave-server/src/main.rs:37`
  ```rust
  // Change from:
  let key_manager = KeyManagerBuilder::build_mock().unwrap();

  // To:
  let key_manager = KeyManagerBuilder::build_from_os_rng().unwrap();
  ```

### Phase 2: Add RA-TLS Client

- [ ] **File**: `crates/enclave/src/client/ratls.rs` (new file)
  - [ ] Implement `RatlsEnclaveClient` wrapper
  - [ ] Integrate your RA-TLS library
  - [ ] Implement attestation verification callback
  - [ ] Map to existing `EnclaveApiClient` trait

### Phase 3: Add RA-TLS Server

- [ ] **File**: `crates/enclave-server/src/server/ratls_server.rs` (new file)
  - [ ] Implement RA-TLS server using your library
  - [ ] Generate attestation during TLS handshake
  - [ ] Expose existing RPC methods over RA-TLS

- [ ] **File**: `crates/enclave-server/src/main.rs`
  - [ ] Add CLI flag: `--use-ratls` (default: false for testing)
  - [ ] Start RA-TLS server instead of HTTP when enabled

### Phase 4: Implement Peer Discovery Boot Logic

- [ ] **File**: `crates/enclave/src/client/booter.rs`
  - [ ] Implement `boot_with_peer_discovery` function (see draft below)
  - [ ] Use RA-TLS client for peer connections
  - [ ] Fallback to genesis boot if no peers available

- [ ] **File**: `crates/seismic-reth/crates/node/core/src/args/enclave.rs`
  - [ ] Add `--enclave.boot-peers` CLI argument
  - [ ] Parse comma-separated list of peer addresses

- [ ] **File**: `seismic-reth/bin/seismic-reth/src/main.rs`
  - [ ] Replace `boot_genesis_streamlined_async` call
  - [ ] Call `boot_with_peer_discovery` with parsed peers

### Phase 5: Testing

- [ ] Test genesis boot (no peers)
- [ ] Test joining boot (with genesis peer)
- [ ] Verify all nodes derive same `tx_io` keys
- [ ] Test RA-TLS attestation rejection (invalid TEE)
- [ ] Test fallback to genesis if peers unreachable

---

## Code Snippets to Integrate

### Draft: boot_with_peer_discovery Function

**File**: `crates/enclave/src/client/booter.rs`

```rust
use crate::request_types::RetrieveRootKeyRequest;
use crate::rpc::EnclaveApiClient;
use std::net::SocketAddr;

/// Boots the enclave with peer discovery for distributed consensus
pub async fn boot_with_peer_discovery(
    known_peers: &[SocketAddr],
    attestation_policy_id: String,
    use_ratls: bool,
) -> Result<(), anyhow::Error> {
    // Try to retrieve root key from any existing peer
    for peer_addr in known_peers {
        tracing::info!("Attempting to retrieve root key from peer: {}", peer_addr);

        // TODO: Replace with your RA-TLS client
        let client = if use_ratls {
            // Your RA-TLS client here
            RatlsEnclaveClient::connect(*peer_addr).await?
        } else {
            // Fallback to plain HTTP for testing
            EnclaveClient::builder()
                .ip(peer_addr.ip().to_string())
                .port(peer_addr.port())
                .build()?
        };

        match client.boot_retrieve_root_key(RetrieveRootKeyRequest {
            addr: *peer_addr,
            attestation_policy_id: attestation_policy_id.clone(),
        }).await {
            Ok(_) => {
                tracing::info!("Successfully retrieved root key from peer: {}", peer_addr);
                client.complete_boot().await?;
                return Ok(());
            }
            Err(e) => {
                tracing::warn!("Failed to retrieve from peer {}: {}", peer_addr, e);
                continue;
            }
        }
    }

    // If no peers available or all failed, perform genesis boot
    tracing::info!("No peers available. Performing genesis boot");
    let client = EnclaveClient::default();
    client.boot_genesis().await?;
    client.complete_boot().await?;

    Ok(())
}
```

---

## RA-TLS Integration Touchpoints Summary

| Component | File | What to Replace | With What |
|-----------|------|-----------------|-----------|
| **Client Connection** | `crates/enclave/src/client/booter.rs` | `EnclaveClient::builder()` | `RatlsEnclaveClient::connect()` with attestation verification |
| **Server Startup** | `crates/enclave-server/src/server/server.rs:164` | `start_rpc_server()` | RA-TLS server with attestation generation |
| **Attestation Verification** | `crates/enclave-server/src/server/engine.rs:212` | Keep or simplify based on RA-TLS trust | Decision: trust RA-TLS or verify again |
| **Upgrade Contract** | `crates/enclave-server/src/server/boot.rs:178` | Keep in app or move to RA-TLS callback | Decision: where to enforce TCB approval |

---

## Testing Without RA-TLS

For development and testing before RA-TLS is ready:

1. **Keep mock keys enabled** (current state)
   - All nodes use `[0u8; 32]`
   - No attestation needed

2. **Test key retrieval flow with insecure HTTP**
   ```rust
   // In seismic-reth main.rs
   boot_with_peer_discovery(
       &known_peers,
       "share_root".to_string(),
       use_ratls: false  // Use plain HTTP for testing
   ).await?;
   ```

3. **Verify keys are identical**
   ```rust
   let keys = client.get_purpose_keys(GetPurposeKeysRequest { epoch: 0 }).await?;
   assert_eq!(keys.tx_io_pk, expected_pk_from_all_nodes);
   ```

---

## Security Notes

⚠️ **Current State (Mock Keys)**:
- Root key is hardcoded `[0u8; 32]`
- Anyone can derive the same keys
- Suitable only for testing

⚠️ **After Genesis Boot (No RA-TLS)**:
- Root key is randomly generated
- Keys transmitted over plain HTTP
- Man-in-the-middle attacks possible
- Suitable only for trusted networks

✅ **After RA-TLS Integration**:
- Root key randomly generated
- Keys transmitted over attested TLS
- Only genuine TEEs can join network
- Production-ready security

---

## Questions to Answer

1. **Which RA-TLS library are you using?**
   - Gramine RA-TLS?
   - Intel SGX SDK RA-TLS?
   - Custom implementation?

2. **Where do you want TCB enforcement?**
   - In RA-TLS handshake (recommended)
   - In application after connection
   - Both (defense in depth)

3. **Do you need upgrade contract integration?**
   - Yes: Keep existing `check_upgrade_contract` logic
   - No: Remove it and rely on RA-TLS policy

4. **Peer discovery mechanism?**
   - CLI arguments (simple)
   - Configuration file
   - Service discovery (e.g., Consul, etcd)
   - Blockchain-based peer list

---

## Contact & Support

If you have questions about integration points:
- Check existing attestation code in `crates/enclave-server/src/attestation/`
- Review test cases in `crates/enclave-server/tests/integration/booter.rs`
- See the boot flow diagram in this README

Good luck with the RA-TLS integration! 🔒
