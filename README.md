# tdx-init

Rust rewrite of [flashbots/tdx-init](https://github.com/flashbots/tdx-init) — a utility for secure disk encryption and SSH configuration in Intel TDX VMs. Used by [seismic-images](https://github.com/SeismicSystems/seismic-images) to initialize Seismic validator nodes running in TEEs.

## Usage

```
tdx-init wait-for-key     # Wait for config via HTTP or extract from existing LUKS header
tdx-init set-passphrase   # Set up or mount an encrypted disk with passphrase
```

- `wait-for-key` runs during early boot, before persistent storage is mounted.
- `set-passphrase` runs after the node operator has provided credentials via an authenticated channel.

TODO: we should probably rename `wait-for-key` to `wait-for-config`, but that would need a coordinated update with seismic-images.

## What it does

1. **First boot**: Starts an HTTP server on port 8080, waits for a JSON config payload containing SSH keys, domain config, and service args. Once received, writes SSH keys to `authorized_keys`, persists config to `/etc/tdx-init/config.json`, then auto-initializes the disk with LUKS2 encryption (random passphrase).

2. **Subsequent boots**: Extracts the config from the LUKS2 header token and restores SSH keys and config files.

3. **Disk management** (`set-passphrase`): Formats new disks with LUKS2 or mounts existing ones. Stores SSH keys and config as LUKS token metadata. Creates and permissions standard directories under `/persistent/`.

## Changes from upstream

The upstream Go version accepts a single raw SSH key string. This Rust rewrite:

- Accepts a **JSON config payload** (`InitConfig`) instead of a raw key, carrying SSH keys, domain config (email, name), and per-service args (reth, summit, enclave)
- Supports **multiple SSH keys**
- **Auto-initializes** the disk with a random passphrase after receiving config (no manual searcher SSH step needed)
- **Persists full config** to `/persistent/conf/node.json` and embeds it in the LUKS header
- Includes **default args** for seismic-reth, summit, and enclave-server with flag validation
- Adds disk device **discovery with polling** and **disk resize** on LUKS unlock
- Backwards-compatible with the old single-key LUKS token format
