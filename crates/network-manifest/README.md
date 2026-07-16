# seismic-network-manifest

Schema and identity derivation for `network-manifest.json`, the deploy-time
artifact that defines a Seismic network: [`NetworkManifestV1`] (strict,
deserialize-only parsing) and [`NetworkId`] (SHA-256 of the exact file bytes).

Deliberately dependency-light — serde + sha2, no attestation stack — so every
manifest consumer parses it with the same code:

- `seismic-attestation` re-exports these types for node-side callers
  (the attestation service, transcript bindings);
- `tdx-init` validates the manifest embed at boot-config POST time;
- the deploy tool emits the manifest and pins the same golden vector as
  `fixtures/network-manifest-v1.json`.
