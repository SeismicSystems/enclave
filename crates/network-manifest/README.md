# seismic-network-manifest

Schema and identity derivation for `network-manifest.json`, the deploy-time
artifact that defines a Seismic network: [`NetworkManifestV1`] (strict,
deserialize-only parsing) and [`NetworkId`] (SHA-256 of the exact file bytes).

Deliberately dependency-light — serde + sha2, no attestation stack — so every
manifest consumer parses it with the same code:

- `seismic-attestation` re-exports these types for node-side callers
  (the attestation service, transcript bindings);
- `tdx-init` validates the manifest embed at boot-config POST time;
- `seismic-manifest` (`bin/seismic-manifest`) renders the manifest for deploy
  tooling — the only emitter, kept out of this crate so node builds stay
  parse-only — and its round-trip test holds `parse → render` to the exact
  bytes of `fixtures/network-manifest-v1.json`.
