# seismic-measurement-registry-client

The enclave's read-only Alloy interface to the canonical
[`MeasurementRegistry`](https://github.com/SeismicSystems/seismic/blob/main/contracts/src/enclave/MeasurementRegistry.sol).

Runtime code needs only:

- the registry genesis-predeploy address; and
- `eth_call` access to `isAccepted(bytes32 admissionId)`.

Admission-ID derivation and registry genesis-storage derivation live in
`seismic-measurement-admission`. Solidity sources, contract artifacts, policy
mutation, transaction signing, and authority administration live in the
`SeismicSystems/seismic` contract and deployment tooling.

The `abi_parity` test pins the generated Rust selector locally. CI also checks
the binding against the canonical
`seismic/contracts/artifacts/MeasurementRegistry.json` so an upstream ABI
change cannot silently drift from the runtime interface.
