# seismic-measurement-registry-client

The enclave's read-only Alloy interface to the canonical
[`MeasurementRegistry`](https://github.com/SeismicSystems/seismic/blob/main/contracts/src/predeploys/MeasurementRegistry.sol).

Runtime code needs only:

- the registry genesis-predeploy address; and
- `eth_call` access to `isAccepted(bytes32 admissionId)`.

Admission-ID derivation and registry genesis-storage derivation live in
`seismic-measurement-admission`. Solidity sources, contract artifacts, policy
mutation, transaction signing, and admin-role administration live in the
`SeismicSystems/seismic` contract and deployment tooling.

A unit test pins the generated Rust selector locally. The seismic repo, which
pins this crate, checks the binding against its canonical
[`contracts/artifacts/MeasurementRegistry.json`](https://github.com/SeismicSystems/seismic/blob/main/contracts/artifacts/MeasurementRegistry.json)
at that pin, so an ABI change cannot ship past the pin bump that adopts it.
