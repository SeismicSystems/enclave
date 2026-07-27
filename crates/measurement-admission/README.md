# seismic-measurement-admission

The shared implementation of Seismic's measurement-admission predicate:

```text
verified guest measurements -> canonical admission ID -> accepted-ID set
```

One crate defines the versioned schema (`seismic.azure-tdx.pcr4-pcr9-pcr11.v1`),
the admission-ID derivation, the strict compiler from a measurement-policy
document to the set of IDs it admits, and the `MeasurementRegistry` genesis
storage that seeds them. Its consumers only differ in where the accepted set
comes from:

- **responder** (attestation service): derives the ID from verified evidence
  and asks `MeasurementRegistry.isAccepted(id)` on local reth;
- **joiner**: compiles the manifest-pinned bootstrap policy artifact and tests
  membership before it can read any chain state;
- **deploy tooling**: compiles the same artifact into registry genesis
  storage, via the CLI.

Policy documents are Flashbots-compatible record lists restricted to one
value per register: one record admits one guest identity and compiles to one
admission ID, so the reviewed document literally lists the accepted set.

The canonical Solidity contract and its artifact live in `seismic/contracts`;
the storage-slot formulas here are pinned by golden tests on both sides.
Parity tests hold the compiler's accepted semantics equal to attested-tls's
`check_measurement`.

## CLI

Built with the `cli` feature (`cargo build -p seismic-measurement-admission
--features cli`):

```console
$ seismic-measurement-admission compile measurement-policy.json
$ seismic-measurement-admission admission-id --pcr4 0x… --pcr9 0x… --pcr11 0x…
```

`compile` prints a JSON report: policy hash, admission IDs (total and
per-record), and the complete registry genesis storage map. The committed
fixture pair under `fixtures/` is the golden vector for the whole pipeline.
