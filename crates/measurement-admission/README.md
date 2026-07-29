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
- **deploy tooling**: promotes raw image measurements into the policy
  artifact and compiles it into registry genesis storage, via the CLI.

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
$ seismic-measurement-admission promote measurements.json --measurement-id seismic_2026-06-11.abc123.vhd
$ seismic-measurement-admission compile measurement-policy.json
$ seismic-measurement-admission admission-id --pcr4 0x… --pcr9 0x… --pcr11 0x…
```

`promote` normalizes raw `make measure` output into a one-record policy
document binding exactly the schema registers (an already-promoted record
list passes through byte-verbatim), and compiles its own output before
returning. `compile` prints a JSON report: policy hash, admission IDs (total
and per-record), the canonical registry runtime-code hash, and the complete
registry genesis storage map. Both read stdin for `-`. The committed fixture
pairs under `fixtures/golden/` are the golden vectors for the whole pipeline;
the rest of `fixtures/` is test-harness input, not byte-pinned.

## Policy review and updates

Humans review the **policy document**, never the compiled report. The
document is the only human-authored format in the pipeline, and each record
reads as one image: its artifact name, attestation type, and the exact PCR
values it must show. No expansion step sits between the document and the
accepted set, so the reviewed document literally lists the accepted
identities. Approval is committed on-chain as the document's SHA-256
(`activePolicyHash`), pinning the exact bytes that were reviewed. The
compiled report is a deterministic machine artifact — regenerated on
demand, never shipped — used to seed and audit registry state, not to
review it.

`MeasurementRegistry.applyPolicyUpdate(accept, deprecate,
newActivePolicyHash)` takes a status delta plus the hash of the complete
new document. The compiler never emits deltas; authority tooling derives
them from two compile runs:

```text
old_ids = compile(previous-policy.json).admission_ids
new_ids = compile(new-policy.json).admission_ids

accept    = new_ids − old_ids
deprecate = old_ids − new_ids
newActivePolicyHash = compile(new-policy.json).policy_hash
```

`newActivePolicyHash` commits to the complete document rather than the
delta, so any revision's full policy is recoverable from one published
document without replaying prior updates. Reinstatement needs no special
casing (`accept` permits `Deprecated -> Accepted`), and the registry
rejects duplicate, contradictory, no-op, and invalid-transition batches
atomically, backstopping a mis-computed diff. Genesis is the degenerate
case: no previous document, so the complete compiled set is written
directly into registry storage as revision 1.
