//! Byte parity between the golden measurement-policy fixture pair and its
//! committed copy in the seismic repo
//! (https://github.com/SeismicSystems/seismic/tree/main/contracts/test/fixtures).
//!
//! The golden pair stays owned by this crate — the policy compiler that
//! produces the compiled report lives here — while the seismic repo commits a
//! verbatim copy so its Solidity fixture tests run self-contained. A committed
//! copy can only agree with the pair it last saw, so CI checks out the seismic
//! copy and compares bytes: regenerating the golden pair fails here until the
//! seismic copy is updated in step, instead of drifting silently.

use std::{env, fs, path::PathBuf};

const SEISMIC_FIXTURES_ENV: &str = "SEISMIC_CONTRACTS_FIXTURES";

/// Basename and golden bytes of every fixture the seismic repo copies.
const COPIED_FIXTURES: [(&str, &[u8]); 2] = [
    (
        "measurement-policy-v1.json",
        include_bytes!("../fixtures/golden/measurement-policy-v1.json"),
    ),
    (
        "measurement-policy-v1.compiled.json",
        include_bytes!("../fixtures/golden/measurement-policy-v1.compiled.json"),
    ),
];

/// CI checks out `SeismicSystems/seismic` and points this test at its
/// committed `contracts/test/fixtures` directory. It is ignored in an
/// ordinary local run because the copy intentionally lives in the seismic
/// repo.
#[test]
#[ignore = "CI supplies the seismic/contracts fixture copies"]
fn seismic_fixture_copies_match_golden_pair() {
    let dir = PathBuf::from(env::var_os(SEISMIC_FIXTURES_ENV).unwrap_or_else(|| {
        panic!("{SEISMIC_FIXTURES_ENV} must point to seismic's contracts/test/fixtures")
    }));
    for (name, golden) in COPIED_FIXTURES {
        let path = dir.join(name);
        let copy = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read {}: {error}; seismic/contracts must commit a verbatim copy of \
                 fixtures/golden/{name}",
                path.display()
            )
        });
        assert!(
            copy == golden,
            "seismic's contracts/test/fixtures/{name} is not byte-identical to \
             fixtures/golden/{name}; copy the regenerated golden pair into the seismic repo"
        );
    }
}
