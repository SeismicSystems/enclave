#[cfg(not(feature = "supervisorctl"))]
pub mod service;
#[cfg(feature = "supervisorctl")]
pub mod supervisorctl;

pub mod test_utils;

/// tdx_evidence_helpers contains helpers for dealing with Vec<u8> evidence
/// and converting it to a human readable format. It is mainly used for debugging
/// the logic is mostly copied and pasted from https://github.com/confidential-containers/trustee/tree/main/deps/verifier/src/tdx
#[allow(dead_code)]
pub mod tdx_evidence_helpers;

/// runners has cargo tests so I can
/// one click run them and see the output
/// They are for dev convenience only
/// test runners are for dev convenience only
#[allow(unused_imports)]
pub mod runners;
