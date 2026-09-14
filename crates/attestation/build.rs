//! Record the `dcap-qvl` version this build links, for `TrustAnchors`.
//!
//! `dcap-qvl` compiles Intel's SGX Root CA in and keeps it in a private
//! module, so it is the one anchor a Seismic verdict rests on that cannot
//! be hashed from here. The crate version stands in for it: the root is
//! pinned by the crate, and the crate by its version. This whole script is
//! a stand-in too: upstreaming a one-line `pub use` of `TRUSTED_ROOT_CA_DER`
//! to `dcap-qvl` (and re-exporting it from the attested-tls fork) would let
//! `TrustAnchors` hash the root directly and delete this file.
//!
//! Cargo tells a build script nothing about its dependencies' versions, so
//! the version is read from the lockfile: the nearest `Cargo.lock` above this
//! crate's manifest. That is the enclave workspace's lock, both in a checkout
//! of this repo and in the git checkout a consumer such as the deploy CLI
//! builds this crate from. A consumer's own lockfile resolves the same
//! requirement the backend declares, so the two agree unless one has been
//! updated without the other; `cargo tree -i dcap-qvl` in the consumer is the
//! authority should they differ.

use std::{env, fs, path::PathBuf};

const CRATE: &str = "dcap-qvl";
const ENV: &str = "SEISMIC_DCAP_QVL_VERSION";

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let lock = manifest_dir
        .ancestors()
        .map(|dir| dir.join("Cargo.lock"))
        .find(|path| path.is_file())
        .unwrap_or_else(|| {
            panic!(
                "no Cargo.lock above {}: seismic-attestation records the {CRATE} version it \
                 links from the lockfile",
                manifest_dir.display()
            )
        });
    println!("cargo::rerun-if-changed={}", lock.display());

    let text = fs::read_to_string(&lock)
        .unwrap_or_else(|error| panic!("reading {}: {error}", lock.display()));
    let versions = locked_versions(&text, CRATE);
    let version = match versions.as_slice() {
        [version] => version,
        [] => panic!(
            "{} pins no {CRATE}; the attestation backend depends on it",
            lock.display()
        ),
        many => panic!(
            "{} pins {CRATE} at {} versions ({}); the trust-anchor record needs exactly one",
            lock.display(),
            many.len(),
            many.join(", ")
        ),
    };
    println!("cargo::rustc-env={ENV}={version}");
}

/// Every version `lock` (a `Cargo.lock`) resolves `name` to.
///
/// A lockfile is a sequence of `[[package]]` tables whose first two keys are
/// `name` and `version`, in that order; that is all this reads, so the
/// build needs no TOML parser.
fn locked_versions(lock: &str, name: &str) -> Vec<String> {
    let wanted = format!("name = \"{name}\"");
    let mut versions = Vec::new();
    let mut lines = lock.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if line != wanted {
            continue;
        }
        let version = lines
            .next()
            .and_then(|line| line.strip_prefix("version = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("Cargo.lock: `{wanted}` is not followed by its version"));
        versions.push(version.to_string());
    }
    versions
}
