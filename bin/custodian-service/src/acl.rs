//! `--allow <user>:<purpose>[,<purpose>...]` grants → [`MethodAcl`].
//!
//! Grants name users, never numeric UIDs: sysusers-allocated UIDs are not
//! stable across image builds, while usernames are pinned by the same image
//! that defines them — the systemd unit passing `--allow` lives next to the
//! user definitions in seismic-images, and both are part of the measured
//! image, so there is deliberately no runtime-mutation path. Names resolve
//! once at startup via `getpwnam_r`; an unresolvable name fails the boot so
//! a typo'd grant surfaces immediately instead of as a runtime deny.

use anyhow::{Context as _, Result, bail};
use seismic_custodian_ipc::server::MethodAcl;
use std::ffi::CString;

/// Valid purpose labels: kebab-case of the [`MethodAcl`] field each one
/// populates. `ping` is not grantable — it is open to anyone who can connect.
/// Single source for both the `--allow` help text and the grant-parse error,
/// so the two stay in lockstep.
pub const VALID_PURPOSES: &str = "tx-io, tx-io-public, rng, snapshot, \
     create-root-key-bootstrap-attempt, wrap-root-key, \
     install-root-key-from-verified-bootstrap-response";

/// Build the socket ACL from repeated `--allow` values. No specs yields the
/// default deny-all ACL.
pub fn method_acl_from_allow_specs(specs: &[String]) -> Result<MethodAcl> {
    build_acl(specs, resolve_uid)
}

/// Username→UID lookup: always [`resolve_uid`] in production (wired by
/// [`method_acl_from_allow_specs`]), but made generic for testing, so
/// the grant matrix and purpose validation are exercised against a fixed
/// user set instead of the host's user database.
type ResolveUid = fn(&str) -> Result<u32>;

/// Core of [`method_acl_from_allow_specs`], split out for the tests.
fn build_acl(specs: &[String], resolve: ResolveUid) -> Result<MethodAcl> {
    let mut acl = MethodAcl::default();
    for spec in specs {
        let Some((user, purposes)) = spec.split_once(':') else {
            bail!("--allow '{spec}': expected <user>:<purpose>[,<purpose>...]");
        };
        let uid = resolve(user).with_context(|| format!("--allow '{spec}'"))?;
        for purpose in purposes.split(',') {
            let grants = match purpose {
                "tx-io" => &mut acl.tx_io,
                "tx-io-public" => &mut acl.tx_io_public,
                "rng" => &mut acl.rng,
                "snapshot" => &mut acl.snapshot,
                "create-root-key-bootstrap-attempt" => &mut acl.create_root_key_bootstrap_attempt,
                "wrap-root-key" => &mut acl.wrap_root_key,
                "install-root-key-from-verified-bootstrap-response" => {
                    &mut acl.install_root_key_from_verified_bootstrap_response
                }
                other => {
                    bail!("--allow '{spec}': unknown purpose '{other}' (valid: {VALID_PURPOSES})")
                }
            };
            grants.insert(uid);
        }
    }
    Ok(acl)
}

/// Resolve a username to its UID via `getpwnam_r` (libc is already linked
/// for `SO_PEERCRED`; no extra dependency).
fn resolve_uid(user: &str) -> Result<u32> {
    let c_user = CString::new(user).context("username contains a NUL byte")?;

    // Start at the libc's suggested buffer size and grow on ERANGE; the cap
    // only bounds a pathological NSS backend.
    // SAFETY: sysconf takes an integer selector and touches no caller memory.
    let mut buf_len = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        len if len > 0 => len as usize,
        _ => 1024,
    };
    const MAX_BUF_LEN: usize = 1 << 20;

    loop {
        let mut buf = vec![0u8; buf_len];
        // SAFETY: a zeroed passwd is only read if `result` is non-null, in
        // which case getpwnam_r has fully initialized it.
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: all pointers are live locals; getpwnam_r writes at most
        // `buf.len()` bytes into `buf` and points `result` at `passwd` (or
        // null) before returning.
        let rc = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut passwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf_len < MAX_BUF_LEN {
            buf_len *= 2;
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc))
                .with_context(|| format!("resolving user '{user}'"));
        }
        if result.is_null() {
            bail!("user '{user}' does not exist on this system");
        }
        return Ok(passwd.pw_uid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seismic_custodian_ipc::Request;

    fn fake_resolve(user: &str) -> Result<u32> {
        match user {
            "reth" => Ok(1001),
            "enclave-attest" => Ok(1002),
            other => bail!("user '{other}' does not exist"),
        }
    }

    // The production grant matrix: reth gets exactly its two secret purposes,
    // the attestation service gets public tx-io data plus bootstrap authority.
    #[test]
    fn grants_map_to_method_acl_sets() {
        let acl = build_acl(
            &[
                "reth:tx-io,rng".to_string(),
                "enclave-attest:tx-io-public,create-root-key-bootstrap-attempt,\
                 wrap-root-key,install-root-key-from-verified-bootstrap-response"
                    .to_string(),
            ],
            fake_resolve,
        )
        .expect("valid specs");

        assert!(acl.allows(1001, &Request::GetTxIoKeypair { epoch: 0 }));
        assert!(acl.allows(1001, &Request::GetRngKeypair { epoch: 0 }));
        assert!(!acl.allows(1001, &Request::GetSnapshotKey { epoch: 0 }));
        assert!(!acl.allows(1001, &Request::CreateRootKeyBootstrapAttempt));

        assert!(acl.allows(1002, &Request::GetTxIoPublicKey { epoch: 0 }));
        assert!(acl.allows(1002, &Request::CreateRootKeyBootstrapAttempt));
        assert!(!acl.allows(1002, &Request::GetTxIoKeypair { epoch: 0 }));

        // Ping stays open even to ungranted UIDs.
        assert!(acl.allows(4242, &Request::Ping));
        assert!(!acl.allows(4242, &Request::GetTxIoKeypair { epoch: 0 }));
    }

    #[test]
    fn no_specs_is_deny_by_default() {
        let acl = build_acl(&[], fake_resolve).expect("empty specs");
        assert!(!acl.allows(1001, &Request::GetTxIoKeypair { epoch: 0 }));
        assert!(acl.allows(1001, &Request::Ping));
    }

    #[test]
    fn malformed_specs_fail_the_boot() {
        for spec in [
            "reth",           // no colon
            "reth:",          // empty purpose list
            "reth:tx-io,",    // trailing comma
            "reth:snapshots", // misspelled purpose
            "ghost:tx-io",    // unresolvable user
        ] {
            assert!(
                build_acl(&[spec.to_string()], fake_resolve).is_err(),
                "spec '{spec}' must be rejected"
            );
        }
    }

    #[test]
    fn resolve_uid_finds_root_and_rejects_unknown_users() {
        assert_eq!(resolve_uid("root").expect("root exists"), 0);
        assert!(resolve_uid("no-such-user-seismic-custodian-test").is_err());
    }
}
