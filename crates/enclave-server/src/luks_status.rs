//! Reader for the first-boot LUKS-wipe progress that the `setup-persistent-luks`
//! script publishes. See
//! <https://github.com/SeismicSystems/seismic-images/blob/seismic/modules/seismic/mkosi.extra/usr/bin/setup-persistent-luks>
//!
//! First boot wipes the whole persistent disk to seed dm-integrity tags — an
//! hour-plus, otherwise-silent operation. The script writes progress to a
//! tmpfs file (atomically) and removes it when done; enclave-server is the
//! only node service alive for the entire wipe, so it serves the latest
//! snapshot via the `getLuksProvisioningStatus` RPC for the operator's CLI
//! progress bar.
//!
//! Strictly read-only and decoupled: we read the file on demand and never
//! write it, so a status read can never affect the wipe (and vice versa).

use seismic_enclave::LuksProvisioningStatus;

/// tmpfs file the wipe producer writes (and removes on completion). Absent
/// whenever no first-boot provisioning is in flight.
const LUKS_STATUS_FILE: &str = "/run/seismic/status/luks.json";

/// Current wipe status. Returns [`LuksProvisioningStatus::Idle`] when the file
/// is absent (no wipe in flight — done or never started), and
/// [`LuksProvisioningStatus::Unknown`] when it exists but can't be read or
/// parsed (a broken status pipeline, which is distinct from "done"). Best-effort
/// telemetry: a polling CLI must never get a hard error, so this is infallible.
pub fn read() -> LuksProvisioningStatus {
    read_from(LUKS_STATUS_FILE)
}

fn read_from(path: &str) -> LuksProvisioningStatus {
    // A tiny tmpfs read; synchronous is fine inside the async RPC handler.
    match std::fs::read(path) {
        // Present but unparseable → the pipeline is broken, not "done".
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(LuksProvisioningStatus::Unknown),
        // Absent is the normal "no wipe in flight" case (done or never started).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LuksProvisioningStatus::Idle,
        // Exists but unreadable (perms/IO): surface as Unknown, never as Idle.
        Err(_) => LuksProvisioningStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn absent_file_is_idle() {
        assert_eq!(
            read_from("/no/such/path/luks.json"),
            LuksProvisioningStatus::Idle
        );
    }

    #[test]
    fn absent_is_idle_but_garbage_is_unknown() {
        // A present-but-unparseable file must NOT look like "done" (Idle);
        // it signals a broken status pipeline.
        let f = write_temp("not json{");
        assert_eq!(
            read_from(f.path().to_str().unwrap()),
            LuksProvisioningStatus::Unknown
        );
    }

    /// Pins the wire contract the bash producer hand-writes. If this changes,
    /// `setup-persistent-luks`'s `write_progress_status` must change too.
    #[test]
    fn parses_provisioning_with_eta() {
        let f = write_temp(
            r#"{"state":"provisioning","bytes_done":104857600,"bytes_total":1099511627776,"eta_seconds":5400}"#,
        );
        assert_eq!(
            read_from(f.path().to_str().unwrap()),
            LuksProvisioningStatus::Provisioning {
                bytes_done: 104857600,
                bytes_total: 1099511627776,
                eta_seconds: Some(5400),
            }
        );
    }

    #[test]
    fn parses_provisioning_without_eta() {
        let f = write_temp(r#"{"state":"provisioning","bytes_done":0,"bytes_total":0}"#);
        assert_eq!(
            read_from(f.path().to_str().unwrap()),
            LuksProvisioningStatus::Provisioning {
                bytes_done: 0,
                bytes_total: 0,
                eta_seconds: None,
            }
        );
    }

    #[test]
    fn parses_idle_and_error() {
        let idle = write_temp(r#"{"state":"idle"}"#);
        assert_eq!(
            read_from(idle.path().to_str().unwrap()),
            LuksProvisioningStatus::Idle
        );
        let err = write_temp(r#"{"state":"error","error":"boom"}"#);
        assert_eq!(
            read_from(err.path().to_str().unwrap()),
            LuksProvisioningStatus::Error {
                error: "boom".to_string()
            }
        );
    }
}
