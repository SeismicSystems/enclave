//! The candidate tx_io_pk file: the public `tx_io_pk@0` of the candidate root
//! key the custodian minted at startup, as its 33 raw bytes (compressed SEC1).
//! The attestation service's founding harvest quotes it, and tdx-init compares
//! it with the manifest's pin at the config POST.
//!
//! A file rather than a socket method, so the candidate never appears in the
//! custodian's API: `GetTxIoPublicKey` only ever answers for a key the
//! manifest pins. The custodian writes the file once, at mint. It is valid
//! until the network manifest exists: after that the candidate may have been
//! discarded, and no reader looks at it. A restart re-mints and rewrites it.

use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// In the custodian's runtime directory, which the image creates
/// `2750 custodian:custodian-ipc`, so readers get the file through the
/// `custodian-ipc` group.
pub const CANDIDATE_TX_IO_PK_PATH: &str = "/run/seismic/custodian/candidate-tx-io-pk";

/// Owner read-write, group read: the key is public, but only the custodian
/// writes it.
const CANDIDATE_TX_IO_PK_FILE_MODE: u32 = 0o640;

/// Why a candidate tx_io_pk file that exists could not be read.
#[derive(Debug, thiserror::Error)]
pub enum CandidateTxIoPkFileError {
    #[error("reading {path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    #[error("{path}: expected 33 bytes, found {len}")]
    WrongLength { path: PathBuf, len: usize },
}

/// Delete a previous process's candidate tx_io_pk file. The runtime directory
/// outlives a service restart, so without this a failed [`write`] would leave
/// readers with a key no custodian holds.
pub fn remove_stale(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Write the candidate atomically: to a temporary file beside `path`, then
/// renamed over it, so a reader never sees a partial file.
pub fn write(path: &Path, tx_io_pk: &[u8; 33]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    // A tmp file left by a crashed write would fail `create_new`.
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(CANDIDATE_TX_IO_PK_FILE_MODE)
        .open(&tmp)?;
    file.write_all(tx_io_pk)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}

/// The candidate's `tx_io_pk@0`, or `None` while the custodian has not
/// written the file.
pub fn read(path: &Path) -> Result<Option<[u8; 33]>, CandidateTxIoPkFileError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CandidateTxIoPkFileError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let len = bytes.len();
    bytes
        .try_into()
        .map(Some)
        .map_err(|_| CandidateTxIoPkFileError::WrongLength {
            path: path.to_path_buf(),
            len,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn writes_raw_bytes_that_read_back_and_replace_a_previous_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("candidate-tx-io-pk");

        write(&path, &[0x02; 33]).expect("first write");
        write(&path, &[0x03; 33]).expect("a restart's re-mint");

        assert_eq!(fs::read(&path).expect("read back"), [0x03; 33]);
        assert_eq!(read(&path).expect("read"), Some([0x03; 33]));
        let mode = fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, CANDIDATE_TX_IO_PK_FILE_MODE);
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn remove_stale_deletes_a_previous_candidate_and_tolerates_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("candidate-tx-io-pk");

        remove_stale(&path).expect("no previous candidate");
        write(&path, &[0x02; 33]).expect("write");
        remove_stale(&path).expect("remove the previous candidate");
        assert_eq!(read(&path).expect("read"), None);
    }

    #[test]
    fn rejects_a_candidate_of_the_wrong_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("candidate-tx-io-pk");

        for body in [&[][..], &[0x02; 32], &[0x02; 34]] {
            fs::write(&path, body).expect("write");
            assert!(
                matches!(
                    read(&path),
                    Err(CandidateTxIoPkFileError::WrongLength { len, .. }) if len == body.len()
                ),
                "{} bytes",
                body.len()
            );
        }
    }
}
