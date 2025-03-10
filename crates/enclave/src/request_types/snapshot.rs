use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrepareEncryptedSnapshotRequest {} // require auth token eventually

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrepareEncryptedSnapshotResponse {
    pub success: bool,
    // size
    // block number at snapshot point
    // block hash at snapshot point
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DownloadEncryptedSnapshotRequest {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DownloadEncryptedSnapshotResponse {
    pub encrypted_snapshot: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UploadEncryptedSnapshotRequest {
    pub encrypted_snapshot: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UploadEncryptedSnapshotResponse {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RestoreFromEncryptedSnapshotRequest {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RestoreFromEncryptedSnapshotResponse {
    pub success: bool,
}
