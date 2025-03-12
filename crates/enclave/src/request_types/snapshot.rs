use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrepareEncryptedSnapshotRequest {} // require auth token eventually

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrepareEncryptedSnapshotResponse {
    pub success: bool,
    pub error: String,
    // size
    // block number at snapshot point
    // block hash at snapshot point
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RestoreFromEncryptedSnapshotRequest {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RestoreFromEncryptedSnapshotResponse {
    pub success: bool,
    pub error: String,
}
