// // Prepares an encrypted snapshot of the reth database
// // the snapshot is compressed and encrypted with the snapshot key
// pub async fn prepare_encrypted_snapshot(request: SnapSyncRequest) -> RpcResult<SnapSyncResponse> {
// }

// // Gives the client the encrypted snapshot
// // Assumes the snapshot is already created
// pub async fn download_encrypted_snapshot(request: SnapSyncRequest) -> RpcResult<SnapSyncResponse> {
// }

// // Uploads the encrypted snapshot to the enclave server
// // File gets put the in the correct spot
// pub async fn upload_encrypted_snapshot(request: SnapSyncRequest) -> RpcResult<SnapSyncResponse> {
// }

// // Restores the reth database from the encrypted snapshot
// // stops reth, decryptes and decompresses the snapshot, restarts reth with snapshot data active
// pub async fn restore_from_encrypted_snapshot(request: SnapSyncRequest) -> RpcResult<SnapSyncResponse> {
// }
