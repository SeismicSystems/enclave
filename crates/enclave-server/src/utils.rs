use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use libc::uid_t;

pub fn get_current_uid() -> uid_t {
    unsafe { libc::getuid() }
}

pub fn anyhow_to_rpc_error(e: anyhow::Error) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), e.to_string(), None::<()>)
}
