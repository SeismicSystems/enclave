//! Building blocks of the standalone centralized custodian service:
//! council-delivered epoch keys over a keyfile-persisted root key
//! ([`state`], [`root_key_file`]), the epoch-aware socket dispatch
//! ([`dispatch`]), the council TCP port ([`council`]), and the
//! observer-custodian sides of that port — parent verification
//! ([`observer_serving`]) and the fetching client ([`observer`]). The
//! shipped binary (`main.rs`) is a thin CLI over these modules; they are
//! also linkable as a library so integration tests can assemble the full
//! topology — council port, unix socket, persistence — in one process.

pub mod council;
pub mod dispatch;
pub mod observer;
pub mod observer_serving;
pub mod root_key_file;
pub mod state;
#[cfg(test)]
pub(crate) mod test_support;
