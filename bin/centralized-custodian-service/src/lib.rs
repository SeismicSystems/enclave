//! Building blocks of the centralized custodian service: council-delivered
//! epoch keys over the base custodian's root-key lifecycle ([`state`]), the
//! epoch-aware socket dispatch ([`dispatch`]), and the council TCP port
//! ([`council`]). The shipped binary (`main.rs`) is a thin CLI over these
//! modules; they are also linkable as a library so integration tests can
//! assemble the full topology — council port, unix socket, persistence —
//! in one process.

pub mod council;
pub mod dispatch;
pub mod state;
#[cfg(test)]
pub(crate) mod test_support;
