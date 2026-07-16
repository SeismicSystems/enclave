//! Building blocks of the standalone key-custodian host: the root-key
//! lifecycle ([`state`]), the socket dispatch ([`dispatch`]), and the
//! `--allow` grant parsing ([`acl`]). The shipped binary (`main.rs`) is a
//! thin CLI over these modules; they are also linkable as a library so
//! workspace integration tests can assemble real custodian/attestation-service
//! topologies over real sockets in one process.

pub mod acl;
pub mod dispatch;
pub mod state;
