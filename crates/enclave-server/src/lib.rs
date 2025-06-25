#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod attestation;
pub mod key_manager;
pub mod snapshot;
pub mod snapsync;
pub mod server;
pub mod utils;

use clap as _; // used by main.rs
