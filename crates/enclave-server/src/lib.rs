#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use clap as _;
use time as _; // see Cargo.toml for explanation // used in main.rs

pub mod attestation;
pub mod key_manager;
pub mod server;
pub mod utils;
