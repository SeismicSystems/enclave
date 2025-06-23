#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use time as _; // see Cargo.toml for explanation
use clap as _; // used in main.rs

pub mod attestation;
pub mod key_manager;
pub mod server;
pub mod utils;
