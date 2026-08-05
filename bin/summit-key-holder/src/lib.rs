//! Pre-manifest holder of a node's summit consensus keys.
//!
//! The network manifest pins every founding validator's pubkeys, so the
//! keys must exist *before* the manifest does — before the config POST,
//! before admission, before LUKS. This service is
//! where they live in that window: it generates the summit keypairs
//! (ed25519 node identity + BLS12-381 MinPk consensus) in RAM at boot,
//! serves `{pubkeys, quote}` over plain HTTP for deploy's founding harvest,
//! and persists them into summit's keystore once LUKS has opened
//! `/persistent`. See
//! <https://github.com/SeismicSystems/seismic/blob/main/docs/tee/network-founding.md>.
//!
//! Boundary rules:
//!
//! - **Never the custodian.** These are per-VM identity keys, not
//!   `root_key`-shared secrets, and the custodian's design is *no network
//!   listener, ever* — while this service must serve HTTP to the outside
//!   pre-manifest, the most exposed moment in the node's life. Hosting the
//!   keys there would undo the custodian split.
//! - **Same user as summit.** The keystore is written as the `summit` user
//!   into summit's own key directory: summit's keys live under summit's own
//!   user/ownership even though keygen happens in this binary, and serving
//!   pubkeys never grants another user read access to key material.
//! - **Keygen/persist vs serve are separable modules** ([`keys`] and
//!   [`state`] vs [`http`]), and the persist trigger is a Unix control
//!   socket ([`control`]) rather than the network listener. The socket is
//!   the future custody-split boundary: if the single-process holder is
//!   ever split (privates in a socket-only process, a secret-free HTTP
//!   front), the client side of that socket does not change.
//!
//! Lifecycle per boot: generate RAM keys → serve `{pubkeys, quote}` until
//! `/run/seismic/conf/network-manifest.json` appears (the quote window;
//! reopens every boot since the conf dir is tmpfs) → `persist` over the
//! control socket writes the keystore on first boot or confirms it on
//! reboot, discarding the RAM keys either way → pubkey serving continues
//! for life from the keystore, feeding the launch-time continuity
//! assertion. RAM keys that never persist die with the process (dropping a
//! commonware private key zeroizes it); a reboot in the founding window
//! therefore burns the harvested key, which the launch assertion is
//! designed to catch.

pub mod control;
pub mod error;
pub mod http;
pub mod keys;
pub mod state;
