use crate::key_manager::key_manager::KeyManager;

use anyhow::Result;
use rand::rngs::OsRng;
use rand::TryRngCore;

/// A builder for creating instances of [`KeyManager`].
///
/// Provides methods to create either a secure, randomly initialized key manager
/// or a deterministic mock version for testing purposes.
pub struct KeyManagerBuilder {}

impl KeyManagerBuilder {
    /// Creates a new instance of the `KeyManagerBuilder`.
    pub fn new() -> Self {
        Self {}
    }

    /// Builds a [`KeyManager`] using cryptographically secure random bytes
    /// sourced from the operating system's RNG.
    ///
    /// # Errors
    ///
    /// Returns an error if the random number generator fails or if the
    /// `KeyManager` fails to initialize.
    pub fn build_from_os_rng() -> Result<KeyManager> {
        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        let km = KeyManager::new(rng_bytes)?;
        Ok(km)
    }

    /// Builds a mock [`KeyManager`] initialized with zeroed bytes.
    ///
    /// This method is intended for testing and non-production use.
    pub fn build_mock() -> Result<KeyManager> {
        let km = KeyManager::new([0u8; 32])?;
        Ok(km)
    }
}
