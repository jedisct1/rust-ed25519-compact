use core::ops::{Deref, DerefMut};

use super::error::Error;

/// A seed, which a key pair can be derived from.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Seed([u8; Seed::BYTES]);

impl From<[u8; 32]> for Seed {
    fn from(seed: [u8; 32]) -> Self {
        Seed(seed)
    }
}

impl Seed {
    /// Number of raw bytes in a seed.
    pub const BYTES: usize = 32;

    /// Creates a seed from raw bytes.
    pub fn new(seed: [u8; Seed::BYTES]) -> Self {
        Seed(seed)
    }

    /// Creates a seed from a slice.
    pub fn from_slice(seed: &[u8]) -> Result<Self, Error> {
        let mut seed_ = [0u8; Seed::BYTES];
        if seed.len() != seed_.len() {
            return Err(Error::InvalidSeed);
        }
        seed_.copy_from_slice(seed);
        Ok(Seed::new(seed_))
    }
}

#[cfg(feature = "random")]
impl Default for Seed {
    /// Generates a random seed.
    fn default() -> Self {
        let mut seed = [0u8; Seed::BYTES];
        getrandom::getrandom(&mut seed).expect("RNG failure");
        Seed(seed)
    }
}

#[cfg(feature = "random")]
impl Seed {
    /// Generates a random seed.
    pub fn generate() -> Self {
        Seed::default()
    }
}

impl Deref for Seed {
    type Target = [u8; Seed::BYTES];

    /// Returns a seed as raw bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Seed {
    /// Returns a seed as mutable raw bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "zeroizing")]
impl zeroize::Zeroize for Seed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
