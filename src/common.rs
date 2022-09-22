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

/// Noise, for non-deterministic signatures.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Noise([u8; Noise::BYTES]);

impl Noise {
    /// Number of raw bytes for a noise component.
    pub const BYTES: usize = 16;

    /// Creates a new noise component from raw bytes.
    pub fn new(noise: [u8; Noise::BYTES]) -> Self {
        Noise(noise)
    }

    /// Creates noise from a slice.
    pub fn from_slice(noise: &[u8]) -> Result<Self, Error> {
        let mut noise_ = [0u8; Noise::BYTES];
        if noise.len() != noise_.len() {
            return Err(Error::InvalidSeed);
        }
        noise_.copy_from_slice(noise);
        Ok(Noise::new(noise_))
    }
}

impl Deref for Noise {
    type Target = [u8; Noise::BYTES];

    /// Returns a noise as raw bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "random")]
impl Default for Noise {
    /// Generates random noise.
    fn default() -> Self {
        let mut noise = [0u8; Noise::BYTES];
        getrandom::getrandom(&mut noise).expect("RNG failure");
        Noise(noise)
    }
}

#[cfg(feature = "random")]
impl Noise {
    /// Generates random noise.
    pub fn generate() -> Self {
        Noise::default()
    }
}
