//! Example usage:
//!
//! ```rust
//! use ed25519_compact::*;
//!
//! // A message to sign and verify.
//! let message = b"test";
//!
//! // Generates a new key pair using a random seed.
//! // A given seed will always produce the same key pair.
//! let key_pair = KeyPair::from_seed(Seed::default());
//!
//! // Computes a signature for this message using the secret part of the key pair.
//! let signature = key_pair.sk.sign(message, Some(Noise::default()));
//!
//! // Verifies the signature using the public part of the key pair.
//! key_pair
//!     .pk
//!     .verify(message, &signature)
//!     .expect("Signature didn't verify");
//!
//! // Verification of a different message using the same signature and public key fails.
//! key_pair
//!     .pk
//!     .verify(b"A different message", &signature)
//!     .expect_err("Signature shouldn't verify");
//!
//! // All these structures can be viewed as raw bytes simply by dereferencing them:
//! let signature_as_bytes: &[u8] = signature.as_ref();
//! println!("Signature as bytes: {:?}", signature_as_bytes);
//! ```

#![no_std]
#![allow(
    clippy::needless_range_loop,
    clippy::many_single_char_names,
    clippy::unreadable_literal,
    clippy::let_and_return,
    clippy::needless_lifetimes,
    clippy::cast_lossless,
    clippy::suspicious_arithmetic_impl,
    clippy::identity_op
)]
mod curve25519;
mod ed25519;
mod error;
mod sha512;

pub use ed25519::*;
pub use error::*;
