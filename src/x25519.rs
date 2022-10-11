use core::ops::{Deref, DerefMut};

use super::common::*;
use super::error::Error;
use super::field25519::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey([u8; PublicKey::BYTES]);

impl PublicKey {
    /// Number of raw bytes in a public key.
    pub const BYTES: usize = 32;

    /// Creates a public key from raw bytes.
    pub fn new(pk: [u8; PublicKey::BYTES]) -> Self {
        PublicKey(pk)
    }

    /// Creates a public key from a slice.
    pub fn from_slice(pk: &[u8]) -> Result<Self, Error> {
        let mut pk_ = [0u8; PublicKey::BYTES];
        if pk.len() != pk_.len() {
            return Err(Error::InvalidPublicKey);
        }
        Fe::reject_noncanonical(pk)?;
        pk_.copy_from_slice(pk);
        Ok(PublicKey::new(pk_))
    }

    /// Multiply a point by the cofactor, returning an error if the element is
    /// in a small-order group.
    pub fn clear_cofactor(&self) -> Result<Self, Error> {
        let cofactor = [
            8u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        self.ladder(&cofactor, 4)
    }

    /// Multiply the point represented by the public key by the scalar after
    /// clamping it
    pub fn dh(&self, sk: &SecretKey) -> Result<Self, Error> {
        let sk = sk.clamped();
        self.ladder(&sk.0, 255)
    }

    /// Multiply the point represented by the public key by the scalar WITHOUT
    /// CLAMPING
    pub fn unclamped_mul(&self, sk: &SecretKey) -> Result<Self, Error> {
        self.clear_cofactor()?;
        self.ladder(&sk.0, 256)
    }

    pub(crate) fn ladder(&self, s: &[u8], bits: usize) -> Result<Self, Error> {
        let x1 = Fe::from_bytes(&self.0);
        let mut x2 = FE_ONE;
        let mut z2 = FE_ZERO;
        let mut x3 = x1;
        let mut z3 = FE_ONE;
        let mut swap: u8 = 0;
        let mut pos = bits - 1;
        loop {
            let bit = (s[pos >> 3] >> (pos & 7)) & 1;
            swap ^= bit;
            Fe::cswap2(&mut x2, &mut x3, &mut z2, &mut z3, swap);
            swap = bit;
            let a = x2 + z2;
            let b = x2 - z2;
            let aa = a.square();
            let bb = b.square();
            x2 = aa * bb;
            let e = aa - bb;
            let da = (x3 - z3) * a;
            let cb = (x3 + z3) * b;
            x3 = (da + cb).square();
            z3 = x1 * ((da - cb).square());
            z2 = e * (bb + (e.mul32(121666)));
            if pos == 0 {
                break;
            }
            pos -= 1;
        }
        Fe::cswap2(&mut x2, &mut x3, &mut z2, &mut z3, swap);
        z2 = z2.invert();
        x2 = x2 * z2;
        if !x2.is_nonzero() {
            return Err(Error::WeakPublicKey);
        }
        Ok(PublicKey(x2.to_bytes()))
    }

    /// The Curve25519 base point
    #[inline]
    pub fn base_point() -> PublicKey {
        PublicKey(FE_CURVE25519_BASEPOINT.to_bytes())
    }
}

impl Deref for PublicKey {
    type Target = [u8; PublicKey::BYTES];

    /// Returns a public key as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A secret key.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SecretKey([u8; SecretKey::BYTES]);

impl SecretKey {
    /// Number of bytes in a secret key.
    pub const BYTES: usize = 32;

    /// Creates a secret key from raw bytes.
    pub fn new(sk: [u8; SecretKey::BYTES]) -> Self {
        SecretKey(sk)
    }

    /// Creates a secret key from a slice.
    pub fn from_slice(sk: &[u8]) -> Result<Self, Error> {
        let mut sk_ = [0u8; SecretKey::BYTES];
        if sk.len() != sk_.len() {
            return Err(Error::InvalidSecretKey);
        }
        sk_.copy_from_slice(sk);
        Ok(SecretKey::new(sk_))
    }

    /// Perform the X25519 clamping magic
    pub fn clamped(&self) -> SecretKey {
        let mut clamped = *self;
        clamped[0] &= 248;
        clamped[31] &= 63;
        clamped[31] |= 64;
        clamped
    }

    /// Recover the public key
    pub fn recover_public_key(&self) -> Result<PublicKey, Error> {
        let sk = self.clamped();
        PublicKey::base_point().ladder(&sk.0, 255)
    }

    /// Tentatively overwrite the secret key with zeros.
    pub fn wipe(&mut self) {
        Mem::wipe(self.0)
    }
}

impl Deref for SecretKey {
    type Target = [u8; SecretKey::BYTES];

    /// Returns a secret key as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretKey {
    /// Returns a secret key as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A key pair.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct KeyPair {
    /// Public key part of the key pair.
    pub pk: PublicKey,
    /// Secret key part of the key pair.
    pub sk: SecretKey,
}

impl KeyPair {
    /// Number of bytes in a key pair.
    pub const BYTES: usize = SecretKey::BYTES;

    /// Generates a new key pair.
    #[cfg(feature = "random")]
    pub fn generate() -> KeyPair {
        let mut sk = [0u8; SecretKey::BYTES];
        getrandom::getrandom(&mut sk).expect("getrandom");
        if !Fe::from_bytes(&sk).is_nonzero() {
            panic!("All-zero secret key");
        }
        let sk = SecretKey(sk);
        let pk = sk
            .recover_public_key()
            .expect("generated public key is weak");
        KeyPair { pk, sk }
    }
}

impl Deref for KeyPair {
    type Target = [u8; KeyPair::BYTES];

    /// Returns a key pair as bytes.
    fn deref(&self) -> &Self::Target {
        &self.sk
    }
}

#[cfg(not(feature = "disable-signatures"))]
mod from_ed25519 {
    use super::super::{
        edwards25519, sha512, KeyPair as EdKeyPair, PublicKey as EdPublicKey,
        SecretKey as EdSecretKey,
    };
    use super::*;

    impl SecretKey {
        /// Convert an Ed25519 secret key to a X25519 secret key.
        pub fn from_ed25519(edsk: &EdSecretKey) -> Result<SecretKey, Error> {
            let seed = edsk.seed();
            let az: [u8; 64] = {
                let mut hash_output = sha512::Hash::hash(*seed);
                hash_output[0] &= 248;
                hash_output[31] &= 63;
                hash_output[31] |= 64;
                hash_output
            };
            SecretKey::from_slice(&az[..32])
        }
    }

    impl PublicKey {
        /// Convert an Ed25519 public key to a X25519 public key.
        pub fn from_ed25519(edpk: &EdPublicKey) -> Result<PublicKey, Error> {
            let pk = PublicKey::from_slice(
                &edwards25519::ge_to_x25519_vartime(edpk).ok_or(Error::InvalidPublicKey)?,
            )?;
            pk.clear_cofactor()?;
            Ok(pk)
        }
    }

    impl KeyPair {
        /// Convert an Ed25519 key pair to a X25519 key pair.
        pub fn from_ed25519(edkp: &EdKeyPair) -> Result<KeyPair, Error> {
            let pk = PublicKey::from_ed25519(&edkp.pk)?;
            let sk = SecretKey::from_ed25519(&edkp.sk)?;
            Ok(KeyPair { pk, sk })
        }
    }
}

#[cfg(not(feature = "disable-signatures"))]
pub use from_ed25519::*;

#[test]
fn test_x25519() {
    let sk_1 = SecretKey::from_slice(&[
        1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
    .unwrap();
    let pk_1 = PublicKey::base_point().unclamped_mul(&sk_1).unwrap();
    assert_eq!(pk_1, PublicKey::base_point());
    let kp_a = KeyPair::generate();
    let kp_b = KeyPair::generate();
    let secret_a = kp_b.pk.dh(&kp_a.sk).unwrap();
    let secret_b = kp_a.pk.dh(&kp_b.sk).unwrap();
    assert_eq!(secret_a, secret_b);
}

#[cfg(not(feature = "disable-signatures"))]
#[test]
fn test_x25519_map() {
    use super::KeyPair as EdKeyPair;
    let edkp_a = EdKeyPair::generate();
    let edkp_b = EdKeyPair::generate();
    let kp_a = KeyPair::from_ed25519(&edkp_a).unwrap();
    let kp_b = KeyPair::from_ed25519(&edkp_b).unwrap();
    let secret_a = kp_b.pk.dh(&kp_a.sk).unwrap();
    let secret_b = kp_a.pk.dh(&kp_b.sk).unwrap();
    assert_eq!(secret_a, secret_b);
}
