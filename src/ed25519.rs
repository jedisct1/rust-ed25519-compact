use super::curve25519::{ge_scalarmult_base, is_identity, sc_muladd, sc_reduce, GeP2, GeP3};
use super::error::Error;
use super::sha512;
use core::fmt;
use core::ops::Deref;

/// A public key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
        pk_.copy_from_slice(pk);
        Ok(PublicKey::new(pk_))
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
#[derive(Copy, Clone)]
pub struct SecretKey([u8; SecretKey::BYTES]);

impl SecretKey {
    /// Number of bytes in a secret key.
    pub const BYTES: usize = 32 + PublicKey::BYTES;

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

    /// Returns the public counterpart of a secret key.
    pub fn public_key(&self) -> PublicKey {
        let mut pk = [0u8; PublicKey::BYTES];
        pk.copy_from_slice(&self[32..]);
        PublicKey(pk)
    }
}

impl Deref for SecretKey {
    type Target = [u8; SecretKey::BYTES];

    /// Returns a secret key as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A key pair.
#[derive(Copy, Clone)]
pub struct KeyPair {
    /// Public key part of the key pair.
    pub pk: PublicKey,
    /// Secret key part of the key pair.
    pub sk: SecretKey,
}

/// An Ed25519 signature.
#[derive(Copy, Clone)]
pub struct Signature([u8; Signature::BYTES]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:x?}", self))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Signature {
    /// Number of raw bytes in a signature.
    pub const BYTES: usize = 64;

    /// Creates a signature from raw bytes.
    pub fn new(bytes: [u8; Signature::BYTES]) -> Self {
        Signature(bytes)
    }

    /// Creates a signature key from a slice.
    pub fn from_slice(signature: &[u8]) -> Result<Self, Error> {
        let mut signature_ = [0u8; Signature::BYTES];
        if signature.len() != signature_.len() {
            return Err(Error::InvalidSignature);
        }
        signature_.copy_from_slice(signature);
        Ok(Signature::new(signature_))
    }
}

impl Deref for Signature {
    type Target = [u8; Signature::BYTES];

    /// Returns a signture as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A seed, which a key pair can be derived from.
pub struct Seed([u8; Seed::BYTES]);

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

/// Noise, for non-deterministic signatures.
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

impl PublicKey {
    /// Verifies that the signature `signature` is valid for the message `message`.
    pub fn verify(&self, message: impl AsRef<[u8]>, signature: &Signature) -> Result<(), Error> {
        let s = &signature[32..64];
        if check_lt_l(s) {
            return Err(Error::InvalidSignature);
        }
        if is_identity(self) || self.iter().fold(0, |acc, x| acc | x) == 0 {
            return Err(Error::WeakPublicKey);
        }
        let a = match GeP3::from_bytes_negate_vartime(self) {
            Some(g) => g,
            None => {
                return Err(Error::InvalidPublicKey);
            }
        };

        let mut hasher = sha512::Hash::new();
        hasher.update(&signature[0..32]);
        hasher.update(&self[..]);
        hasher.update(message);
        let mut hash = hasher.finalize();
        sc_reduce(&mut hash);

        let r = GeP2::double_scalarmult_vartime(hash.as_ref(), a, s);
        if r.to_bytes()
            .as_ref()
            .iter()
            .zip(signature.iter())
            .fold(0, |acc, (x, y)| acc | (x ^ y))
            != 0
        {
            Err(Error::SignatureMismatch)
        } else {
            Ok(())
        }
    }
}

impl SecretKey {
    /// Computes a signature for the message `message` using the secret key.
    /// The noise parameter is optional, but recommended in order to mitigate fault attacks.
    pub fn sign(&self, message: impl AsRef<[u8]>, noise: Option<Noise>) -> Signature {
        let seed = &self[0..32];
        let public_key = &self[32..64];
        let az: [u8; 64] = {
            let mut hash_output = sha512::Hash::hash(seed);
            hash_output[0] &= 248;
            hash_output[31] &= 63;
            hash_output[31] |= 64;
            hash_output
        };
        let nonce = {
            let mut hasher = sha512::Hash::new();
            if let Some(noise) = noise {
                hasher.update(&noise[..]);
                hasher.update(&az[..]);
            } else {
                hasher.update(&az[32..64]);
            }
            hasher.update(&message);
            let mut hash_output = hasher.finalize();
            sc_reduce(&mut hash_output[0..64]);
            hash_output
        };
        let mut signature: [u8; 64] = [0; 64];
        let r: GeP3 = ge_scalarmult_base(&nonce[0..32]);
        for (result_byte, source_byte) in
            (&mut signature[0..32]).iter_mut().zip(r.to_bytes().iter())
        {
            *result_byte = *source_byte;
        }
        for (result_byte, source_byte) in (&mut signature[32..64]).iter_mut().zip(public_key.iter())
        {
            *result_byte = *source_byte;
        }
        let mut hasher = sha512::Hash::new();
        hasher.update(signature.as_ref());
        hasher.update(&message);
        let mut hram = hasher.finalize();
        sc_reduce(&mut hram);
        sc_muladd(
            &mut signature[32..64],
            &hram[0..32],
            &az[0..32],
            &nonce[0..32],
        );
        let signature = Signature(signature);

        #[cfg(any(
            target_arch = "wasm32",
            target_arch = "wasm64",
            feature = "self-verify"
        ))]
        {
            PublicKey::from_slice(public_key)
                .expect("Key length changed")
                .verify(message, &signature)
                .expect("Newly created signature cannot be verified");
        }
        signature
    }
}

impl KeyPair {
    /// Number of bytes in a key pair.
    pub const BYTES: usize = SecretKey::BYTES;

    /// Generates a new key pair using a secret seed.
    pub fn from_seed(seed: Seed) -> KeyPair {
        if seed.iter().fold(0, |acc, x| acc | x) == 0 {
            panic!("All-zero seed");
        }
        let mut secret: [u8; 64] = {
            let mut hash_output = sha512::Hash::hash(&seed[..]);
            hash_output[0] &= 248;
            hash_output[31] &= 63;
            hash_output[31] |= 64;
            hash_output
        };
        let a = ge_scalarmult_base(&secret[0..32]);
        let public_key = a.to_bytes();
        for (dest, src) in (&mut secret[32..64]).iter_mut().zip(public_key.iter()) {
            *dest = *src;
        }
        for (dest, src) in (&mut secret[0..32]).iter_mut().zip(seed.iter()) {
            *dest = *src;
        }
        KeyPair {
            pk: PublicKey(public_key),
            sk: SecretKey(secret),
        }
    }

    /// Creates a key pair from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_slice(&bytes)?;
        let pk = sk.public_key();
        Ok(KeyPair { pk, sk })
    }
}

impl Deref for KeyPair {
    type Target = [u8; KeyPair::BYTES];

    /// Returns a key pair as bytes.
    fn deref(&self) -> &Self::Target {
        &self.sk
    }
}

static L: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

fn check_lt_l(s: &[u8]) -> bool {
    let mut c: u8 = 0;
    let mut n: u8 = 1;

    let mut i = 31;
    loop {
        c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
        n &= ((((s[i] ^ L[i]) as i32) - 1) >> 8) as u8;
        if i == 0 {
            break;
        } else {
            i -= 1;
        }
    }
    c == 0
}

#[cfg(feature = "traits")]
mod ed25519_trait {
    use super::{PublicKey, SecretKey, Signature};
    use ::ed25519::signature as ed25519_trait;

    impl ed25519_trait::Signature for Signature {
        fn from_bytes(bytes: &[u8]) -> Result<Self, ed25519_trait::Error> {
            let mut bytes_ = [0u8; Signature::BYTES];
            bytes_.copy_from_slice(bytes);
            Ok(Signature::new(bytes_))
        }
    }

    impl ed25519_trait::Signer<Signature> for SecretKey {
        fn try_sign(&self, message: &[u8]) -> Result<Signature, ed25519_trait::Error> {
            Ok(self.sign(message, None))
        }
    }

    impl ed25519_trait::Verifier<Signature> for PublicKey {
        fn verify(
            &self,
            message: &[u8],
            signature: &Signature,
        ) -> Result<(), ed25519_trait::Error> {
            self.verify(message, signature)
                .map_err(|e| ed25519_trait::Error::from_source(e))
        }
    }
}
