#[cfg(feature = "blind-keys")]
use super::curve25519::{ge_scalarmult, sc_invert, sc_mul};
use super::curve25519::{
    ge_scalarmult_base, is_identity, sc_muladd, sc_reduce, sc_reduce32, GeP2, GeP3,
};
use super::error::Error;
use super::sha512;
use core::fmt;
use core::ops::Deref;

/// A public key.
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
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
        pk.copy_from_slice(&self[Seed::BYTES..]);
        PublicKey(pk)
    }

    /// Returns the seed of a secret key.
    pub fn seed(&self) -> Seed {
        let mut seed = [0u8; Seed::BYTES];
        seed.copy_from_slice(&self[0..Seed::BYTES]);
        Seed(seed)
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct KeyPair {
    /// Public key part of the key pair.
    pub pk: PublicKey,
    /// Secret key part of the key pair.
    pub sk: SecretKey,
}

/// An Ed25519 signature.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct Signature([u8; Signature::BYTES]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:x?}", &self.0))
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
        let pk = &self[32..64];
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
        let r = ge_scalarmult_base(&nonce[0..32]);
        signature[0..32].copy_from_slice(&r.to_bytes()[..]);
        signature[32..64].copy_from_slice(pk);
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

        #[cfg(feature = "self-verify")]
        {
            PublicKey::from_slice(pk)
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

    /// Generates a new key pair.
    #[cfg(feature = "random")]
    pub fn generate() -> KeyPair {
        KeyPair::from_seed(Seed::default())
    }

    /// Generates a new key pair using a secret seed.
    pub fn from_seed(seed: Seed) -> KeyPair {
        if seed.iter().fold(0, |acc, x| acc | x) == 0 {
            panic!("All-zero seed");
        }
        let (scalar, _) = {
            let hash_output = sha512::Hash::hash(&seed[..]);
            KeyPair::split(&hash_output, false, true)
        };
        let pk = ge_scalarmult_base(&scalar).to_bytes();
        let mut sk = [0u8; 64];
        sk[0..32].copy_from_slice(&seed.0);
        sk[32..64].copy_from_slice(&pk);
        KeyPair {
            pk: PublicKey(pk),
            sk: SecretKey(sk),
        }
    }

    /// Creates a key pair from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_slice(bytes)?;
        let pk = sk.public_key();
        Ok(KeyPair { pk, sk })
    }

    pub fn clamp(scalar: &mut [u8]) {
        scalar[0] &= 248;
        scalar[31] &= 63;
        scalar[31] |= 64;
    }

    pub fn split(bytes: &[u8; 64], reduce: bool, clamp: bool) -> ([u8; 32], [u8; 32]) {
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&bytes[0..32]);
        if clamp {
            Self::clamp(&mut scalar);
        }
        if reduce {
            sc_reduce32(&mut scalar);
        }
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&bytes[32..64]);
        (scalar, prefix)
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
            #[cfg(feature = "std")]
            {
                self.verify(message, signature)
                    .map_err(|e| ed25519_trait::Error::from_source(e))
            }

            #[cfg(not(feature = "std"))]
            {
                self.verify(message, signature)
                    .map_err(|_| ed25519_trait::Error::new())
            }
        }
    }
}

#[test]
fn test_ed25519() {
    let kp = KeyPair::from_seed([42u8; 32].into());
    let message = b"Hello, World!";
    let signature = kp.sk.sign(message, None);
    assert!(kp.pk.verify(message, &signature).is_ok());
    assert!(kp.pk.verify(b"Hello, world!", &signature).is_err());
    assert_eq!(
        signature.as_ref(),
        [
            196, 182, 1, 15, 182, 182, 231, 166, 227, 62, 243, 85, 49, 174, 169, 9, 162, 196, 98,
            104, 30, 81, 22, 38, 184, 136, 253, 128, 10, 160, 128, 105, 127, 130, 138, 164, 57, 86,
            94, 160, 216, 85, 153, 139, 81, 100, 38, 124, 235, 210, 26, 95, 231, 90, 73, 206, 33,
            216, 171, 15, 188, 181, 136, 7,
        ]
    );
}

#[cfg(feature = "blind-keys")]
mod blind_keys {
    use super::*;

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub struct Blind([u8; Blind::BYTES]);

    impl From<[u8; 32]> for Blind {
        fn from(blind: [u8; 32]) -> Self {
            Blind(blind)
        }
    }

    impl Blind {
        /// Number of raw bytes in a blind.
        pub const BYTES: usize = 32;

        /// Creates a blind from raw bytes.
        pub fn new(blind: [u8; Blind::BYTES]) -> Self {
            Blind(blind)
        }

        /// Creates a blind from a slice.
        pub fn from_slice(blind: &[u8]) -> Result<Self, Error> {
            let mut blind_ = [0u8; Blind::BYTES];
            if blind.len() != blind_.len() {
                return Err(Error::InvalidBlind);
            }
            blind_.copy_from_slice(blind);
            Ok(Blind::new(blind_))
        }
    }

    #[cfg(feature = "random")]
    impl Default for Blind {
        /// Generates a random blind.
        fn default() -> Self {
            let mut blind = [0u8; Blind::BYTES];
            getrandom::getrandom(&mut blind).expect("RNG failure");
            Blind(blind)
        }
    }

    #[cfg(feature = "random")]
    impl Blind {
        /// Generates a random blind.
        pub fn generate() -> Self {
            Blind::default()
        }
    }

    impl Deref for Blind {
        type Target = [u8; Blind::BYTES];

        /// Returns a blind as raw bytes.
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    /// A blind public key.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub struct BlindPublicKey([u8; PublicKey::BYTES]);

    impl Deref for BlindPublicKey {
        type Target = [u8; BlindPublicKey::BYTES];

        /// Returns a public key as bytes.
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl BlindPublicKey {
        /// Number of bytes in a blind public key.
        pub const BYTES: usize = PublicKey::BYTES;

        /// Creates a blind public key from raw bytes.
        pub fn new(bpk: [u8; PublicKey::BYTES]) -> Self {
            BlindPublicKey(bpk)
        }

        /// Creates a blind public key from a slice.
        pub fn from_slice(bpk: &[u8]) -> Result<Self, Error> {
            let mut bpk_ = [0u8; PublicKey::BYTES];
            if bpk.len() != bpk_.len() {
                return Err(Error::InvalidPublicKey);
            }
            bpk_.copy_from_slice(bpk);
            Ok(BlindPublicKey::new(bpk_))
        }

        /// Unblinds a public key.
        pub fn unblind(&self, blind: &Blind) -> Result<PublicKey, Error> {
            let pk_p3 = GeP3::from_bytes_vartime(&self.0).ok_or(Error::InvalidPublicKey)?;
            let hash_output = sha512::Hash::hash(&blind[..]);
            let (blind_factor, _) = KeyPair::split(&hash_output, true, false);
            let inverse = sc_invert(&blind_factor);
            Ok(PublicKey(ge_scalarmult(&inverse, &pk_p3).to_bytes()))
        }

        /// Verifies that the signature `signature` is valid for the message `message`.
        pub fn verify(
            &self,
            message: impl AsRef<[u8]>,
            signature: &Signature,
        ) -> Result<(), Error> {
            PublicKey::new(self.0).verify(message, signature)
        }
    }

    impl From<PublicKey> for BlindPublicKey {
        fn from(pk: PublicKey) -> Self {
            BlindPublicKey(pk.0)
        }
    }

    impl From<BlindPublicKey> for PublicKey {
        fn from(bpk: BlindPublicKey) -> Self {
            PublicKey(bpk.0)
        }
    }

    /// A blind secret key.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub struct BlindSecretKey {
        pub prefix: [u8; 2 * Seed::BYTES],
        pub blind_scalar: [u8; 32],
        pub blind_pk: BlindPublicKey,
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub struct BlindKeyPair {
        /// Public key part of the blind key pair.
        pub blind_pk: BlindPublicKey,
        /// Secret key part of the blind key pair.
        pub blind_sk: BlindSecretKey,
    }

    impl BlindSecretKey {
        /// Computes a signature for the message `message` using the blind secret key.
        /// The noise parameter is optional, but recommended in order to mitigate fault attacks.
        pub fn sign(&self, message: impl AsRef<[u8]>, noise: Option<Noise>) -> Signature {
            let nonce = {
                let mut hasher = sha512::Hash::new();
                if let Some(noise) = noise {
                    hasher.update(&noise[..]);
                    hasher.update(&self.prefix);
                } else {
                    hasher.update(&self.prefix);
                }
                hasher.update(&message);
                let mut hash_output = hasher.finalize();
                sc_reduce(&mut hash_output[0..64]);
                hash_output
            };
            let mut signature: [u8; 64] = [0; 64];
            let r = ge_scalarmult_base(&nonce[0..32]);
            signature[0..32].copy_from_slice(&r.to_bytes()[..]);
            signature[32..64].copy_from_slice(&self.blind_pk.0);
            let mut hasher = sha512::Hash::new();
            hasher.update(signature.as_ref());
            hasher.update(&message);
            let mut hram = hasher.finalize();
            sc_reduce(&mut hram);
            sc_muladd(
                &mut signature[32..64],
                &hram[0..32],
                &self.blind_scalar,
                &nonce[0..32],
            );
            let signature = Signature(signature);

            #[cfg(feature = "self-verify")]
            {
                PublicKey::from_slice(&self.blind_pk.0)
                    .expect("Key length changed")
                    .verify(message, &signature)
                    .expect("Newly created signature cannot be verified");
            }
            signature
        }
    }

    impl PublicKey {
        /// Returns a blind version of the public key.
        pub fn blind(&self, blind: &Blind) -> Result<BlindPublicKey, Error> {
            let (blind_factor, _prefix2) = {
                let hash_output = sha512::Hash::hash(&blind[..]);
                KeyPair::split(&hash_output, true, false)
            };
            let pk_p3 = GeP3::from_bytes_vartime(&self.0).ok_or(Error::InvalidPublicKey)?;
            Ok(BlindPublicKey(
                ge_scalarmult(&blind_factor, &pk_p3).to_bytes(),
            ))
        }
    }

    impl KeyPair {
        /// Returns a blind version of the key pair.
        pub fn blind(&self, blind: &Blind) -> BlindKeyPair {
            let seed = self.sk.seed();
            let (scalar, prefix1) = {
                let hash_output = sha512::Hash::hash(&seed[..]);
                KeyPair::split(&hash_output, false, true)
            };

            let (blind_factor, prefix2) = {
                let hash_output = sha512::Hash::hash(&blind[..]);
                KeyPair::split(&hash_output, true, false)
            };

            let blind_scalar = sc_mul(&scalar, &blind_factor);
            let blind_pk = ge_scalarmult_base(&blind_scalar).to_bytes();

            let mut prefix = [0u8; 2 * Seed::BYTES];
            prefix[0..32].copy_from_slice(&prefix1);
            prefix[32..64].copy_from_slice(&prefix2);
            let blind_pk = BlindPublicKey::new(blind_pk);

            BlindKeyPair {
                blind_pk,
                blind_sk: BlindSecretKey {
                    prefix,
                    blind_scalar,
                    blind_pk,
                },
            }
        }
    }
}

#[cfg(feature = "blind-keys")]
pub use blind_keys::*;

#[test]
#[cfg(feature = "blind-keys")]
fn test_blind_ed25519() {
    use ct_codecs::{Decoder, Hex};

    let kp = KeyPair::generate();
    let blind = Blind::new([69u8; 32]);
    let blind_kp = kp.blind(&blind);
    let message = b"Hello, World!";
    let signature = blind_kp.blind_sk.sign(message, None);
    assert!(blind_kp.blind_pk.verify(message, &signature).is_ok());
    let recovered_pk = blind_kp.blind_pk.unblind(&blind).unwrap();
    assert!(recovered_pk == kp.pk);

    let kp = KeyPair::from_seed(
        Seed::from_slice(
            &Hex::decode_to_vec(
                "875532ab039b0a154161c284e19c74afa28d5bf5454e99284bbcffaa71eebf45",
                None,
            )
            .unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        Hex::decode_to_vec(
            "3b5983605b277cd44918410eb246bb52d83adfc806ccaa91a60b5b2011bc5973",
            None
        )
        .unwrap(),
        kp.pk.as_ref()
    );

    let blind = Blind::from_slice(
        &Hex::decode_to_vec(
            "c461e8595f0ac41d374f878613206704978115a226f60470ffd566e9e6ae73bf",
            None,
        )
        .unwrap(),
    )
    .unwrap();
    let blind_kp = kp.blind(&blind);
    assert_eq!(
        Hex::decode_to_vec(
            "e52bbb204e72a816854ac82c7e244e13a8fcc3217cfdeb90c8a5a927e741a20f",
            None
        )
        .unwrap(),
        blind_kp.blind_pk.as_ref()
    );

    let message = Hex::decode_to_vec("68656c6c6f20776f726c64", None).unwrap();
    let signature = blind_kp.blind_sk.sign(message, None);
    assert_eq!(Hex::decode_to_vec("f35d2027f14250c07b3b353359362ec31e13076a547c749a981d0135fce067a361ad6522849e6ed9f61d93b0f76428129b9eb3f9c3cd0bfa1bc2a086a5eebd09",
        None).unwrap(), signature.as_ref());
}
