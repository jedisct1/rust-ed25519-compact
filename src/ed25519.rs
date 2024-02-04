use core::convert::TryFrom;
use core::fmt;
use core::ops::{Deref, DerefMut};

use super::common::*;
#[cfg(feature = "blind-keys")]
use super::edwards25519::{ge_scalarmult, sc_invert, sc_mul};
use super::edwards25519::{
    ge_scalarmult_base, is_identity, sc_muladd, sc_reduce, sc_reduce32, sc_reject_noncanonical,
    GeP2, GeP3,
};
use super::error::Error;
use super::sha512;

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

impl DerefMut for PublicKey {
    /// Returns a public key as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A secret key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
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
        Seed::from_slice(&self[0..Seed::BYTES]).unwrap()
    }

    /// Returns `Ok(())` if the given public key is the public counterpart of
    /// this secret key.
    /// Returns `Err(Error::InvalidPublicKey)` otherwise.
    /// The public key is recomputed (not just copied) from the secret key,
    /// so this will detect corruption of the secret key.
    pub fn validate_public_key(&self, pk: &PublicKey) -> Result<(), Error> {
        let kp = KeyPair::from_seed(self.seed());
        if kp.pk != *pk {
            return Err(Error::InvalidPublicKey);
        }
        Ok(())
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
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
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
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

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Signature::from_slice(slice)
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

impl DerefMut for Signature {
    /// Returns a signature as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The state of a streaming verification operation.
#[derive(Clone)]
pub struct VerifyingState {
    hasher: sha512::Hash,
    signature: Signature,
    a: GeP3,
}

impl Drop for VerifyingState {
    fn drop(&mut self) {
        Mem::wipe(self.signature.0);
    }
}

impl VerifyingState {
    fn new(pk: &PublicKey, signature: &Signature) -> Result<Self, Error> {
        let r = &signature[0..32];
        let s = &signature[32..64];
        sc_reject_noncanonical(s)?;
        if is_identity(pk) || pk.iter().fold(0, |acc, x| acc | x) == 0 {
            return Err(Error::WeakPublicKey);
        }
        let a = match GeP3::from_bytes_negate_vartime(pk) {
            Some(g) => g,
            None => {
                return Err(Error::InvalidPublicKey);
            }
        };
        let mut hasher = sha512::Hash::new();
        hasher.update(r);
        hasher.update(&pk[..]);
        Ok(VerifyingState {
            hasher,
            signature: *signature,
            a,
        })
    }

    /// Appends data to the message being verified.
    pub fn absorb(&mut self, chunk: impl AsRef<[u8]>) {
        self.hasher.update(chunk)
    }

    /// Verifies the signature and return it.
    pub fn verify(&self) -> Result<(), Error> {
        let mut expected_r_bytes = [0u8; 32];
        expected_r_bytes.copy_from_slice(&self.signature[0..32]);
        let expected_r =
            GeP3::from_bytes_vartime(&expected_r_bytes).ok_or(Error::InvalidSignature)?;
        let s = &self.signature[32..64];

        let mut hash = self.hasher.finalize();
        sc_reduce(&mut hash);

        let r = GeP2::double_scalarmult_vartime(hash.as_ref(), self.a, s);
        if (expected_r - GeP3::from(r)).has_small_order() {
            Ok(())
        } else {
            Err(Error::SignatureMismatch)
        }
    }
}

impl PublicKey {
    /// Verify the signature of a multi-part message (streaming).
    pub fn verify_incremental(&self, signature: &Signature) -> Result<VerifyingState, Error> {
        VerifyingState::new(self, signature)
    }

    /// Verifies that the signature `signature` is valid for the message
    /// `message`.
    pub fn verify(&self, message: impl AsRef<[u8]>, signature: &Signature) -> Result<(), Error> {
        let mut st = VerifyingState::new(self, signature)?;
        st.absorb(message);
        st.verify()
    }
}

/// The state of a streaming signature operation.
#[derive(Clone)]
pub struct SigningState {
    hasher: sha512::Hash,
    az: [u8; 64],
    nonce: [u8; 64],
}

impl Drop for SigningState {
    fn drop(&mut self) {
        Mem::wipe(self.az);
        Mem::wipe(self.nonce);
    }
}

impl SigningState {
    fn new(nonce: [u8; 64], az: [u8; 64], pk_: &[u8]) -> Self {
        let mut prefix: [u8; 64] = [0; 64];
        let r = ge_scalarmult_base(&nonce[0..32]);
        prefix[0..32].copy_from_slice(&r.to_bytes()[..]);
        prefix[32..64].copy_from_slice(pk_);

        let mut st = sha512::Hash::new();
        st.update(prefix);

        SigningState {
            hasher: st,
            nonce,
            az,
        }
    }

    /// Appends data to the message being signed.
    pub fn absorb(&mut self, chunk: impl AsRef<[u8]>) {
        self.hasher.update(chunk)
    }

    /// Computes the signature and return it.
    pub fn sign(&self) -> Signature {
        let mut signature: [u8; 64] = [0; 64];
        let r = ge_scalarmult_base(&self.nonce[0..32]);
        signature[0..32].copy_from_slice(&r.to_bytes()[..]);
        let mut hram = self.hasher.finalize();
        sc_reduce(&mut hram);
        sc_muladd(
            &mut signature[32..64],
            &hram[0..32],
            &self.az[0..32],
            &self.nonce[0..32],
        );
        Signature(signature)
    }
}

impl SecretKey {
    /// Sign a multi-part message (streaming API).
    /// It is critical for `noise` to never repeat.
    pub fn sign_incremental(&self, noise: Noise) -> SigningState {
        let seed = &self[0..32];
        let pk = &self[32..64];
        let az: [u8; 64] = {
            let mut hash_output = sha512::Hash::hash(seed);
            hash_output[0] &= 248;
            hash_output[31] &= 63;
            hash_output[31] |= 64;
            hash_output
        };
        let mut st = sha512::Hash::new();
        #[cfg(feature = "random")]
        {
            let additional_noise = Noise::generate();
            st.update(additional_noise.as_ref());
        }
        st.update(noise.as_ref());
        st.update(seed);
        let nonce = st.finalize();
        SigningState::new(nonce, az, pk)
    }

    /// Computes a signature for the message `message` using the secret key.
    /// The noise parameter is optional, but recommended in order to mitigate
    /// fault attacks.
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
        let mut st = SigningState::new(nonce, az, pk);
        st.absorb(&message);
        let signature = st.sign();

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
        sk[0..32].copy_from_slice(&*seed);
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

    /// Clamp a scalar.
    pub fn clamp(scalar: &mut [u8]) {
        scalar[0] &= 248;
        scalar[31] &= 63;
        scalar[31] |= 64;
    }

    /// Split a serialized representation of a key pair into a secret scalar and
    /// a prefix.
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

    /// Check that the public key is valid for the secret key.
    pub fn validate(&self) -> Result<(), Error> {
        self.sk.validate_public_key(&self.pk)
    }
}

impl Deref for KeyPair {
    type Target = [u8; KeyPair::BYTES];

    /// Returns a key pair as bytes.
    fn deref(&self) -> &Self::Target {
        &self.sk
    }
}

impl DerefMut for KeyPair {
    /// Returns a key pair as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sk
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

    /// Returns the noise as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Noise {
    /// Returns the noise as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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

#[cfg(feature = "traits")]
mod ed25519_trait {
    use ::ed25519::signature as ed25519_trait;

    use super::{PublicKey, SecretKey, Signature};

    impl ed25519_trait::SignatureEncoding for Signature {
        type Repr = Signature;
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
                    .map_err(ed25519_trait::Error::from_source)
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

    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
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

    impl Drop for Blind {
        fn drop(&mut self) {
            Mem::wipe(self.0)
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

        /// Returns a blind as bytes.
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for Blind {
        /// Returns a blind as mutable bytes.
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
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

    impl DerefMut for BlindPublicKey {
        /// Returns a public key as mutable bytes.
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
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
        pub fn unblind(&self, blind: &Blind, ctx: impl AsRef<[u8]>) -> Result<PublicKey, Error> {
            let pk_p3 = GeP3::from_bytes_vartime(&self.0).ok_or(Error::InvalidPublicKey)?;
            let mut hx = sha512::Hash::new();
            hx.update(&blind[..]);
            hx.update([0u8]);
            hx.update(ctx.as_ref());
            let hash_output = hx.finalize();
            let (blind_factor, _) = KeyPair::split(&hash_output, true, false);
            let inverse = sc_invert(&blind_factor);
            Ok(PublicKey(ge_scalarmult(&inverse, &pk_p3).to_bytes()))
        }

        /// Verifies that the signature `signature` is valid for the message
        /// `message`.
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
    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
    pub struct BlindSecretKey {
        pub prefix: [u8; 2 * Seed::BYTES],
        pub blind_scalar: [u8; 32],
        pub blind_pk: BlindPublicKey,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
    pub struct BlindKeyPair {
        /// Public key part of the blind key pair.
        pub blind_pk: BlindPublicKey,
        /// Secret key part of the blind key pair.
        pub blind_sk: BlindSecretKey,
    }

    impl BlindSecretKey {
        /// Computes a signature for the message `message` using the blind
        /// secret key. The noise parameter is optional, but recommended
        /// in order to mitigate fault attacks.
        pub fn sign(&self, message: impl AsRef<[u8]>, noise: Option<Noise>) -> Signature {
            let nonce = {
                let mut hasher = sha512::Hash::new();
                if let Some(noise) = noise {
                    hasher.update(&noise[..]);
                    hasher.update(self.prefix);
                } else {
                    hasher.update(self.prefix);
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

    impl Drop for BlindSecretKey {
        fn drop(&mut self) {
            Mem::wipe(self.prefix);
            Mem::wipe(self.blind_scalar);
        }
    }

    impl PublicKey {
        /// Returns a blind version of the public key.
        pub fn blind(&self, blind: &Blind, ctx: impl AsRef<[u8]>) -> Result<BlindPublicKey, Error> {
            let (blind_factor, _prefix2) = {
                let mut hx = sha512::Hash::new();
                hx.update(&blind[..]);
                hx.update([0u8]);
                hx.update(ctx.as_ref());
                let hash_output = hx.finalize();
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
        pub fn blind(&self, blind: &Blind, ctx: impl AsRef<[u8]>) -> BlindKeyPair {
            let seed = self.sk.seed();
            let (scalar, prefix1) = {
                let hash_output = sha512::Hash::hash(&seed[..]);
                KeyPair::split(&hash_output, false, true)
            };

            let (blind_factor, prefix2) = {
                let mut hx = sha512::Hash::new();
                hx.update(&blind[..]);
                hx.update([0u8]);
                hx.update(ctx.as_ref());
                let hash_output = hx.finalize();
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
    let blind_kp = kp.blind(&blind, "ctx");
    let message = b"Hello, World!";
    let signature = blind_kp.blind_sk.sign(message, None);
    assert!(blind_kp.blind_pk.verify(message, &signature).is_ok());
    let recovered_pk = blind_kp.blind_pk.unblind(&blind, "ctx").unwrap();
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
    let blind_kp = kp.blind(&blind, "ctx");
    assert_eq!(
        Hex::decode_to_vec(
            "246dcd43930b81d5e4d770db934a9fcd985b75fd014bc2a98b0aea02311c1836",
            None
        )
        .unwrap(),
        blind_kp.blind_pk.as_ref()
    );

    let message = Hex::decode_to_vec("68656c6c6f20776f726c64", None).unwrap();
    let signature = blind_kp.blind_sk.sign(message, None);
    assert_eq!(Hex::decode_to_vec("947bacfabc63448f8955dc20630e069e58f37b72bb433ae17f2fa904ea860b44deb761705a3cc2168a6673ee0b41ff7765c7a4896941eec6833c1689315acb0b",
        None).unwrap(), signature.as_ref());
}

#[test]
fn test_streaming() {
    let kp = KeyPair::generate();

    let msg1 = "mes";
    let msg2 = "sage";
    let mut st = kp.sk.sign_incremental(Noise::default());
    st.absorb(msg1);
    st.absorb(msg2);
    let signature = st.sign();

    let msg1 = "mess";
    let msg2 = "age";
    let mut st = kp.pk.verify_incremental(&signature).unwrap();
    st.absorb(msg1);
    st.absorb(msg2);
    assert!(st.verify().is_ok());
}

#[test]
#[cfg(feature = "random")]
fn test_ed25519_invalid_keypair() {
    let kp1 = KeyPair::generate();
    let kp2 = KeyPair::generate();

    assert_eq!(
        kp1.sk.validate_public_key(&kp2.pk).unwrap_err(),
        Error::InvalidPublicKey
    );
    assert_eq!(
        kp2.sk.validate_public_key(&kp1.pk).unwrap_err(),
        Error::InvalidPublicKey
    );
    assert!(kp1.sk.validate_public_key(&kp1.pk).is_ok());
    assert!(kp2.sk.validate_public_key(&kp2.pk).is_ok());
    assert!(kp1.validate().is_ok());
}
