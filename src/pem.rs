#[cfg(feature = "std")]
use ct_codecs::Encoder;
use ct_codecs::{Base64, Decoder};

use super::{Error, KeyPair, PublicKey, SecretKey, Seed};

const DER_HEADER_SK: [u8; 16] = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];

const DER_HEADER_PK: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];

impl KeyPair {
    /// Import a key pair from an OpenSSL-compatible DER file.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        if der.len() != DER_HEADER_SK.len() + Seed::BYTES || der[0..16] != DER_HEADER_SK {
            return Err(Error::ParseError);
        }
        let mut seed = [0u8; Seed::BYTES];
        seed.copy_from_slice(&der[16..]);
        let kp = KeyPair::from_seed(Seed::new(seed));
        Ok(kp)
    }

    /// Import a key pair from an OpenSSL-compatible PEM file.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let mut it = pem.split("-----BEGIN PRIVATE KEY-----");
        let _ = it.next().ok_or(Error::ParseError)?;
        let inner = it.next().ok_or(Error::ParseError)?;
        let mut it = inner.split("-----END PRIVATE KEY-----");
        let b64 = it.next().ok_or(Error::ParseError)?;
        let _ = it.next().ok_or(Error::ParseError)?;
        let mut der = [0u8; 16 + Seed::BYTES];
        Base64::decode(&mut der, b64, Some(b"\r\n\t ")).map_err(|_| Error::ParseError)?;
        Self::from_der(&der)
    }

    /// Export a key pair as an OpenSSL-compatible PEM file.
    #[cfg(feature = "std")]
    pub fn to_pem(&self) -> String {
        format!("{}\n{}\n", self.sk.to_pem().trim(), self.pk.to_pem().trim())
    }
}

impl SecretKey {
    /// Import a secret key from an OpenSSL-compatible DER file.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let kp = KeyPair::from_der(der)?;
        Ok(kp.sk)
    }

    /// Import a secret key from an OpenSSL-compatible PEM file.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let kp = KeyPair::from_pem(pem)?;
        Ok(kp.sk)
    }

    /// Export a secret key as an OpenSSL-compatible DER file.
    #[cfg(feature = "std")]
    pub fn to_der(&self) -> Vec<u8> {
        let mut der = [0u8; 16 + Seed::BYTES];
        der[0..16].copy_from_slice(&DER_HEADER_SK);
        der[16..].copy_from_slice(self.seed().as_ref());
        der.to_vec()
    }

    /// Export a secret key as an OpenSSL-compatible PEM file.
    #[cfg(feature = "std")]
    pub fn to_pem(&self) -> String {
        let b64 = Base64::encode_to_string(self.to_der()).unwrap();
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64
        )
    }
}

impl PublicKey {
    /// Import a public key from an OpenSSL-compatible DER file.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        if der.len() != DER_HEADER_PK.len() + PublicKey::BYTES || der[0..12] != DER_HEADER_PK {
            return Err(Error::ParseError);
        }
        let mut pk = [0u8; PublicKey::BYTES];
        pk.copy_from_slice(&der[12..]);
        let pk = PublicKey::new(pk);
        Ok(pk)
    }

    /// Import a public key from an OpenSSL-compatible PEM file.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let mut it = pem.split("-----BEGIN PUBLIC KEY-----");
        let _ = it.next().ok_or(Error::ParseError)?;
        let inner = it.next().ok_or(Error::ParseError)?;
        let mut it = inner.split("-----END PUBLIC KEY-----");
        let b64 = it.next().ok_or(Error::ParseError)?;
        let _ = it.next().ok_or(Error::ParseError)?;
        let mut der = [0u8; 12 + PublicKey::BYTES];
        Base64::decode(&mut der, b64, Some(b"\r\n\t ")).map_err(|_| Error::ParseError)?;
        Self::from_der(&der)
    }

    /// Export a public key as an OpenSSL-compatible DER file.
    #[cfg(feature = "std")]
    pub fn to_der(&self) -> Vec<u8> {
        let mut der = [0u8; 12 + PublicKey::BYTES];
        der[0..12].copy_from_slice(&DER_HEADER_PK);
        der[12..].copy_from_slice(self.as_ref());
        der.to_vec()
    }

    /// Export a public key as an OpenSSL-compatible PEM file.
    #[cfg(feature = "std")]
    pub fn to_pem(&self) -> String {
        let b64 = Base64::encode_to_string(self.to_der()).unwrap();
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            b64
        )
    }
}

#[test]
fn test_pem() {
    let sk_pem = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMXY1NUbUe/3dW2YUoKW5evsnCJPMfj60/q0RzGne3gg
-----END PRIVATE KEY-----\n";
    let sk = SecretKey::from_pem(sk_pem).unwrap();

    let pk_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyrRjJfTnhMcW5igzYvPirFW5eUgMdKeClGzQhd4qw+Y=
-----END PUBLIC KEY-----\n";
    let pk = PublicKey::from_pem(pk_pem).unwrap();

    assert_eq!(sk.public_key(), pk);

    #[cfg(features = "std")]
    {
        let sk_pem2 = sk.to_pem();
        let pk_pem2 = pk.to_pem();
        assert_eq!(sk_pem, sk_pem2);
        assert_eq!(pk_pem, pk_pem2);
    }
}

#[test]
fn test_der() {
    let kp = KeyPair::generate();
    let sk_der = kp.sk.to_der();
    let sk2 = SecretKey::from_der(&sk_der).unwrap();
    let pk_der = kp.pk.to_der();
    let pk2 = PublicKey::from_der(&pk_der).unwrap();
    assert_eq!(kp.sk, sk2);
    assert_eq!(kp.pk, pk2);
}
