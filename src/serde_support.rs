use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    SecretKey,
    PublicKey,
    KeyPair,
    Signature,
};

mod de {
    use core::fmt;
    use serde::{Deserialize, Deserializer, de};
    use super::{
        Signature,
        PublicKey,
        SecretKey,
    };
    pub struct SignatureVisitor;

    impl<'de> de::Visitor<'de> for SignatureVisitor {
        type Value = Signature;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "expecting a NewtypeStruct")
        }

        fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = <serde_bytes::ByteBuf>::deserialize(deserializer)?;
            Self::Value::from_slice(&bytes).map_err(serde::de::Error::custom)
        }
    }
    pub struct PublicKeyVisitor;

    impl<'de> de::Visitor<'de> for PublicKeyVisitor {
        type Value = PublicKey;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "expecting a NewtypeStruct")
        }

        fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = <serde_bytes::ByteBuf>::deserialize(deserializer)?;
            Self::Value::from_slice(&bytes).map_err(serde::de::Error::custom)
        }
    }
    pub struct SecretKeyVisitor;

    impl<'de> de::Visitor<'de> for SecretKeyVisitor {
        type Value = SecretKey;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "expecting a NewtypeStruct")
        }

        fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = <serde_bytes::ByteBuf>::deserialize(deserializer)?;
            Self::Value::from_slice(&bytes).map_err(serde::de::Error::custom)
        }
    }

}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_ref();
        serializer.serialize_newtype_struct("PublicKey", serde_bytes::Bytes::new(bytes))
    }
}
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = de::PublicKeyVisitor{};
        deserializer.deserialize_newtype_struct("PublicKey", v)
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_ref();
        serializer.serialize_newtype_struct("SecretKey", serde_bytes::Bytes::new(bytes))
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = de::SecretKeyVisitor{};
        deserializer.deserialize_newtype_struct("SecretKey", v)
    }
}

impl Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.sk.as_ref();
        serializer.serialize_newtype_struct("KeyPair", serde_bytes::Bytes::new(bytes))
    }
}

impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = de::SecretKeyVisitor{};
        let sk = deserializer.deserialize_newtype_struct("KeyPair", v)?;
        Ok(KeyPair{
            sk,
            pk: sk.public_key(),
        })
        
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_ref();
        serializer.serialize_newtype_struct("Signature", serde_bytes::Bytes::new(bytes))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = de::SignatureVisitor{};
        deserializer.deserialize_newtype_struct("Signature", v)
    }
}

#[cfg(test)]
mod test_serde {
    use super::*;
    use serde_test::{Token, assert_tokens};
    #[test]
    fn test_serde_sk() {
        let kp = KeyPair::from_seed([42u8; 32].into());
        assert_tokens(
            &kp.sk,
            &[
                Token::NewtypeStruct {
                    name: "SecretKey"
                },
                Token::Bytes(&[
                    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 25, 127, 107, 35, 225, 108, 133, 50, 198,
                    171, 200, 56, 250, 205, 94, 167, 137, 190, 12, 118, 178, 146, 3, 52, 3, 155, 250, 139,
                    61, 54, 141, 97
                    ]),
            ]
        );
    }
    #[test]
    fn test_serde_pk() {
        let kp = KeyPair::from_seed([42u8; 32].into());
        assert_tokens(
            &kp.pk,
            &[
                Token::NewtypeStruct {
                    name: "PublicKey"
                },
                Token::Bytes(&[ 25, 127, 107, 35, 225, 108, 133, 50, 198, 171,
                    200, 56, 250, 205, 94, 167, 137, 190, 12, 118, 178, 146, 3, 52,
                    3, 155, 250, 139, 61, 54, 141, 97, ]),
            ]
        );
    }
    #[test]
    fn test_serde_signature() {
        let kp = KeyPair::from_seed([42u8; 32].into());
        let message = b"Hello, World!";
        let signature = kp.sk.sign(message, None);
        assert_tokens(
            &signature,
            &[
                Token::NewtypeStruct {
                    name: "Signature"
                },
                Token::Bytes(&[
                196, 182, 1, 15, 182, 182, 231, 166, 227, 62, 243, 85, 49, 174, 169, 9, 162, 196, 98,
                104, 30, 81, 22, 38, 184, 136, 253, 128, 10, 160, 128, 105, 127, 130, 138, 164, 57, 86,
                94, 160, 216, 85, 153, 139, 81, 100, 38, 124, 235, 210, 26, 95, 231, 90, 73, 206, 33,
                216, 171, 15, 188, 181, 136, 7,
                ]),
            ]
        );
    }
    #[test]
    fn test_serde_key_pair() {
        let kp = KeyPair::from_seed([42u8; 32].into());
        assert_tokens(
            &kp,
            &[
                Token::NewtypeStruct {
                    name: "KeyPair",
                },
                Token::Bytes(&[
                    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 25, 127, 107, 35, 225, 108, 133, 50, 198,
                    171, 200, 56, 250, 205, 94, 167, 137, 190, 12, 118, 178, 146, 3, 52, 3, 155, 250, 139,
                    61, 54, 141, 97
                    ]),
            ]
        );
    }
}
