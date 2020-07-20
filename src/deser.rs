use std::fmt;
use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Unexpected, Visitor};
use serde::ser::{Serialize, Serializer};
use crate::KeyPair;

impl Serialize for KeyPair {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self[..])
    }
}

impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyPairVisitor;

        impl<'de> Visitor<'de> for KeyPairVisitor {
            type Value = KeyPair;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a KeyPair")
            }

            fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                KeyPair::from_slice(bytes).map_err(|_| {
                    let unexpected = Unexpected::Bytes(bytes);
                    E::invalid_value(unexpected, &self)
                })
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; KeyPair::BYTES];
                let mut index = 0;

                while let Some(b) = seq.next_element()? {
                    if index == KeyPair::BYTES {
                        return Err(A::Error::invalid_length(index + 1, &self));
                    }

                    bytes[index] = b;
                    index += 1;
                }

                if index != KeyPair::BYTES {
                    return Err(A::Error::invalid_length(index, &self));
                }

                KeyPair::from_slice(&bytes).map_err(|_| {
                    A::Error::invalid_value(Unexpected::Seq, &self)
                })
            }
        }

        deserializer.deserialize_bytes(KeyPairVisitor)
    }
}

#[cfg(test)]
mod test {
    use crate::{KeyPair, Seed};
    use serde_json::Error;

    #[test]
    fn test_serialize() -> Result<(), Error> {
        let expect = KeyPair::from_seed(Seed::generate());
        let json = serde_json::to_string(&expect)?;
        let actual: KeyPair = serde_json::from_str(&json)?;
        assert_eq!(&expect[..], &actual[..]);
        Ok(())
    }
}
