use core::fmt::{self, Display};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The signature doesn't verify.
    SignatureMismatch,
    /// A weak public key was used.
    WeakPublicKey,
    /// The public key is invalid.
    InvalidPublicKey,
    /// The secret key is invalid.
    InvalidSecretKey,
    /// The signature is invalid.
    InvalidSignature,
    /// The seed doesn't have the expected length.
    InvalidSeed,
    /// The noise doesn't have the expected length.
    InvalidNoise,
    /// Parse error
    ParseError,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SignatureMismatch => write!(f, "Signature doesn't verify"),
            Error::WeakPublicKey => write!(f, "Weak public key"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidSecretKey => write!(f, "Invalid secret key"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::InvalidSeed => write!(f, "Invalid seed length"),
            Error::InvalidNoise => write!(f, "Invalid noise length"),
            Error::ParseError => write!(f, "Parse error"),
        }
    }
}
