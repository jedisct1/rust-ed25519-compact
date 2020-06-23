use core::fmt::{self, Display};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The signature doesn't verify.
    SignatureMismatch,
    /// A weak public key was used.
    WeakPublicKey,
    /// An invalid public key was used.
    InvalidPublicKey,
    /// The signature is not canonical.
    NoncanonicalSignature,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SignatureMismatch => write!(f, "Signature doesn't verify"),
            Error::WeakPublicKey => write!(f, "Weak public key"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::NoncanonicalSignature => write!(f, "Non-canonical signature"),
        }
    }
}
