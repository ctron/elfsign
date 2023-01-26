use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, der::Enumerated)]
#[repr(u32)]
pub enum Configuration {
    #[default]
    EcdsaP256Sha256 = 0,
    EcdsaP384Sha384 = 1,
}

impl Display for Configuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EcdsaP256Sha256 => f.write_str("ECDSA P-256/SHA-256"),
            Self::EcdsaP384Sha384 => f.write_str("ECDSA P-384/SHA-384"),
        }
    }
}

impl From<Configuration> for DigestAlgorithm {
    fn from(value: Configuration) -> Self {
        match value {
            Configuration::EcdsaP256Sha256 => Self::Sha256,
            Configuration::EcdsaP384Sha384 => Self::Sha384,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
}

impl Display for DigestAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256 => f.write_str("SHA-256"),
            Self::Sha384 => f.write_str("SHA-384"),
        }
    }
}
