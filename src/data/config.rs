#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, der::Enumerated)]
#[repr(u32)]
pub enum Configuration {
    #[default]
    EcdsaP256Sha256 = 0,
    EcdsaP384Sha384 = 1,
}
