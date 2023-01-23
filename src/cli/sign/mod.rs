use crate::signature::{sign, SignatureNoteType};
use std::ffi::OsString;

mod sigstore;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Configuration {
    #[default]
    EcdsaP256Sha256,
    EcdsaP384Sha384,
}

impl From<Configuration> for SignatureNoteType {
    fn from(value: Configuration) -> Self {
        match value {
            Configuration::EcdsaP256Sha256 => Self::SignatureEcdsaP256Sha256,
            Configuration::EcdsaP384Sha384 => Self::SignatureEcdsaP384Sha384,
        }
    }
}

pub struct Options {
    pub input: OsString,
    pub output: OsString,
    pub configuration: Configuration,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    log::info!("Signing configuration: {:?}", options.configuration);

    sign(
        options.input,
        options.output,
        sigstore::create_signer(options.configuration).await?,
    )
    .await?;

    Ok(())
}
