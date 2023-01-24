use crate::{data::Configuration, signature::sign};
use std::ffi::OsString;

mod sigstore;

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
