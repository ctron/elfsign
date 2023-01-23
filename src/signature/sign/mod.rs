use crate::{
    signature::{digest::digest, Signatures, SignerConfiguration},
    utils::ElfType,
};
use async_trait::async_trait;
use object::read::elf::{ElfFile, FileHeader};
use std::future::Future;

mod elf;

pub(crate) use elf::sign;

/// Process the an elf file to generate a signature
#[async_trait(?Send)]
pub trait Processor<'data, Elf>
where
    Elf: ElfType,
{
    async fn run(self, file: ElfFile<'data, Elf::File>) -> anyhow::Result<Signatures>;
}

#[async_trait(?Send)]
impl<'data, Elf, F, Fut> Processor<'data, Elf> for F
where
    Elf: ElfType,
    F: FnOnce(ElfFile<'data, Elf::File>) -> Fut,
    Fut: Future<Output = anyhow::Result<Signatures>>,
{
    async fn run(self, file: ElfFile<'data, Elf::File>) -> anyhow::Result<Signatures> {
        self(file).await
    }
}

/// Create the signature from the parsed elf file.
pub async fn create_signature<S: SignerConfiguration, Elf>(
    signer: &S,
    elf: &ElfFile<'_, Elf>,
) -> anyhow::Result<Signatures>
where
    Elf: FileHeader,
{
    let signature = signer.sign(Box::new(|d| digest(d, elf))).await?;

    if log::log_enabled!(log::Level::Info) {
        log::info!("Signature: {}", base16::encode_lower(&signature.signature));
        log::info!(
            "Public Key: {}",
            base16::encode_lower(&signature.public_key)
        );
    }

    Ok(Signatures {
        signatures: vec![signature],
    })
}

/// Take the raw elf file data and run the processor.
async fn sign_raw<'data, Elf: ElfType>(
    in_data: &'data [u8],
    processor: impl Processor<'data, Elf>,
) -> anyhow::Result<Vec<u8>> {
    let elf = ElfFile::<'data, Elf::File>::parse(in_data)?;
    let endian = elf.endian();
    let signatures = processor.run(elf).await?;
    Ok(signatures.render_as_notes::<Elf>(endian))
}
