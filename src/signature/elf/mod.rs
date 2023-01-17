use crate::signature::{digest::digest, Signatures, SignerConfiguration};
use crate::utils::ElfType;
use object::read::elf::{ElfFile, FileHeader};

mod elfcopy;

pub(crate) use elfcopy::elfcopy;

/// Process the an elf file to generate a signature
pub trait Processor<'data, Elf>
where
    Elf: ElfType,
{
    fn run(self, file: ElfFile<'data, Elf::File>) -> anyhow::Result<Signatures>;
}

impl<'data, Elf, F> Processor<'data, Elf> for F
where
    Elf: ElfType,
    F: FnOnce(ElfFile<'data, Elf::File>) -> anyhow::Result<Signatures>,
{
    fn run(self, file: ElfFile<'data, Elf::File>) -> anyhow::Result<Signatures> {
        self(file)
    }
}

/// Create the signature from the parsed elf file.
pub fn create_signature<S: SignerConfiguration, Elf>(
    signer: &S,
    elf: &ElfFile<Elf>,
) -> anyhow::Result<Signatures>
where
    Elf: FileHeader,
{
    let signature = signer.sign(Box::new(|d| digest(d, &elf)))?;

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
fn sign_raw<'data, Elf: ElfType>(
    in_data: &'data [u8],
    processor: impl Processor<'data, Elf>,
) -> anyhow::Result<Vec<u8>> {
    let elf = ElfFile::<'data, Elf::File>::parse(in_data)?;
    let endian = elf.endian();
    let signatures = processor.run(elf)?;
    Ok(signatures.render_data::<Elf>(endian))
}
