use crate::signature::digest::digest;
use crate::utils::elf::{process_elf, Kind};
use crate::utils::ElfType;
use digest::{Digest, Update};
use object::{elf, read::elf::ElfFile, Endianness};
use sha2::{Sha256, Sha384, Sha512};
use std::ffi::OsString;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum DigestAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub fn apply<Elf: ElfType>(&self, file: ElfFile<Elf::File>) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Sha256 => Self::digest::<Elf, Sha256>(file),
            Self::Sha384 => Self::digest::<Elf, Sha384>(file),
            Self::Sha512 => Self::digest::<Elf, Sha512>(file),
        }
    }

    fn digest<Elf: ElfType, D: Digest + Update>(
        file: ElfFile<Elf::File>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut d = D::new();
        digest(&mut d, &file)?;
        Ok(d.finalize().to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub input: OsString,
    pub algorithm: DigestAlgorithm,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    let algo = options.algorithm;
    let digest = process_elf(options.input, move |kind, file| {
        Box::pin(async move {
            match kind {
                Kind::Elf32 => digest_file::<elf::FileHeader32<Endianness>>(file, algo),
                Kind::Elf64 => digest_file::<elf::FileHeader64<Endianness>>(file, algo),
            }
        })
    })
    .await?;

    println!("{}", base16::encode_lower(&digest));

    Ok(())
}

/// extract signatures from an elf binary
fn digest_file<Elf: ElfType>(data: &[u8], digest: DigestAlgorithm) -> anyhow::Result<Vec<u8>> {
    let file = ElfFile::parse(data)?;
    digest.apply::<Elf>(file)
}
