use crate::{
    utils::{elf::process_elf, ElfType},
    verification::elf::{extract_signatures, verify_signatures},
};
use anyhow::bail;
use object::{elf, read::elf::ElfFile, Endianness};
use std::ffi::OsString;

#[derive(Clone, Debug)]
pub struct Options {
    pub input: OsString,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    process_elf(
        options.input,
        verify_file::<elf::FileHeader32<Endianness>>,
        verify_file::<elf::FileHeader64<Endianness>>,
    )
}

fn verify_file<Elf: ElfType>(data: &[u8]) -> anyhow::Result<()> {
    let file = ElfFile::parse(data)?;
    let signatures = extract_signatures::<Elf>(&file.raw_header(), data)?;
    let signatures = verify_signatures::<Elf>(&file, signatures)?;

    if signatures.is_empty() {
        bail!("No valid signature found");
    }

    Ok(())
}
