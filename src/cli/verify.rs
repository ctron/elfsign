use crate::{
    utils::ElfType,
    verification::elf::{extract_signatures, verify_signatures},
};
use anyhow::bail;
use object::{elf, read::elf::ElfFile, Endianness};
use std::{ffi::OsString, fs};

#[derive(Clone, Debug)]
pub struct Options {
    pub input: OsString,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    let in_data = fs::read(&options.input)?;
    let in_data = &*in_data;

    let kind = match object::FileKind::parse(in_data) {
        Ok(file) => file,
        Err(err) => {
            bail!("Failed to parse file: {}", err);
        }
    };
    match kind {
        object::FileKind::Elf32 => verify_file::<elf::FileHeader32<Endianness>>(in_data)?,
        object::FileKind::Elf64 => verify_file::<elf::FileHeader64<Endianness>>(in_data)?,
        _ => {
            bail!("Not an ELF file");
        }
    };

    Ok(())
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
