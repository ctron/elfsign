// FIXME: handle the case of an existing signature section

use crate::signature::{
    elf::{create_signature, sign_raw, Processor},
    SignerConfiguration, SIGNATURE_V1_SECTION,
};
use crate::utils::ElfType;
use anyhow::bail;
use object::elf::{SectionHeader32, SectionHeader64};
use object::read::elf::{FileHeader, SectionHeader};
use object::{bytes_of, elf, Endian, Endianness, Pod, SectionIndex, U16, U32, U64};
use std::cmp::min;
use std::fs;
use std::path::Path;

pub(crate) fn elfcopy<P1, P2, S>(
    in_file_path: P1,
    out_file_path: P2,
    signer: S,
) -> anyhow::Result<()>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
    S: SignerConfiguration,
{
    let in_file_path = in_file_path.as_ref();
    let out_file_path = out_file_path.as_ref();

    let in_data = fs::read(in_file_path)?;
    let in_data = &*in_data;

    let kind = match object::FileKind::parse(in_data) {
        Ok(file) => file,
        Err(err) => {
            bail!("Failed to parse file: {}", err);
        }
    };
    let out_data = match kind {
        object::FileKind::Elf32 => copy_file::<elf::FileHeader32<Endianness>>(in_data, |file| {
            create_signature(&signer, &file)
        })?,
        object::FileKind::Elf64 => copy_file::<elf::FileHeader64<Endianness>>(in_data, |file| {
            create_signature(&signer, &file)
        })?,
        _ => {
            bail!("Not an ELF file");
        }
    };

    if let Err(err) = fs::write(&out_file_path, out_data) {
        bail!(
            "Failed to write file '{}': {}",
            out_file_path.to_string_lossy(),
            err
        );
    }

    Ok(())
}

fn copy_file<'data, Elf: ElfType<Endian = Endianness>>(
    in_data: &'data [u8],
    processor: impl Processor<'data, Elf>,
) -> anyhow::Result<Vec<u8>> {
    let sig_data = sign_raw(in_data, processor)?;

    // copy all to output buffer
    let mut out = in_data.to_vec();

    let file = Elf::File::parse(in_data)?;
    let endian = file.endian()?;

    let shstrndx = file.e_shstrndx(endian);
    let sections = file.sections(endian, in_data)?;

    let shstrtab = sections.section(SectionIndex(shstrndx as usize))?;
    let shoff = file.e_shoff(endian).into() as usize;

    // copy .shrstrtab to new location
    let new_e_shstrndx_offset = out.len();
    out.extend(shstrtab.data(endian, in_data)?);
    // append SIGNATURE_HEADER
    //let sig_section_name_index = out.len() - new_e_shstrndx_offset;
    let sig_section_name_index = out.len() - new_e_shstrndx_offset;
    out.extend(SIGNATURE_V1_SECTION.as_bytes());
    out.push(b'\0');
    // record new indexes and offsets
    let new_e_shstrndx_len = out.len() - new_e_shstrndx_offset;

    // append signatures
    let sig_data_offset = out.len();
    let sig_data_len = sig_data.len();
    out.extend(sig_data);

    // copy section headers
    let new_section_header_offset = out.len();
    let section_header_size = file.e_shentsize(endian) as usize * file.e_shnum(endian) as usize;
    out.extend(&in_data[shoff..shoff + section_header_size]);
    let mut new_section_header_count = file.e_shnum(endian);

    // append section header for signature
    out.extend(section_header_signatures(
        endian,
        file.is_type_64(),
        sig_section_name_index,
        sig_data_offset,
        sig_data_len,
    ));
    new_section_header_count += 1;

    // update .shrstrtab offset (before coping section header table)
    patch_section_header::<Elf>(
        new_section_header_offset,
        &mut out,
        SectionIndex(file.e_shstrndx(endian) as usize),
        Elf::SH_OFFSET,
        Elf::WORD,
        &Elf::word(endian, new_e_shstrndx_offset),
    );
    patch_section_header::<Elf>(
        new_section_header_offset,
        &mut out,
        SectionIndex(file.e_shstrndx(endian) as usize),
        Elf::SH_SIZE,
        Elf::WORD,
        &Elf::word(endian, new_e_shstrndx_len),
    );

    // update section header offset and num (e_shoff and e_shnum)
    patch(
        Elf::e_shoff_mut(&mut out),
        &Elf::word(endian, new_section_header_offset),
    );
    patch_pod(
        Elf::e_shnum_mut(&mut out),
        &U16::new(endian, new_section_header_count as u16),
    );

    Ok(out)
}

fn section_header_signatures<E: Endian>(
    endian: E,
    is_64bit: bool,
    name_index: usize,
    offset: usize,
    len: usize,
) -> Vec<u8> {
    let zero = U32::new(endian, 0);

    let sh_name = U32::new(endian, name_index as u32);
    let sh_type = U32::new(endian, elf::SHT_NOTE);

    if !is_64bit {
        bytes_of(&SectionHeader32 {
            sh_name,
            sh_type,
            sh_flags: U32::new(endian, 0),
            sh_addr: zero,
            sh_offset: U32::new(endian, offset as u32),
            sh_size: U32::new(endian, len as u32),
            sh_link: zero,
            sh_info: zero,
            sh_addralign: U32::new(endian, 1),
            sh_entsize: zero,
        })
        .to_vec()
    } else {
        bytes_of(&SectionHeader64 {
            sh_name,
            sh_type,
            sh_flags: U64::new(endian, 0),
            sh_addr: U64::new(endian, 0),
            sh_offset: U64::new(endian, offset as u64),
            sh_size: U64::new(endian, len as u64),
            sh_link: zero,
            sh_info: zero,
            sh_addralign: U64::new(endian, 1),
            sh_entsize: U64::new(endian, 0),
        })
        .to_vec()
    }
}

fn patch_section_header<Elf: ElfType>(
    shoff: usize,
    out: &mut [u8],
    index: SectionIndex,
    offset: usize,
    len: usize,
    data: &[u8],
) {
    patch(
        &mut Elf::section_header_mut(shoff, out, index)[offset..offset + len],
        data,
    );
}

fn patch_pod<P: Pod>(data: &mut [u8], new: &P) {
    patch(data, bytes_of(new));
}

fn patch(data: &mut [u8], new: &[u8]) {
    assert_eq!(data.len(), new.len(), "Patch length don't match");
    let len = min(data.len(), new.len());
    for i in 0..len {
        data[i] = new[i];
    }
}
