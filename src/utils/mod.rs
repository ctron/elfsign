use crate::utils::notes::NoteHeader;
use object::{
    bytes_of,
    elf::{FileHeader32, FileHeader64},
    read::elf::FileHeader,
    Endian, SectionIndex, U32, U64,
};

pub mod elf;
pub mod notes;
pub mod reader;
pub mod writer;

pub trait Header<E: Endian> {
    fn section_header_size() -> usize;
    fn section_header_mut(shoff: usize, data: &mut [u8], index: SectionIndex) -> &mut [u8] {
        let len = Self::section_header_size();
        let offset = shoff + (len * index.0);
        &mut data[offset..offset + len]
    }

    fn e_shoff_mut(data: &mut [u8]) -> &mut [u8];
    fn e_shnum_mut(data: &mut [u8]) -> &mut [u8];

    const SH_OFFSET: usize;
    const SH_SIZE: usize;

    const WORD: usize;

    fn word(endian: E, value: usize) -> Vec<u8>;
}

impl<E: Endian> Header<E> for FileHeader32<E> {
    fn section_header_size() -> usize {
        0x028
    }

    const SH_OFFSET: usize = 0x10;
    const SH_SIZE: usize = 0x14;

    const WORD: usize = 0x04;

    fn word(endian: E, value: usize) -> Vec<u8> {
        bytes_of(&U32::new(endian, value as u32)).to_vec()
    }

    fn e_shoff_mut(data: &mut [u8]) -> &mut [u8] {
        &mut data[0x20..0x20 + Self::WORD]
    }

    fn e_shnum_mut(data: &mut [u8]) -> &mut [u8] {
        &mut data[0x30..0x30 + 2]
    }
}

impl<E: Endian> Header<E> for FileHeader64<E> {
    fn section_header_size() -> usize {
        0x40
    }

    const SH_OFFSET: usize = 0x18;
    const SH_SIZE: usize = 0x20;

    const WORD: usize = 0x08;

    fn word(endian: E, value: usize) -> Vec<u8> {
        bytes_of(&U64::new(endian, value as u64)).to_vec()
    }

    fn e_shoff_mut(data: &mut [u8]) -> &mut [u8] {
        &mut data[0x28..0x28 + Self::WORD]
    }

    fn e_shnum_mut(data: &mut [u8]) -> &mut [u8] {
        &mut data[0x3C..0x3C + 2]
    }
}

pub trait ElfType: Header<Self::Endian> {
    type Endian: Endian;

    type File: FileHeader<Endian = Self::Endian>;
    type Note: NoteHeader<Endian = Self::Endian>;
}

impl<E: Endian> ElfType for FileHeader64<E> {
    type Endian = E;
    type File = FileHeader64<E>;
    type Note = FileHeader64<E>;
}

impl<E: Endian> ElfType for FileHeader32<E> {
    type Endian = E;
    type File = FileHeader32<E>;
    type Note = FileHeader32<E>;
}
