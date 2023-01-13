use crate::utils::notes::NoteHeader;
use object::elf::{FileHeader32, FileHeader64};
use object::read::elf::FileHeader;
use object::Endian;

pub mod notes;

pub trait ElfType {
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
