use crate::utils::ElfType;
use object::elf::{FileHeader32, FileHeader64, NoteHeader32, NoteHeader64};
use object::write::WritableBuffer;
use object::{bytes_of_slice, Endian, Pod, U32};
use std::borrow::Cow;

pub struct Note<'n> {
    pub namespace: &'n str,
    pub descriptor: Cow<'n, [u8]>,
    pub r#type: u32,
}

pub trait NoteHeader {
    type Item: Pod;
    type Endian: Endian;

    fn vec_with_capacity(num: usize) -> Vec<Self::Item> {
        Vec::with_capacity(num)
    }

    fn add(
        headers: &mut Vec<Self::Item>,
        endian: Self::Endian,
        namesz: u32,
        descsz: u32,
        r#type: u32,
    );
}

impl<E: Endian> NoteHeader for FileHeader32<E> {
    type Item = NoteHeader32<E>;
    type Endian = E;

    fn vec_with_capacity(num: usize) -> Vec<Self::Item> {
        Vec::with_capacity(num)
    }

    fn add(
        headers: &mut Vec<Self::Item>,
        endian: Self::Endian,
        namesz: u32,
        descsz: u32,
        r#type: u32,
    ) {
        headers.push(Self::Item {
            n_namesz: U32::new(endian, namesz),
            n_descsz: U32::new(endian, descsz),
            n_type: U32::new(endian, r#type),
        });
    }
}

impl<E: Endian> NoteHeader for FileHeader64<E> {
    type Item = NoteHeader64<E>;
    type Endian = E;

    fn vec_with_capacity(num: usize) -> Vec<Self::Item> {
        Vec::with_capacity(num)
    }

    fn add(
        headers: &mut Vec<Self::Item>,
        endian: Self::Endian,
        namesz: u32,
        descsz: u32,
        r#type: u32,
    ) {
        headers.push(Self::Item {
            n_namesz: U32::new(endian, namesz),
            n_descsz: U32::new(endian, descsz),
            n_type: U32::new(endian, r#type),
        });
    }
}

pub struct NoteWriter<'w, W: WritableBuffer, E: ElfType> {
    writer: &'w mut W,
    endian: E::Endian,
}

impl<'w, W: WritableBuffer, E: ElfType> NoteWriter<'w, W, E> {
    pub fn new(writer: &'w mut W, endian: E::Endian) -> Self {
        Self { writer, endian }
    }

    fn align_4(offset: usize) -> usize {
        const SIZE: usize = 4;
        (offset + (SIZE - 1)) & !(SIZE - 1)
    }

    /// Write a slice of notes.
    pub fn write_notes(&mut self, notes: &[Note]) {
        // headers first

        let num = notes.len();
        let mut headers = E::Note::vec_with_capacity(num);

        let mut payload_size = 0;
        for note in notes {
            let namespace_len = note.namespace.len() + 1; // plus null byte
            let descriptor_len = note.descriptor.len();

            payload_size += Self::align_4(namespace_len);
            payload_size += Self::align_4(descriptor_len);

            E::Note::add(
                &mut headers,
                self.endian,
                namespace_len as u32,
                descriptor_len as u32,
                note.r#type as u32,
            );
        }

        // reserve the space and write header data

        let header_data = bytes_of_slice(headers.as_slice());
        self.writer
            .reserve(header_data.len() + payload_size)
            // right now, none of the implementations do return an error
            .expect("Should never happen");

        self.writer.write_bytes(header_data);

        // payload next

        for note in notes {
            self.write_padded(note.namespace.as_bytes(), true);
            self.write_padded(&note.descriptor, false);
        }
    }

    fn write_padded(&mut self, data: &[u8], add_null: bool) {
        self.writer.write_bytes(data);

        let mut len = data.len();
        if add_null {
            self.writer.write_bytes(&[0; 1]);
            len += 1;
        }

        let padding = Self::align_4(len) - len;
        self.writer.write_bytes(&vec![0u8; padding]);
    }
}
