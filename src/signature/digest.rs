use crate::signature::SIGNATURE_V1_SECTION;
use digest::{Digest, Output};
use object::read::elf::{ElfFile, FileHeader};
use object::{bytes_of, Object, ObjectSection, ObjectSegment, U64};

/// Create a digest of an elf file.
///
/// This must include all information which is relevant in executing the binary. But it must not
/// contain the signatures itself.
struct Digester<'data, D: Digest, F: FileHeader> {
    file: ElfFile<'data, F>,
    digest: D,
}

impl<'data, D: Digest, F: FileHeader> Digester<'data, D, F> {
    pub fn digest(mut self) -> anyhow::Result<Output<D>> {
        // FIXME: most likely we might want to digest in a different way, by "element", recording the actual information of the process, to make it transparent what we did and what happened
        // FIXME: this function lacks all kind of information which should go into the digest

        log::debug!("Processing entrypoint");

        Self::update(
            &mut self.digest,
            bytes_of(&U64::new(self.file.endian(), self.file.entry())),
        );

        log::debug!("Processing segments");

        for segment in self.file.segments() {
            let (start, len) = segment.file_range();
            Self::update(
                &mut self.digest,
                &self.file.data()[start as usize..(start + len) as usize],
            );
        }

        log::debug!("Processing sections");

        for section in self.file.sections() {
            if section.name()? == SIGNATURE_V1_SECTION {
                continue;
            }

            if let Some((start, len)) = section.file_range() {
                Self::update(
                    &mut self.digest,
                    &self.file.data()[start as usize..(start + len) as usize],
                );
            }
        }

        Ok(self.digest.finalize())
    }

    fn update(digest: &mut D, data: impl AsRef<[u8]>) {
        let data = data.as_ref();
        log::debug!("Digesting - len: {}", data.len());
        digest.update(data);
    }
}

/// Digest a file.
pub fn digest<D: Digest, F: FileHeader>(file: ElfFile<F>) -> anyhow::Result<Output<D>> {
    Digester {
        file,
        digest: D::new(),
    }
    .digest()
}
