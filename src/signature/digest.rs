use crate::signature::SIGNATURE_V1_SECTION;
use digest::Update;
use object::read::elf::{ElfFile, FileHeader};
use object::{bytes_of, Object, ObjectSection, U64};

/// Create a digest of an elf file.
///
/// This must include all information which is relevant in executing the binary. But it must not
/// contain the signatures itself.
struct Digester<'d, 'data, F>
where
    F: FileHeader,
{
    file: &'data ElfFile<'data, F>,
    digest: &'d mut dyn Update,
}

impl<'d, 'data, F> Digester<'d, 'data, F>
where
    F: FileHeader,
{
    pub fn digest(&mut self) -> anyhow::Result<()> {
        // FIXME: most likely we might want to digest in a different way, by "element", recording the actual information of the process, to make it transparent what we did and what happened
        // FIXME: this function lacks all kind of information which should go into the digest

        log::debug!("Processing entrypoint");

        self.digest
            .update(bytes_of(&U64::new(self.file.endian(), self.file.entry())));

        /*
        if log::log_enabled!(Debug) {
            log::debug!(
                "Digested entrypoint - state: {}",
                base16::encode_lower(&self.digest.clone().finalize())
            );
        }*/

        // FIXME: need to figure out if we need the segments.
        // They do change due to the signature process. However, the segments are described
        // by the sections which we process below.
        /*
        log::debug!("Processing segments");

        for segment in self.file.segments() {
            let (start, len) = segment.file_range();
            let data = segment.data()?;
            self.digest.update(data);

            if log::log_enabled!(Debug) {
                log::debug!(
                    "Digested segment - start: {start}, len: {len}, check: {}, state: {}",
                    base16::encode_lower(&D::digest(data)),
                    base16::encode_lower(&self.digest.clone().finalize())
                );
            }
        }
         */

        log::debug!("Processing sections");

        for section in self.file.sections() {
            let name = section.name()?;
            if name == SIGNATURE_V1_SECTION {
                continue;
            }
            if name == ".shstrtab" {
                // FIXME: we need to find a way to deal with this
                // only digest the strings, but ignore the SIGNATURE_V1_SECTION string
                continue;
            }

            if let Some((_, _)) = section.file_range() {
                let data = section.data()?;
                self.digest.update(data);

                /*
                if log::log_enabled!(Debug) {
                    log::debug!(
                        "Digested section ({name}) - start: {start}, len: {len}, check: {}, state: {}",
                        base16::encode_lower(&D::digest(data)),
                        base16::encode_lower(&self.digest.clone().finalize())
                    );
                }*/
            }
        }

        Ok(())
    }
}

/// Digest a file.
pub fn digest<F>(digest: &mut dyn Update, file: &ElfFile<F>) -> anyhow::Result<()>
where
    F: FileHeader,
{
    Digester { file, digest }.digest()
}
