use crate::utils::notes::{Note, NoteWriter};
use crate::utils::ElfType;
use ::digest::Digest;
use sigstore::crypto::SigStoreSigner;
use std::borrow::Cow;
use std::marker::PhantomData;

pub mod digest;
pub mod sign;

/// The name of the elf sections containing the signature information
pub const SIGNATURE_V1_SECTION: &str = ".note.signature-v1";
pub const SIGNATURE_V1_SECTION_ALIGN: usize = 1;

/// The namespace of the signature's note section entries
pub const ELF_NOTE_SIGNATURE_V1_NAMESPACE: &str = "Signature";

/// The possible types of the signature entries.
pub enum SignatureNoteType {
    SignatureEd2551Sha512 = 1,
}

#[derive(Clone, Debug)]
pub struct Signature {
    // FIXME: right now we don't carry any information of the algorithms used
    pub digest: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Signature {
    fn encode(&self) -> Vec<u8> {
        let mut result = self.digest.clone();
        result.extend(self.signature.clone());
        result
    }
}

#[derive(Clone, Debug)]
pub struct Signatures {
    pub signatures: Vec<Signature>,
}

impl Signatures {
    // TODO: also need to parse the data

    /// render the signature data section
    pub fn render_data<E: ElfType>(&self, endian: E::Endian) -> Vec<u8> {
        let mut result = Vec::new();
        let mut writer = NoteWriter::<_, E>::new(&mut result, endian);

        let mut notes = Vec::with_capacity(self.signatures.len());

        for signature in &self.signatures {
            notes.push(Note {
                namespace: ELF_NOTE_SIGNATURE_V1_NAMESPACE,
                descriptor: Cow::Owned(signature.encode()),
                r#type: SignatureNoteType::SignatureEd2551Sha512 as u32,
            });
        }

        writer.write_notes(&notes);

        result
    }
}

#[deprecated]
pub trait Signer {
    fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
}

#[deprecated]
pub struct SignerWrapper<S, Si>(S, PhantomData<Si>)
where
    Si: signature::Signature,
    S: signature::Signer<Si>;

#[deprecated]
impl<S, Si> SignerWrapper<S, Si>
where
    Si: signature::Signature,
    S: signature::Signer<Si>,
{
    pub fn new(signer: S) -> Self {
        Self(signer, PhantomData::default())
    }
}

impl<S, Si> Signer for SignerWrapper<S, Si>
where
    Si: signature::Signature,
    S: signature::Signer<Si>,
{
    fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.try_sign(msg)?.as_bytes().to_vec())
    }
}

impl Signer for SigStoreSigner {
    fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.sign(msg)?)
    }
}

pub trait SignerConfiguration {
    type Digest: Digest;
    fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
}
