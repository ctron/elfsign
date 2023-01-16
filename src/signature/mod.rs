use crate::utils::notes::{Note, NoteWriter};
use crate::utils::ElfType;
use ::digest::Digest;
use anyhow::bail;
use sha2::{Sha256, Sha512};
use sigstore::crypto::SigStoreSigner;
use std::borrow::Cow;
use std::marker::PhantomData;

pub mod digest;
pub mod elf;
pub mod sign;

/// The name of the elf sections containing the signature information
pub const SIGNATURE_V1_SECTION: &str = ".note.signature-v1";
pub const SIGNATURE_V1_SECTION_ALIGN: usize = 1;

/// The namespace of the signature's note section entries
pub const ELF_NOTE_SIGNATURE_V1_NAMESPACE: &str = "Signature";

/// The possible types of the signature entries.
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum SignatureNoteType {
    SignatureEcdsa256Sha256 = 1,
    SignatureEd2551Sha512 = 2,
}

impl TryFrom<u32> for SignatureNoteType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SignatureNoteType::SignatureEcdsa256Sha256),
            2 => Ok(SignatureNoteType::SignatureEd2551Sha512),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub r#type: SignatureNoteType,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Signature {
    fn encode(&self) -> Vec<u8> {
        let mut result = self.public_key.clone();
        result.extend(self.signature.clone());
        result
    }

    /// parse the note descriptor into a signature
    pub fn parse(r#type: SignatureNoteType, data: &[u8]) -> anyhow::Result<Self> {
        log::debug!("Parsing: {:?}", r#type);
        let (public_key, signature) = match r#type {
            SignatureNoteType::SignatureEcdsa256Sha256 => Self::split(data, 32, 32),
            SignatureNoteType::SignatureEd2551Sha512 => Self::split(data, 32, 64),
        }?;

        Ok(Signature {
            signature,
            public_key,
            r#type,
        })
    }

    /// Split the descriptor data into digest and signature
    fn split(
        data: &[u8],
        public_key_len: usize,
        signature_len: usize,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        if data.len() != public_key_len + signature_len {
            bail!(
                "Descriptor size mismatch - expected: {} + {} = {}, actual: {}",
                public_key_len,
                signature_len,
                public_key_len + signature_len,
                data.len()
            );
        }

        let (digest, signature) = data.split_at(public_key_len);
        Ok((digest.to_vec(), signature.to_vec()))
    }
}

#[derive(Clone, Debug)]
pub struct Signatures {
    pub signatures: Vec<Signature>,
}

impl Signatures {
    /// render the signature data section
    pub fn render_data<E: ElfType>(&self, endian: E::Endian) -> Vec<u8> {
        let mut result = Vec::new();
        let mut writer = NoteWriter::<_, E>::new(&mut result, endian);

        let mut notes = Vec::with_capacity(self.signatures.len());

        for signature in &self.signatures {
            notes.push(Note {
                namespace: ELF_NOTE_SIGNATURE_V1_NAMESPACE,
                descriptor: Cow::Owned(signature.encode()),
                r#type: signature.r#type as u32,
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
    type Digest: Digest + Clone;
    fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn public_key(&self) -> anyhow::Result<Vec<u8>>;
    fn r#type(&self) -> SignatureNoteType;
}
