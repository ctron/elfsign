use crate::utils::{
    notes::{Note, NoteWriter},
    ElfType,
};
use ::digest::{Digest, Update};
use anyhow::{bail, Context};
use async_trait::async_trait;
use base64::{display::Base64Display, engine::general_purpose::STANDARD, Engine};
use ecdsa::{
    der,
    elliptic_curve::{generic_array::ArrayLength, FieldSize},
    PrimeCurve, SignatureSize,
};
use object::Endian;
use signature::{DigestSigner, SignatureEncoding};
use sigstore::rekor::{
    self,
    apis::configuration::Configuration,
    models::{
        hashedrekord,
        hashedrekord::{AlgorithmKind, Data, Hash, PublicKey, Spec},
        ProposedEntry,
    },
};
use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter},
    io::Cursor,
    marker::PhantomData,
    ops::Add,
};

pub mod digest;
mod sign;

use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
pub(crate) use sign::sign;

/// The name of the elf sections containing the signature information
pub const SIGNATURE_V1_SECTION: &str = ".note.signature-v1";

/// The namespace of the signature's note section entries
pub const ELF_NOTE_SIGNATURE_V1_NAMESPACE: &str = "Signature";

/// The possible types of the signature entries.
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum SignatureNoteType {
    SignatureEcdsaP256Sha256 = 1,
    SignatureEcdsaP384Sha384 = 2,
}

impl TryFrom<u32> for SignatureNoteType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SignatureEcdsaP256Sha256),
            2 => Ok(Self::SignatureEcdsaP384Sha384),
            _ => Err(()),
        }
    }
}

/// A signature, stored as a note section entry
///
/// ## Encoding
///
/// Consider the following encoding, using the elf file endian-ness.
///
/// ```
/// struct Signature {
///   public_key_len: u32,
///   signature_len: u32,
///   number_of_certificates: u32,
///   certificate_lens: [u32; number_of_certificates],
///   certificates: [[u8; certificate_lens[i]]; number_of_certificates],
/// }
/// ```
///
#[derive(Clone)]
pub struct Signature {
    // FIXME: using the note type here is a bit wacky, as it actually is the type of the note entry
    pub r#type: SignatureNoteType,
    /// DER/ASN.1 encoded public key
    pub public_key: Vec<u8>,
    /// DER/ASN.1 encoded signature
    pub signature: Vec<u8>,

    /// DER encoded certificate bundle, root last.
    // FIXME: this contains duplicate information, like the algorithms, or the public key. Is that a problem?
    pub certificate_bundle: Vec<Vec<u8>>,
}

pub struct DebugCertificateBundle<'d>(pub &'d Vec<Vec<u8>>);

impl<'d> Debug for DebugCertificateBundle<'d> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_list();
        for c in self.0 {
            d.entry(&DebugCertificate(c));
        }
        d.finish()
    }
}

pub struct DebugCertificate<'d>(pub &'d Vec<u8>);

impl<'d> Debug for DebugCertificate<'d> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Base64Display::new(self.0, &base64::engine::general_purpose::STANDARD).fmt(f)
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("type", &self.r#type)
            .field("public_key", &base16::encode_lower(&self.public_key))
            .field("signature", &base16::encode_lower(&self.signature))
            .field(
                "certificate_bundle",
                &DebugCertificateBundle(&self.certificate_bundle),
            )
            .finish()
    }
}

impl Signature {
    fn encode<E: Endian>(&self, e: E) -> Vec<u8> {
        let mut result = Vec::with_capacity(4096);

        // write fixed header

        result.write_encoded(e, self.public_key.len() as u32);
        result.write_encoded(e, self.signature.len() as u32);
        result.write_encoded(e, self.certificate_bundle.len() as u32);

        // write lengths of certificates

        for cert in &self.certificate_bundle {
            result.write_encoded(e, cert.len() as u32);
        }

        // write public key

        result.write_bytes(&self.public_key);

        // write signature

        result.write_bytes(&self.signature);

        // write certificates

        for cert in &self.certificate_bundle {
            result.extend(cert);
        }

        // done

        result
    }

    /// parse the note descriptor into a signature
    pub fn parse<E: Endian>(
        endian: E,
        r#type: SignatureNoteType,
        data: &[u8],
    ) -> anyhow::Result<Self> {
        log::debug!("Parsing: {:?}", r#type);

        let mut c = Cursor::new(data);
        let public_key_len = c
            .read_map(|b| endian.read_u32_bytes(b))
            .context("read public key length")?;
        let signature_len = c
            .read_map(|b| endian.read_u32_bytes(b))
            .context("read signature length")?;
        let number_of_certificates = c
            .read_map(|b| endian.read_u32_bytes(b))
            .context("read number of certificates")?;

        let mut certificate_lengths = Vec::with_capacity(number_of_certificates as usize);
        for i in 0..number_of_certificates {
            certificate_lengths.push(
                c.read_map(|b| endian.read_u32_bytes(b))
                    .context(format!("read certificate length {i}"))?,
            );
        }

        let public_key = c
            .read_vec(public_key_len as usize)
            .context("read public key")?;
        let signature = c
            .read_vec(signature_len as usize)
            .context("read signature")?;

        let mut certificate_bundle = Vec::with_capacity(number_of_certificates as usize);
        for (i, l) in certificate_lengths.into_iter().enumerate() {
            certificate_bundle.push(
                c.read_vec(l as usize)
                    .context(format!("read certificate {i}"))?,
            );
        }

        // FIXME: ensure size

        Ok(Signature {
            r#type,
            public_key,
            signature,
            certificate_bundle,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Signatures {
    pub signatures: Vec<Signature>,
}

impl Signatures {
    /// render the signature data section as a notes section.
    pub fn render_as_notes<E: ElfType>(&self, endian: E::Endian) -> Vec<u8> {
        let mut result = Vec::new();
        let mut writer = NoteWriter::<_, E>::new(&mut result, endian);

        let mut notes = Vec::with_capacity(self.signatures.len());

        for signature in &self.signatures {
            notes.push(Note {
                namespace: ELF_NOTE_SIGNATURE_V1_NAMESPACE,
                descriptor: Cow::Owned(signature.encode(endian)),
                r#type: signature.r#type as u32,
            });
        }

        writer.write_notes(&notes);

        result
    }
}

pub type DigestFeeder<'f> = Box<dyn FnOnce(&mut dyn Update) -> anyhow::Result<()> + 'f>;

/// A configuration, ready to sign content.
#[async_trait(?Send)]
pub trait SignerConfiguration {
    async fn sign<'f>(&self, f: DigestFeeder<'f>) -> anyhow::Result<Signature>;
}

pub trait VerifyingKeyEncoding {
    fn to_public_key_vec(&self) -> anyhow::Result<Vec<u8>>;
    fn to_public_key_der(&self) -> anyhow::Result<Vec<u8>>;
}

/// A trait for encoding signatures in DER/ASN.1 format
pub trait DerSignatureEncoding: Sized {
    fn to_der(&self) -> Vec<u8>;
    fn try_from_der(data: &[u8]) -> anyhow::Result<Self>;
}

impl<C> DerSignatureEncoding for ecdsa::Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
    der::MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    fn to_der(&self) -> Vec<u8> {
        ecdsa::Signature::to_der(self).to_vec()
    }

    fn try_from_der(data: &[u8]) -> anyhow::Result<Self> {
        Ok(ecdsa::Signature::from_der(data)?)
    }
}

pub trait CertificateBundleEncoding {
    /// provide a bundle of DER encoded certificates, ordered by chain, root last
    fn to_certificate_bundle(&self) -> anyhow::Result<Vec<Vec<u8>>>;
}

impl CertificateBundleEncoding for Vec<Vec<u8>> {
    fn to_certificate_bundle(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self.clone())
    }
}

pub struct DigestSignerWrapper<D, S, DS, CBE>
where
    D: Digest + Clone,
    DS: DigestSigner<D, S> + VerifyingKeyEncoding,
    CBE: CertificateBundleEncoding,
{
    signer: DS,
    r#type: SignatureNoteType,
    certificate_bundle: CBE,
    _marker: PhantomData<(D, S)>,
}

impl<D, S, DS, CBE> DigestSignerWrapper<D, S, DS, CBE>
where
    D: Digest + Clone,
    DS: DigestSigner<D, S> + VerifyingKeyEncoding,
    CBE: CertificateBundleEncoding,
{
    pub fn new(signer: DS, r#type: SignatureNoteType, certificate_bundle: CBE) -> Self {
        Self {
            signer,
            r#type,
            certificate_bundle,
            _marker: Default::default(),
        }
    }
}

#[async_trait(?Send)]
impl<D, S, DS, CBE> SignerConfiguration for DigestSignerWrapper<D, S, DS, CBE>
where
    D: Digest + Update + Clone,
    DS: DigestSigner<D, S> + VerifyingKeyEncoding,
    S: DerSignatureEncoding,
    CBE: CertificateBundleEncoding,
{
    async fn sign<'f>(&self, f: DigestFeeder<'f>) -> anyhow::Result<Signature> {
        // digest file
        let mut digest = D::new();
        f(&mut digest)?;

        let publish_digest = digest.clone().finalize().to_vec();

        // sign
        let signature = self.signer.try_sign_digest(digest)?.to_der();
        let public_key = self.signer.to_public_key_der()?;
        let certificate_bundle = self.certificate_bundle.to_certificate_bundle()?;

        // signature entry
        let signature = Signature {
            r#type: self.r#type,
            signature,
            public_key,
            certificate_bundle,
        };

        // publish to rekor
        publish(&publish_digest, &signature).await?;

        // done
        Ok(signature)
    }
}

/// publish the digest
async fn publish(digest: &[u8], signature: &Signature) -> anyhow::Result<()> {
    let cfg = Configuration::default();

    let cert = match signature.certificate_bundle.first() {
        Some(cert) => cert,
        None => {
            bail!("No certificate provided");
        }
    };

    let tag = "CERTIFICATE";

    // yes, the certificate goes in to the "public key" field
    let public_key = format!(
        r#"-----BEGIN {tag}-----
{}
-----END {tag}-----
"#,
        STANDARD
            .encode(cert)
            .as_bytes()
            .chunks(64)
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join("\n")
    );
    // and yes, it is double-base64 encoded
    let public_key = STANDARD.encode(&public_key);

    let entry = ProposedEntry::Hashedrekord {
        api_version: "0.0.1".to_string(),
        spec: Spec {
            signature: hashedrekord::Signature {
                content: STANDARD.encode(&signature.signature),
                public_key: PublicKey::new(public_key),
            },
            data: Data {
                hash: Hash::new(AlgorithmKind::sha256, base16::encode_lower(digest)),
            },
        },
    };

    log::info!("Request: {}", serde_json::to_string_pretty(&entry)?);

    let log = match rekor::apis::entries_api::create_log_entry(&cfg, entry).await {
        Ok(log) => log,
        Err(err) => {
            match &err {
                rekor::apis::Error::ResponseError(response) => {
                    log::warn!("Status: {}", response.status);
                    log::warn!("Response: {}", response.content);
                }
                _ => {}
            }
            bail!(err);
        }
    };
    log::info!("Rekor log entry: {log:#?}");

    Ok(())
}
