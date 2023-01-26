use crate::data::{DigestAlgorithm, Signature};
use ::der::asn1::OctetString;
use ::digest::{Digest, Update};
use anyhow::anyhow;
use async_trait::async_trait;
use ecdsa::{
    der,
    elliptic_curve::{generic_array::ArrayLength, FieldSize},
    PrimeCurve, SignatureSize,
};
use sha2::{Sha256, Sha384};
use signature::{DigestSigner, SignatureEncoding};
use std::{fmt::Debug, marker::PhantomData, ops::Add};

pub mod digest;
mod publish;
mod sign;

use crate::data;
pub(crate) use sign::sign;

/// The name of the elf sections containing the signature information
pub const SIGNATURE_V1_SECTION: &str = ".note.signature-v1";

/// The namespace of the signature's note section entries
pub const ELF_NOTE_SIGNATURE_V1_NAMESPACE: &str = "Signature";

/// The possible types of the signature entries.
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum SignatureNoteType {
    Asn1Signature = 0,
}

impl From<SignatureNoteType> for u32 {
    fn from(value: SignatureNoteType) -> Self {
        value as u32
    }
}

impl TryFrom<u32> for SignatureNoteType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Asn1Signature),
            _ => Err(()),
        }
    }
}

pub type DigestFeeder<'f> = Box<dyn FnOnce(&mut dyn Update) -> anyhow::Result<()> + 'f>;

/// A configuration, ready to sign content.
#[async_trait(?Send)]
pub trait SignerConfiguration {
    async fn sign<'f>(&self, f: DigestFeeder<'f>) -> anyhow::Result<Signature>;
    fn digest_algorithm(&self) -> DigestAlgorithm;
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

pub trait DigestInformation {
    fn algorithm() -> DigestAlgorithm;
}

impl DigestInformation for Sha256 {
    fn algorithm() -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }
}

impl DigestInformation for Sha384 {
    fn algorithm() -> DigestAlgorithm {
        DigestAlgorithm::Sha384
    }
}

pub struct DigestSignerWrapper<D, S, DS, CBE>
where
    D: Digest + DigestInformation + Clone,
    DS: DigestSigner<D, S> + VerifyingKeyEncoding,
    CBE: CertificateBundleEncoding,
{
    signer: DS,
    r#type: data::Configuration,
    certificate_bundle: CBE,
    _marker: PhantomData<(D, S)>,
}

impl<D, S, DS, CBE> DigestSignerWrapper<D, S, DS, CBE>
where
    D: Digest + DigestInformation + Clone,
    DS: DigestSigner<D, S> + VerifyingKeyEncoding,
    CBE: CertificateBundleEncoding,
{
    pub fn new(signer: DS, r#type: data::Configuration, certificate_bundle: CBE) -> Self {
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
    D: Digest + DigestInformation + Update + Clone,
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

        // publish to rekor
        let leaf_certificate = certificate_bundle
            .first()
            .ok_or_else(|| anyhow!("certificate bundle was empty"))?;
        let rekor = publish::publish(
            self.digest_algorithm(),
            &publish_digest,
            leaf_certificate,
            &signature,
        )
        .await?;

        // signature entry
        let signature = Signature {
            r#type: self.r#type,
            signature: OctetString::new(signature)?,
            public_key: OctetString::new(public_key)?,
            certificate_bundle: certificate_bundle
                .into_iter()
                .map(OctetString::new)
                .collect::<Result<Vec<_>, _>>()?,
            rekor: Some(rekor),
        };

        // done
        Ok(signature)
    }

    fn digest_algorithm(&self) -> DigestAlgorithm {
        D::algorithm()
    }
}
