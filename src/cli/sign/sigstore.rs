use super::Configuration;
use crate::signature::{
    DebugCertificateBundle, DigestFeeder, DigestSignerWrapper, Signature, SignatureNoteType,
    SignerConfiguration, VerifyingKeyEncoding,
};
use anyhow::bail;
use async_trait::async_trait;
use digest::{const_oid::AssociatedOid, Digest};
use ecdsa::elliptic_curve::{
    generic_array::ArrayLength,
    ops::{Invert, Reduce},
    pkcs8::EncodePublicKey,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    subtle::CtOption,
    AffinePoint, FieldSize, PointCompression, ProjectiveArithmetic, Scalar,
};
use ecdsa::{hazmat::SignPrimitive, PrimeCurve, SignatureSize, SigningKey};
use p256::{pkcs8::DecodePrivateKey, NistP256};
use p384::NistP384;
use sha2::{Sha256, Sha384};
use sigstore::{
    crypto::{
        signing_key::{ecdsa::ECDSAKeys, KeyPair, SigStoreKeyPair},
        SigStoreSigner, SigningScheme,
    },
    fulcio::{oauth::OauthTokenProvider, FulcioCert, FulcioClient, TokenProvider, FULCIO_ROOT},
};
use std::marker::PhantomData;
use url::Url;

impl From<Configuration> for SigningScheme {
    fn from(value: Configuration) -> Self {
        match value {
            Configuration::EcdsaP256Sha256 => SigningScheme::ECDSA_P256_SHA256_ASN1,
            Configuration::EcdsaP384Sha384 => SigningScheme::ECDSA_P384_SHA384_ASN1,
        }
    }
}

pub struct SigstoreConfiguration<D: Digest>(
    SigStoreSigner,
    FulcioCert,
    SignatureNoteType,
    PhantomData<D>,
);

impl<D: Digest> From<((SigStoreSigner, FulcioCert), SignatureNoteType)>
    for SigstoreConfiguration<D>
{
    fn from(value: ((SigStoreSigner, FulcioCert), SignatureNoteType)) -> Self {
        Self(value.0 .0, value.0 .1, value.1, Default::default())
    }
}

impl<C> VerifyingKeyEncoding for SigningKey<C>
where
    C: PrimeCurve + AssociatedOid + ProjectiveArithmetic + PointCompression,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: sec1::ModulusSize,
{
    fn to_public_key_vec(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }

    fn to_public_key_der(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.verifying_key().to_public_key_der()?.to_vec())
    }
}

pub struct BoxedSignerConfiguration(Box<dyn SignerConfiguration>);

#[async_trait(?Send)]
impl SignerConfiguration for BoxedSignerConfiguration {
    async fn sign<'f>(&self, f: DigestFeeder<'f>) -> anyhow::Result<Signature> {
        self.0.sign(f).await
    }
}

pub async fn create_signer(
    configuration: Configuration,
) -> anyhow::Result<impl SignerConfiguration> {
    let fulcio = FulcioClient::new(
        Url::parse(FULCIO_ROOT)?,
        TokenProvider::Oauth(OauthTokenProvider::default()),
    );

    let (signer, cert) = fulcio.request_cert(configuration.into()).await?;

    // take the PEM certificate list and convert it into a DER serialize certificate bundle
    let bundle = x509_parser::pem::Pem::iter_from_buffer(cert.as_ref())
        .map(|r| r.map(|pem| pem.contents))
        .collect::<Result<Vec<_>, _>>()?;

    log::warn!("Cert Bundle: {:?}", DebugCertificateBundle(&bundle));
    if log::log_enabled!(log::Level::Info) {
        let size: usize = bundle.iter().map(|der| der.len()).sum();
        log::info!("Cert bundle size: {size}");
    }

    // Unfortunately we cannot just use the sigstore signer, as it only allows to sign "messages",
    // but we have a digest, not a message. So we need to extract the keys and set up the signer
    // ourselves.

    match signer.to_sigstore_keypair()? {
        SigStoreKeyPair::ECDSA(ECDSAKeys::P256(keys)) => {
            let keys = ecdsa::SigningKey::<NistP256>::from_pkcs8_der(&keys.private_key_to_der()?)?;
            Ok(BoxedSignerConfiguration(Box::new(DigestSignerWrapper::<
                Sha256,
                _,
                _,
                _,
            >::new(
                keys,
                SignatureNoteType::SignatureEcdsaP256Sha256,
                bundle,
            ))))
        }
        SigStoreKeyPair::ECDSA(ECDSAKeys::P384(keys)) => {
            let keys = ecdsa::SigningKey::<NistP384>::from_pkcs8_der(&keys.private_key_to_der()?)?;
            Ok(BoxedSignerConfiguration(Box::new(DigestSignerWrapper::<
                Sha384,
                _,
                _,
                _,
            >::new(
                keys,
                SignatureNoteType::SignatureEcdsaP384Sha384,
                bundle,
            ))))
        }
        keys => {
            bail!("Unsupported configuration: {}", keys.to_string());
        }
    }
}
