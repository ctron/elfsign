use super::Configuration;
use crate::signature::{
    DigestSignerWrapper, Signature, SignatureNoteType, SignerConfiguration, VerifyingKeyEncoding,
};
use anyhow::bail;
use digest::{Digest, Update};
use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::elliptic_curve::ops::{Invert, Reduce};
use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use ecdsa::elliptic_curve::subtle::CtOption;
use ecdsa::elliptic_curve::{sec1, AffinePoint, FieldSize, ProjectiveArithmetic, Scalar};
use ecdsa::hazmat::SignPrimitive;
use ecdsa::{PrimeCurve, SignatureSize, SigningKey};
use p256::{pkcs8::DecodePrivateKey, NistP256};
use p384::NistP384;
use sha2::{Sha256, Sha384};
use sigstore::crypto::signing_key::{ecdsa::ECDSAKeys, KeyPair, SigStoreKeyPair};
use sigstore::{
    crypto::{SigStoreSigner, SigningScheme},
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
    C: PrimeCurve + ProjectiveArithmetic,
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
}

pub struct BoxedSignerConfiguration(Box<dyn SignerConfiguration>);

impl SignerConfiguration for BoxedSignerConfiguration {
    fn sign<'f>(
        &self,
        f: Box<dyn FnOnce(&mut dyn Update) -> anyhow::Result<()> + 'f>,
    ) -> anyhow::Result<Signature> {
        self.0.sign(f)
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

    log::warn!("FulcioCert:\n {cert}");

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
            >::new(
                keys,
                SignatureNoteType::SignatureEcdsa256Sha256,
            ))))
        }
        SigStoreKeyPair::ECDSA(ECDSAKeys::P384(keys)) => {
            let keys = ecdsa::SigningKey::<NistP384>::from_pkcs8_der(&keys.private_key_to_der()?)?;
            Ok(BoxedSignerConfiguration(Box::new(DigestSignerWrapper::<
                Sha384,
                _,
                _,
            >::new(
                keys,
                SignatureNoteType::SignatureEcdsaP384Sha384,
            ))))
        }
        keys => {
            bail!("Unsupported configuration: {}", keys.to_string());
        }
    }
}
