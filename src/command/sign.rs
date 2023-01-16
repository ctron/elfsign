use crate::signature::{elf, SignatureNoteType, SignerConfiguration};
use anyhow::bail;
use digest::Digest;
use sha2::{Sha256, Sha512};
use sigstore::crypto::CosignVerificationKey;
use sigstore::{
    crypto::{SigStoreSigner, SigningScheme},
    fulcio::{oauth::OauthTokenProvider, FulcioCert, FulcioClient, TokenProvider, FULCIO_ROOT},
};
use std::{ffi::OsString, marker::PhantomData};
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Configuration {
    EcdsaP256Sha256,
    Ed25519Sha512,
}

impl From<Configuration> for SignatureNoteType {
    fn from(value: Configuration) -> Self {
        match value {
            Configuration::EcdsaP256Sha256 => Self::SignatureEcdsa256Sha256,
            Configuration::Ed25519Sha512 => Self::SignatureEd2551Sha512,
        }
    }
}

impl From<Configuration> for SigningScheme {
    fn from(value: Configuration) -> Self {
        match value {
            Configuration::EcdsaP256Sha256 => SigningScheme::ECDSA_P256_SHA256_ASN1,
            Configuration::Ed25519Sha512 => SigningScheme::ED25519,
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

impl<D> SignerConfiguration for SigstoreConfiguration<D>
where
    D: Digest + Clone,
{
    type Digest = D;

    fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.sign(msg)?)
    }

    fn public_key(&self) -> anyhow::Result<Vec<u8>> {
        match self.0.to_verification_key()? {
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(public_key) => {
                Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
            }
            CosignVerificationKey::ED25519(public_key) => Ok(public_key.as_bytes().to_vec()),
            // FIXME: add additional variants
            key => {
                bail!("Unsupported configuration: {:?}", key);
            }
        }
    }

    fn r#type(&self) -> SignatureNoteType {
        self.2
    }
}

pub struct Options {
    pub input: OsString,
    pub output: OsString,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    // FIXME: allow to override
    let configuration = Configuration::Ed25519Sha512;

    let fulcio = FulcioClient::new(
        Url::parse(FULCIO_ROOT).unwrap(),
        TokenProvider::Oauth(OauthTokenProvider::default()),
    );

    match configuration {
        Configuration::EcdsaP256Sha256 => {
            let signer: SigstoreConfiguration<Sha256> = (
                fulcio.request_cert(configuration.into()).await?,
                configuration.into(),
            )
                .into();
            elf::elfcopy(options.input, options.output, signer)?
        }
        Configuration::Ed25519Sha512 => {
            let signer: SigstoreConfiguration<Sha512> = (
                fulcio.request_cert(configuration.into()).await?,
                configuration.into(),
            )
                .into();
            elf::elfcopy(options.input, options.output, signer)?
        }
    }

    Ok(())
}
