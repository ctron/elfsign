use crate::elfcopy;
use crate::signature::SignerConfiguration;
use digest::Digest;
use sha2::Sha256;
use sigstore::crypto::{SigStoreSigner, SigningScheme};
use sigstore::fulcio::oauth::OauthTokenProvider;
use sigstore::fulcio::{FulcioCert, FulcioClient, TokenProvider, FULCIO_ROOT};
use std::ffi::OsString;
use std::marker::PhantomData;
use url::Url;

pub enum Configuration {
    EcdsaP256Sha256Asn1,
}

impl From<Configuration> for SigningScheme {
    fn from(value: Configuration) -> Self {
        match value {
            Configuration::EcdsaP256Sha256Asn1 => SigningScheme::ECDSA_P256_SHA256_ASN1,
        }
    }
}

pub struct SigstoreConfiguration<D: Digest>(SigStoreSigner, FulcioCert, PhantomData<D>);

impl<D: Digest> From<(SigStoreSigner, FulcioCert)> for SigstoreConfiguration<D> {
    fn from(value: (SigStoreSigner, FulcioCert)) -> Self {
        Self(value.0, value.1, Default::default())
    }
}

impl<D> SignerConfiguration for SigstoreConfiguration<D>
where
    D: Digest,
{
    type Digest = D;

    fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.sign(msg)?)
    }
}

pub struct Options {
    pub input: OsString,
    pub output: OsString,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    let configuration = Configuration::EcdsaP256Sha256Asn1;

    let fulcio = FulcioClient::new(
        Url::parse(FULCIO_ROOT).unwrap(),
        TokenProvider::Oauth(OauthTokenProvider::default()),
    );

    match configuration {
        Configuration::EcdsaP256Sha256Asn1 => {
            let signer: SigstoreConfiguration<Sha256> =
                fulcio.request_cert(configuration.into()).await?.into();
            elfcopy::elfcopy(options.input, options.output, signer)?
        }
    }

    Ok(())
}
