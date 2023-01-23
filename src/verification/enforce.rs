use anyhow::bail;
use async_trait::async_trait;
use seedwing_policy_engine::value::{Object, RuntimeValue};
use std::ops::Deref;
use x509_parser::prelude::*;

#[derive(Debug)]
pub struct CertificateBundle<'c> {
    pub raw: Vec<&'c [u8]>,
    pub parsed: Vec<X509Certificate<'c>>,
}

impl<'c> Deref for CertificateBundle<'c> {
    type Target = [X509Certificate<'c>];

    fn deref(&self) -> &Self::Target {
        &self.parsed
    }
}

impl<'c> AsRef<[&'c [u8]]> for CertificateBundle<'c> {
    fn as_ref(&self) -> &[&'c [u8]] {
        &self.raw
    }
}

impl<'c> TryFrom<&'c [Vec<u8>]> for CertificateBundle<'c> {
    type Error = anyhow::Error;

    fn try_from(bundle: &'c [Vec<u8>]) -> Result<Self, Self::Error> {
        let mut raw = Vec::with_capacity(bundle.len());
        let mut parsed = Vec::with_capacity(bundle.len());

        for cert in bundle {
            let cert = cert.as_ref();
            raw.push(cert);
            parsed.push(parse_x509_certificate(cert)?.1);
        }

        Ok(Self { raw, parsed })
    }
}

impl<'c> From<&CertificateBundle<'c>> for RuntimeValue {
    fn from(value: &CertificateBundle<'c>) -> Self {
        let mut result = Object::new();

        result.set("raw", RuntimeValue::with_iter(value.raw.clone()));
        //result.set("raw", value.raw.as_slice());
        result.set("parsed", value.parsed.as_slice());

        result.into()
    }
}

/// Enforce a certificate chain/bundle
#[async_trait(?Send)]
pub trait CertificateChainEnforcer {
    async fn enforce<'c>(&self, bundle: &'c CertificateBundle<'c>) -> anyhow::Result<()>;
}

#[async_trait(?Send)]
impl CertificateChainEnforcer for &[&(dyn CertificateChainEnforcer)] {
    async fn enforce<'c>(&self, bundle: &'c CertificateBundle<'c>) -> anyhow::Result<()> {
        for enforcer in self.iter() {
            enforcer.enforce(bundle).await?;
        }
        Ok(())
    }
}

/// Enforce a single certificate
#[async_trait(?Send)]
pub trait CertificateEnforcer {
    async fn enforce_self<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()>;

    async fn enforce_leaf<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()>;
    async fn enforce_intermediate<'c>(
        &self,
        certificate: &'c X509Certificate<'c>,
    ) -> anyhow::Result<()>;
    async fn enforce_root<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()>;
}

/// Allow using a list of enforcers, and-ing them together.
#[async_trait(?Send)]
impl CertificateEnforcer for &[&(dyn CertificateEnforcer)] {
    async fn enforce_self<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()> {
        for enforcer in self.iter() {
            enforcer.enforce_self(certificate).await?;
        }
        Ok(())
    }

    async fn enforce_leaf<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()> {
        for enforcer in self.iter() {
            enforcer.enforce_leaf(certificate).await?;
        }
        Ok(())
    }

    async fn enforce_intermediate<'c>(
        &self,
        certificate: &'c X509Certificate<'c>,
    ) -> anyhow::Result<()> {
        for enforcer in self.iter() {
            enforcer.enforce_intermediate(certificate).await?;
        }
        Ok(())
    }

    async fn enforce_root<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()> {
        for enforcer in self.iter() {
            enforcer.enforce_root(certificate).await?;
        }
        Ok(())
    }
}

pub struct StandardEnforcer;

impl StandardEnforcer {
    fn enforce_common(&self, _certificate: &X509Certificate) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait(?Send)]
impl CertificateEnforcer for StandardEnforcer {
    async fn enforce_self<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()> {
        self.enforce_leaf(certificate).await?;
        self.enforce_root(certificate).await?;
        Ok(())
    }

    async fn enforce_leaf<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()> {
        self.enforce_common(certificate)?;

        if !certificate
            .key_usage()?
            .map(|ku| ku.value.digital_signature())
            .unwrap_or_default()
        {
            bail!("certificate is not intended for signing");
        }
        if !certificate
            .extended_key_usage()?
            .map(|eku| eku.value.code_signing)
            .unwrap_or_default()
        {
            bail!("certificate is not intended for code signing");
        }
        Ok(())
    }

    async fn enforce_intermediate<'c>(
        &self,
        certificate: &'c X509Certificate<'c>,
    ) -> anyhow::Result<()> {
        self.enforce_common(certificate)?;

        Ok(())
    }

    async fn enforce_root<'c>(&self, certificate: &'c X509Certificate<'c>) -> anyhow::Result<()> {
        self.enforce_common(certificate)?;

        if !certificate.is_ca() {
            bail!("root certificate is not a CA");
        }

        Ok(())
    }
}
