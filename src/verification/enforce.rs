use anyhow::bail;
use async_trait::async_trait;
use x509_parser::prelude::*;

/// Enforce a certificate chain/bundle
#[async_trait(?Send)]
pub trait CertificateChainEnforcer {
    async fn enforce_slice<'c>(&self, bundle: &'c [&'c X509Certificate<'c>]) -> anyhow::Result<()>;
}

#[async_trait(?Send)]
pub trait CertificateChainEnforcerEx: CertificateChainEnforcer {
    async fn enforce<'c, A>(&self, bundle: A) -> anyhow::Result<()>
    where
        A: AsRef<[X509Certificate<'c>]>,
    {
        self.enforce_slice(bundle.as_ref().into_iter().collect::<Vec<_>>().as_slice())
            .await
    }
}

impl<E: CertificateChainEnforcer> CertificateChainEnforcerEx for E {}

#[async_trait(?Send)]
impl CertificateChainEnforcer for &[&(dyn CertificateChainEnforcer)] {
    async fn enforce_slice<'c>(&self, bundle: &'c [&'c X509Certificate<'c>]) -> anyhow::Result<()> {
        for enforcer in self.iter() {
            enforcer.enforce_slice(bundle).await?;
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
