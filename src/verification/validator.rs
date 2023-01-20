use crate::verification::enforce::{
    CertificateBundle, CertificateChainEnforcer, CertificateEnforcer,
};
use anyhow::bail;
use async_trait::async_trait;

/// Enforce a certificate chain
///
/// ## Requirements
///
/// * One or more certificates
/// * Listed in the order: leaf-first, root-last
/// * Might be "self signed" if only one
/// * Ensure that each subject was signed by the following issuer
///
/// ## Excludes
///
/// Among other things, it does not:
///
/// * Check the validation period

pub struct EnforceCertificateChain<'e, E>(pub &'e E)
where
    E: CertificateEnforcer;

#[async_trait(?Send)]
impl<'e, E> CertificateChainEnforcer for EnforceCertificateChain<'e, E>
where
    E: CertificateEnforcer,
{
    async fn enforce<'c>(&self, bundle: &'c CertificateBundle<'c>) -> anyhow::Result<()> {
        if bundle.is_empty() {
            bail!("empty certificate bundle");
        }

        let mut i = bundle.iter();

        let mut next = i.next();
        let mut issuer = i.next();
        let mut idx = 0;
        while let Some(subject) = next {
            if let Err(err) =
                subject.verify_signature(issuer.as_ref().map(|issuer| &issuer.subject_pki))
            {
                bail!("failed to verify signature chain: {err}");
            }

            if idx == 0 {
                if issuer.is_none() {
                    // enforce as self-signed
                    self.0.enforce_self(subject).await?;
                } else {
                    // enforce as leaf
                    self.0.enforce_leaf(subject).await?;
                }
            } else {
                #[allow(clippy::collapsible_else_if)]
                if issuer.is_none() {
                    // enforce as root, might also be a leaf
                    self.0.enforce_root(subject).await?;
                } else {
                    self.0.enforce_intermediate(subject).await?;
                }
            }

            idx += 1;

            // keep going
            next = issuer;
            issuer = i.next();
        }

        Ok(())
    }
}
