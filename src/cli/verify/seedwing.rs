use crate::verification::enforce::CertificateChainEnforcer;
use anyhow::bail;
use async_trait::async_trait;
use seedwing_policy_engine::lang::builder::Builder;
use seedwing_policy_engine::runtime::{BuildError, RuntimeError, World};
use seedwing_policy_engine::value::RuntimeValue;
use x509_parser::certificate::X509Certificate;

#[derive(Debug, thiserror::Error)]
pub enum SeedwingError {
    #[error("build error: {0:?}")]
    Build(Vec<BuildError>),
    #[error("runtime error: {0:?}")]
    Runtime(Vec<RuntimeError>),
}

impl From<Vec<BuildError>> for SeedwingError {
    fn from(value: Vec<BuildError>) -> Self {
        SeedwingError::Build(value)
    }
}

impl From<Vec<RuntimeError>> for SeedwingError {
    fn from(value: Vec<RuntimeError>) -> Self {
        SeedwingError::Runtime(value)
    }
}

pub struct SeedwingEnforcer {
    runtime: World,
}

impl SeedwingEnforcer {
    pub async fn new() -> Result<Self, SeedwingError> {
        let policy = seedwing_policy_engine::runtime::sources::Ephemeral::new(
            "<internal>:default.dog",
            include_str!("../../../policies/default.dog"),
        );

        let mut builder = Builder::new();

        builder.build(policy.iter())?;
        let runtime = builder.finish().await?;

        Ok(Self { runtime })
    }
}

#[async_trait(?Send)]
impl CertificateChainEnforcer for SeedwingEnforcer {
    async fn enforce_slice<'c>(&self, bundle: &'c [&'c X509Certificate<'c>]) -> anyhow::Result<()> {
        let result = self
            .runtime
            .evaluate("<internal>:default.dog::signed-binary", bundle)
            .await?;
        log::debug!("Result: {result:#?}");

        if !result.satisfied() {
            if log::log_enabled!(log::Level::Debug) {
                let value: RuntimeValue = bundle.into();
                log::debug!("Value: {value:#?}");
            }
            bail!("policy rejected");
        }

        Ok(())
    }
}
