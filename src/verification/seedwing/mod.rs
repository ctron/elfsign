use crate::verification::enforce::{CertificateBundle, CertificateChainEnforcer};
use crate::verification::seedwing::explain::explain;
use anyhow::bail;
use async_trait::async_trait;
use seedwing_policy_engine::lang::builder::Builder;
use seedwing_policy_engine::runtime::{BuildError, RuntimeError, World};
use seedwing_policy_engine::value::{Object, RuntimeValue};

mod explain;

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
    async fn enforce<'c>(&self, bundle: &'c CertificateBundle<'c>) -> anyhow::Result<()> {
        let input = SignedBinary { bundle };

        let result = self
            .runtime
            .evaluate("<internal>:default.dog::signed-binary", &input)
            .await?;

        log::trace!("trace: {:#?}", result.rationale());
        if !result.satisfied() {
            if log::log_enabled!(log::Level::Info) {
                explain(&result)?;
            }
            bail!("policy rejected");
        }

        Ok(())
    }
}

/// The structure we pass on to seedwing
#[derive(Debug)]
pub struct SignedBinary<'c> {
    bundle: &'c CertificateBundle<'c>,
}

impl<'a> From<&SignedBinary<'a>> for RuntimeValue {
    fn from(value: &SignedBinary) -> Self {
        let mut result = Object::new();

        result.set("certificate-bundle", value.bundle);

        result.into()
    }
}
