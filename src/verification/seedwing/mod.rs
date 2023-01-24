use crate::verification::enforce::{CertificateBundle, CertificateChainEnforcer};
use crate::verification::seedwing::explain::explain;
use anyhow::bail;
use async_trait::async_trait;
use seedwing_policy_engine::error_printer::ErrorPrinter;
use seedwing_policy_engine::lang::builder::Builder;
use seedwing_policy_engine::lang::parser::SourceLocation;
use seedwing_policy_engine::runtime::cache::SourceCache;
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
        let runtime = match Self::build().await {
            Ok(runtime) => runtime,
            Err(err) => {
                if log::log_enabled!(log::Level::Warn) {
                    let mut cache = SourceCache::new();
                    Self::sources().for_each(|(location, s)| cache.add(location, s.into()));
                    // FIXME: use reference once we moved back to HEAD
                    ErrorPrinter::new(&cache).display(err.clone());
                }
                return Err(SeedwingError::Build(err));
            }
        };
        Ok(Self { runtime })
    }

    fn sources() -> impl Iterator<Item = (SourceLocation, String)> {
        seedwing_policy_engine::runtime::sources::Ephemeral::new(
            "<internal>:default.dog",
            include_str!("../../../policies/default.dog"),
        )
        .iter()
    }

    async fn build() -> Result<World, Vec<BuildError>> {
        let mut builder = Builder::new();
        builder.build(Self::sources())?;
        builder.finish().await
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
