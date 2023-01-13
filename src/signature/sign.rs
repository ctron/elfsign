use crate::signature::SignerConfiguration;
use digest::Output;

pub fn sign<S: SignerConfiguration>(
    signer: &S,
    digest: Output<S::Digest>,
) -> anyhow::Result<crate::signature::Signature> {
    let digest = digest.to_vec();
    let signature = signer.sign(&digest)?;

    log::info!("Digest: {}", base16::encode_lower(&digest));
    log::info!("Signature: {}", base16::encode_lower(&signature));

    Ok(crate::signature::Signature { digest, signature })
}
