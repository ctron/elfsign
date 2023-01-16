use crate::signature::SignerConfiguration;
use digest::Output;

pub fn sign<S: SignerConfiguration>(
    signer: &S,
    digest: Output<S::Digest>,
) -> anyhow::Result<crate::signature::Signature> {
    let digest = digest.to_vec();
    let signature = signer.sign(&digest)?;

    let public_key = signer.public_key()?;

    log::info!("Public Key: {}", base16::encode_lower(&public_key));
    log::info!("Digest: {}", base16::encode_lower(&digest));
    log::info!("Signature: {}", base16::encode_lower(&signature));

    Ok(crate::signature::Signature {
        r#type: signer.r#type(),
        public_key,
        signature,
    })
}
