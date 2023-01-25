use crate::data::RekorBundle;
use anyhow::bail;
use base64::{engine::general_purpose::STANDARD, Engine};
use sigstore::rekor::{
    self,
    apis::configuration::Configuration,
    models::{
        hashedrekord::{self, AlgorithmKind, Data, Hash, PublicKey, Spec},
        ProposedEntry,
    },
};

/// publish the digest
pub async fn publish(
    digest: &[u8],
    certificate: &[u8],
    signature: &[u8],
) -> anyhow::Result<RekorBundle> {
    let cfg = Configuration::default();

    const TAG: &str = "CERTIFICATE";
    const VERSION: &str = "0.0.1";

    // yes, the certificate goes in to the "public key" field
    let public_key = format!(
        r#"-----BEGIN {TAG}-----
{}
-----END {TAG}-----
"#,
        STANDARD
            .encode(certificate)
            .as_bytes()
            .chunks(64)
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join("\n")
    );
    // and yes, it is double-base64 encoded
    let public_key = STANDARD.encode(&public_key);

    let entry = ProposedEntry::Hashedrekord {
        api_version: VERSION.to_string(),
        spec: Spec {
            signature: hashedrekord::Signature {
                content: STANDARD.encode(signature),
                public_key: PublicKey::new(public_key),
            },
            data: Data {
                hash: Hash::new(AlgorithmKind::sha256, base16::encode_lower(digest)),
            },
        },
    };

    log::info!("Request: {}", serde_json::to_string_pretty(&entry)?);

    let log = match rekor::apis::entries_api::create_log_entry(&cfg, entry).await {
        Ok(log) => log,
        Err(err) => {
            match &err {
                rekor::apis::Error::ResponseError(response) => {
                    log::warn!("Status: {}", response.status);
                    log::warn!("Response: {}", response.content);
                }
                _ => {}
            }
            bail!(err);
        }
    };
    log::info!("Rekor log entry: {log:#?}");

    Ok(log.into())
}
