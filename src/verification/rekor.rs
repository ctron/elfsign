use crate::signature::DerSignatureEncoding;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use signature::Verifier;
use sigstore::rekor::models::LogEntry;

pub struct VerifiedInformation {}

/// Data which flows into the signed entry timestamp (SET).
///
/// NOTE: The order and names of these fields are important, as the `to_canonicalized_string` builds
/// on this.
#[derive(serde::Deserialize, serde::Serialize)]
struct SignedTimeData<'d> {
    #[serde(rename = "body")]
    body: &'d str,
    #[serde(rename = "integratedTime")]
    integrated_time: u64,
    #[serde(rename = "logID")]
    log_id: &'d str,
    #[serde(rename = "logIndex")]
    log_index: u64,
}

impl<'d> SignedTimeData<'d> {
    /// Generate a canonicalized JSON string (JCS)
    pub fn to_canonicalized_string(&self) -> Result<String, serde_json::Error> {
        // serde (without pretty print) and the order of the fields in the struct
        // ensure that we already get a canonicalized string, there is no additional work here
        serde_json::to_string(self)
    }

    pub fn canonicalize(log: &LogEntry) -> Result<String, serde_json::Error> {
        SignedTimeData {
            log_id: &log.log_i_d,
            log_index: log.log_index as _,
            body: &log.body,
            integrated_time: log.integrated_time as _,
        }
        .to_canonicalized_string()
    }
}

/// extract the signed time
///
/// This is necessary as the current rekor API doesn't make the fields public.
fn extract_signed_time(log: &LogEntry) -> anyhow::Result<String> {
    let json = serde_json::to_value(&log.verification)?;

    Ok(json
        .get("signedEntryTimestamp")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("missing field 'signedEntryTimestamp'"))?)
}

pub fn verify_entry<V, S>(log: &LogEntry, rekor_public_key: &V) -> anyhow::Result<()>
where
    V: Verifier<S>,
    S: DerSignatureEncoding,
{
    let c = SignedTimeData::canonicalize(&log).context("build signed time data structure")?;
    let signature = extract_signed_time(log)?;
    let signature = STANDARD.decode(&signature)?;
    let s = S::try_from_der(&signature)?;

    log::info!("Verify: '{}'", c);

    rekor_public_key
        .verify(c.as_bytes(), &s)
        .context("verify signed time")?;

    // now we know that the combination of logId, logIndex, body, and time was signed by rekor

    let body = log.decode_body()?;
    log::info!("Body: {body:?}");

    // TODO: verify rekor certificate

    todo!("Implement");
}
