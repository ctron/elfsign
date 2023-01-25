use crate::signature::DerSignatureEncoding;
use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use signature::Verifier;
use sigstore::rekor::models::LogEntry;
use time::OffsetDateTime;

/// Carry verified information from the log entry.
///
/// This structure contains some of the content which could be verified through the
/// signed entry timestamp (SET).
///
/// Verified means that the information was signed with the public key of the rekor instance. As
/// the timestamp is part of this, and we trust rekor to only sign a "correct" timestamp, the
/// log entry is believed to have been signed at this point in time.
#[derive(Clone, Debug)]
pub struct VerifiedInformation {
    pub timestamp: OffsetDateTime,
    /// The body of the SET
    pub body: Vec<u8>,
}

/// Data which flows into the signed entry timestamp (SET).
///
/// **NOTE:** The order and names of these fields are important, as the `to_canonicalized_string` builds
/// on this.
#[derive(serde::Deserialize, serde::Serialize)]
struct SignedTimeData<'d> {
    #[serde(rename = "body")]
    body: &'d str,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logID")]
    log_id: &'d str,
    #[serde(rename = "logIndex")]
    log_index: i64,
}

impl<'d> SignedTimeData<'d> {
    /// Generate a canonicalized JSON string (JCS)
    pub fn to_canonicalized_string(&self) -> Result<String, serde_json::Error> {
        // serde (without pretty print) and the order of the fields in the struct
        // ensure that we already get a canonicalized string, there is no additional work here
        serde_json::to_string(self)
    }
}

impl<'d> From<&'d LogEntry> for SignedTimeData<'d> {
    fn from(log: &'d LogEntry) -> Self {
        Self {
            log_id: &log.log_i_d,
            log_index: log.log_index as _,
            body: &log.body,
            integrated_time: log.integrated_time as _,
        }
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

/// Verify a rekor log entry.
///
/// This will:
///
/// * Verify that the combination of log Id, log index, body, and timestamp
///   (see [`SignedTimeData`]) have been signed by the public key of the rekor instance.
/// * Decode the body data from base64 (but not deserialize it)
///
/// This ensures:
///
/// * That the information from the log entry, returned by the function, can be trusted as
///   as information coming from the rekor instance (by the provided public key).
///
pub fn verify_entry<V, S>(
    log: &LogEntry,
    rekor_public_key: &V,
) -> anyhow::Result<VerifiedInformation>
where
    V: Verifier<S>,
    S: DerSignatureEncoding,
{
    // TODO: verify inclusion
    // TODO: verify checkpoint signature

    // verify SET

    let set = SignedTimeData::from(log);
    let c = set
        .to_canonicalized_string()
        .context("build signed time data structure")?;
    let signature = extract_signed_time(log)?;
    let signature = STANDARD.decode(&signature)?;
    let s = S::try_from_der(&signature)?;

    log::info!("Verify: '{}'", c);

    rekor_public_key
        .verify(c.as_bytes(), &s)
        .context("verify signed time")?;

    // now we know that the combination of logId, logIndex, body, and time was signed by rekor

    // decode the body from the SET
    let body = STANDARD.decode(set.body)?;
    if log::log_enabled!(log::Level::Debug) {
        log::debug!("Body: {}", String::from_utf8_lossy(&body));
    }

    Ok(VerifiedInformation {
        timestamp: OffsetDateTime::from_unix_timestamp(set.integrated_time)?,
        body,
    })
}
