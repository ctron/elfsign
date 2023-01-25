use der::Sequence;
use sigstore::rekor::models::LogEntry;

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct RekorBundle {
    /// The ID of the log entry.
    ///
    /// NOTE: This is called "uuid" in the Rekor API. However, it is not a UUID:
    /// https://github.com/sigstore/rekor/blob/8d29f44633723a19deb0361b3cb72b0f8f6abbe4/pkg/sharding/sharding.go#L25-L36
    pub entry_id: String,
}

impl From<LogEntry> for RekorBundle {
    fn from(value: LogEntry) -> Self {
        Self {
            entry_id: value.uuid,
        }
    }
}
