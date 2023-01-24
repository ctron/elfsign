use der::Sequence;

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct RekorBundle {
    /// The ID of the log entry.
    ///
    /// NOTE: This is called "uuid" in the Rekor API. However, it is not a UUID.
    pub entry_id: String,
}
