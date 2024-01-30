/// Protocol execution ID
///
/// Each protocol execution must have unique execution ID. All signers taking part in the protocol
/// (keygen/signing/etc.) must share the same execution ID, otherwise protocol will abort with
/// unverbose error.
#[derive(Clone, Copy)]
pub struct ExecutionId<'id> {
    id: &'id [u8],
}

impl<'id> ExecutionId<'id> {
    /// Constructs an execution ID from bytes
    pub fn new(eid: &'id [u8]) -> Self {
        Self { id: eid }
    }

    /// Returns bytes that represent an execution ID
    pub fn as_bytes(&self) -> &'id [u8] {
        self.id
    }
}
