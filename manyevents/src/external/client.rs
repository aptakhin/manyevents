use crate::Uuid;
use serde_json::Value;

pub trait PushApi {
    fn push_event(
        &self,
        tenant_id: Uuid,
        entity: String,
        data: Value,
        token: String,
    ) -> Result<(), ()>;
}

pub struct InternalPushApi {}

impl PushApi for InternalPushApi {
    fn push_event(
        &self,
        tenant_id: Uuid,
        entity: String,
        data: Value,
        token: String,
    ) -> Result<(), ()> {
        Ok(())
    }
}
