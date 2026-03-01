use std::sync::Arc;

use actix::Message;

use crate::common::Session;

/// session更新
#[derive(Debug, Clone, Message)]
#[rtype(result = "()")]
pub struct SessionUpdated {
    pub session: Arc<Session>,
}
