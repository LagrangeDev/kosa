use std::sync::Arc;

use crate::{common::Session, event::Event};

/// session更新
#[derive(Debug, Clone)]
pub struct SessionUpdated {
    pub session: Arc<Session>,
}

impl Event for SessionUpdated {
    const NAME: &'static str = "session_updated";
}

/// session 过期
#[derive(Debug, Clone)]
pub struct SessionExpired {
    pub msg: String,
}

impl Event for SessionExpired {
    const NAME: &'static str = "session_expired";
}
