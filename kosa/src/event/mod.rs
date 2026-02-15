use std::fmt::Debug;

use bytes::Bytes;
pub(crate) use context::EventContext;
pub use login::SessionUpdated;
pub use message::GroupMessageEvent;

use crate::{
    common::{AppInfo, Session},
    utils::marker::CommandMarker,
};

mod context;
mod login;
mod message;
mod push_message;
use crate::utils::broker::Broker;
pub(crate) type EventHandlerFn = fn(Bytes, &Broker, &AppInfo, &Session) -> anyhow::Result<()>;

pub(crate) struct EventEntry {
    pub(crate) creator: fn() -> (&'static str, EventHandlerFn),
}

inventory::collect!(EventEntry);

pub(crate) trait PushEvent: Debug + Clone + Send + Sync + CommandMarker {
    fn handle(
        data: Bytes,
        broker: &Broker,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<()>;
}
