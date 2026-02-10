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

pub(crate) type EventHandlerFn = fn(Bytes, &AppInfo, &Session) -> anyhow::Result<()>;

pub(crate) struct EventEntry {
    pub(crate) creator: fn() -> (&'static str, EventHandlerFn),
}

inventory::collect!(EventEntry);

pub(crate) trait PushEvent: Debug + Clone + Send + Sync + CommandMarker {
    fn handle(data: Bytes, app_info: &AppInfo, session: &Session) -> anyhow::Result<()>;
}
