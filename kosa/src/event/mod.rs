use std::fmt::Debug;

pub use app::{App, Context};
pub(crate) use context::EventContext;
pub(crate) use dispatcher::Dispatcher;
pub use login::{SessionExpired, SessionUpdated};
pub use message::{GroupMessageEvent, PrivateMessageEvent};
pub use status::{BotOffline, BotOnline, OfflineReason};

use crate::{
    common::{AppInfo, Session},
    service::packet::sso_packet::SsoPacket,
    utils::marker::CommandMarker,
};

mod app;
mod context;
mod dispatcher;
mod empty;
mod login;
mod message;
mod push_message;
mod status;

pub trait Event: Clone + Send + Sync + 'static {
    const NAME: &'static str;
}

pub(crate) type EventHandlerFn =
    fn(&SsoPacket, &EventContext, &AppInfo, &Session) -> anyhow::Result<()>;

pub(crate) struct EventEntry {
    pub(crate) creator: fn() -> (&'static str, EventHandlerFn),
}

inventory::collect!(EventEntry);

pub(crate) trait PushEvent: Debug + Clone + Send + Sync + CommandMarker {
    fn handle(
        packet: &SsoPacket,
        ctx: &EventContext,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<()>;
}
