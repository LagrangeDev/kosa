use std::fmt::Debug;

pub(crate) use context::EventContext;
pub use login::{SessionExpired, SessionUpdated};
pub use message::{GroupMessageEvent, PrivateMessageEvent};
pub use network::{DisconnectEvent, ReconnectEvent};

use crate::{
    common::{AppInfo, Session},
    service::packet::sso_packet::SsoPacket,
    utils::marker::CommandMarker,
};

mod context;
mod empty;
mod login;
mod message;
mod network;
mod push_message;

use crate::utils::broker::Broker;

pub(crate) type EventHandlerFn = fn(&SsoPacket, &Broker, &AppInfo, &Session) -> anyhow::Result<()>;

pub(crate) struct EventEntry {
    pub(crate) creator: fn() -> (&'static str, EventHandlerFn),
}

inventory::collect!(EventEntry);

pub(crate) trait PushEvent: Debug + Clone + Send + Sync + CommandMarker {
    fn handle(
        packet: &SsoPacket,
        broker: &Broker,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<()>;
}
