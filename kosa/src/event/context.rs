use ahash::AHashMap;
use tracing::trace;

use crate::{
    common::{AppInfo, Session},
    event::{EventEntry, EventHandlerFn},
    service::packet::sso_packet::SsoPacket,
};

#[derive(Debug)]
pub(crate) struct EventContext {
    // todo 需要和service共享一个缓存，或者单独写一个cachecontext，需要主动获取值（事件也可能不用主动获取值？）
    pub(crate) events: AHashMap<&'static str, EventHandlerFn>,
}

impl EventContext {
    pub(crate) fn new() -> Self {
        let mut events = AHashMap::new();

        for entry in inventory::iter::<EventEntry> {
            let (cmd, decode_fn) = (entry.creator)();
            events.insert(cmd, decode_fn);
        }

        Self { events }
    }

    pub(crate) fn decode(
        &self,
        packet: SsoPacket,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<()> {
        match self.events.get(packet.command.as_str()) {
            None => {
                trace!("no event found for {}", packet.command);
                Ok(())
            }
            Some(decode_fn) => decode_fn(packet.data, app_info, session),
        }
    }
}
