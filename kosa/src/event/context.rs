use std::{
    fmt::{Debug, Formatter},
    sync::{OnceLock, Weak},
};

use ahash::AHashMap;
use anyhow::Context as _;
use tracing::trace;

use crate::{
    common::{AppInfo, Bot, Session},
    event::{Event, EventEntry, EventHandlerFn, dispatcher::Dispatcher},
    service::packet::sso_packet::SsoPacket,
};

pub struct EventContext {
    dispatcher: Dispatcher,
    bot: OnceLock<Weak<Bot>>,
    pub(crate) events: AHashMap<&'static str, EventHandlerFn>,
}

impl Debug for EventContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventContext")
            .field("bound", &self.bot.get().is_some())
            .finish_non_exhaustive()
    }
}

impl EventContext {
    pub(crate) fn new(dispatcher: Dispatcher) -> Self {
        let mut events = AHashMap::new();

        for entry in inventory::iter::<EventEntry> {
            let (cmd, decode_fn) = (entry.creator)();
            events.insert(cmd, decode_fn);
        }

        Self {
            dispatcher,
            bot: OnceLock::new(),
            events,
        }
    }

    pub(crate) fn bind_bot(&self, bot: Weak<Bot>) {
        let _ = self.bot.set(bot);
    }

    pub(crate) fn emit<E: Event>(&self, event: E) {
        let Some(bot) = self.bot.get().and_then(Weak::upgrade) else {
            trace!(event = E::NAME, "bot not bound, drop event");
            return;
        };
        self.dispatcher.emit(bot, event);
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
            Some(decode_fn) => decode_fn(&packet, self, app_info, session)
                .with_context(|| format!("push event decode error, cmd: {}", packet.command)),
        }
    }
}
