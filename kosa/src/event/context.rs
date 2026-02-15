use actix::{Actor, AsyncContext, Handler, Message, dev::ToEnvelope};
use ahash::AHashMap;
use tracing::trace;

use crate::{
    common::{AppInfo, Session},
    event::{EventEntry, EventHandlerFn},
    service::packet::sso_packet::SsoPacket,
    utils::broker::Broker,
};

#[derive(Debug)]
pub struct EventContext {
    broker: Broker,
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

        Self {
            broker: Broker::new(),
            events,
        }
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
            Some(decode_fn) => decode_fn(packet.data, &self.broker, app_info, session),
        }
    }

    pub fn subscribe_async<A, M>(&self, ctx: &mut A::Context)
    where
        A: Actor + Handler<M>,
        A::Context: AsyncContext<A> + ToEnvelope<A, M>,
        M: Message<Result = ()> + Send + 'static,
    {
        self.broker.subscribe_async::<A, M>(ctx);
    }

    pub fn issue_async<M>(&self, msg: M)
    where
        M: Message<Result = ()> + Clone + Send + 'static,
    {
        self.broker.issue_async::<M>(msg);
    }
}
