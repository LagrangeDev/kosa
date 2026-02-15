use std::{
    any::{Any, TypeId},
    cell::RefCell,
    collections::HashMap,
};

use actix::{Actor, AsyncContext, Handler, Message, Recipient, dev::ToEnvelope};
use tracing::trace;

#[derive(Debug)]
pub(crate) struct Broker {
    subscribers: RefCell<HashMap<TypeId, Vec<Box<dyn Any>>>>,
}

impl Broker {
    pub fn new() -> Self {
        Self {
            subscribers: RefCell::new(HashMap::new()),
        }
    }
}
impl Broker {
    /// 订阅消息
    ///
    /// A: 订阅者 Actor 类型
    ///
    /// M: 消息类型
    pub fn subscribe_async<A, M>(&self, ctx: &mut A::Context)
    where
        A: Actor + Handler<M>,
        A::Context: AsyncContext<A> + ToEnvelope<A, M>,
        M: Message<Result = ()> + Send + 'static,
    {
        let type_id = TypeId::of::<M>();
        let recipient = ctx.address().recipient();

        self.subscribers
            .borrow_mut()
            .entry(type_id)
            .or_default()
            .push(Box::new(recipient));

        trace!("Broker: Creating TypeId({:?}) subscription list", type_id);
    }

    /// 发布消息
    pub fn issue_async<M>(&self, msg: M)
    where
        M: Message<Result = ()> + Clone + Send + 'static,
    {
        let type_id = TypeId::of::<M>();
        if let Some(subs) = self.subscribers.borrow().get(&type_id) {
            for sub in subs {
                if let Some(recipient) = sub.downcast_ref::<Recipient<M>>() {
                    recipient.do_send(msg.clone());
                }
            }
        }
    }
}
