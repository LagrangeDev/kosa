use std::{
    any::{Any, TypeId},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use dashmap::DashMap;
use tracing::error;

use super::Event;
use crate::common::Bot;

type BoxedFut = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
type HandlerFn<E> = Arc<dyn Fn(Arc<Bot>, E) -> BoxedFut + Send + Sync>;

#[derive(Default)]
pub(crate) struct Dispatcher {
    handlers: DashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Dispatcher {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register<E, F, Fut>(&self, f: F)
    where
        E: Event,
        F: Fn(Arc<Bot>, E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let boxed: HandlerFn<E> = Arc::new(move |bot, ev| Box::pin(f(bot, ev)));
        let mut entry = self
            .handlers
            .entry(TypeId::of::<E>())
            .or_insert_with(|| Box::new(Vec::<HandlerFn<E>>::new()));
        let list = entry
            .downcast_mut::<Vec<HandlerFn<E>>>()
            .expect("dispatcher TypeId collision");
        list.push(boxed);
    }

    pub(crate) fn emit<E: Event>(&self, bot: Arc<Bot>, event: E) {
        let Some(slot) = self.handlers.get(&TypeId::of::<E>()) else {
            return;
        };
        let Some(list) = slot.downcast_ref::<Vec<HandlerFn<E>>>() else {
            return;
        };
        for handler in list.iter() {
            let handler = handler.clone();
            let bot = bot.clone();
            let event = event.clone();
            tokio::spawn(async move {
                if let Err(err) = handler(bot, event).await {
                    error!(event = E::NAME, ?err, "event handler failed");
                }
            });
        }
    }
}
