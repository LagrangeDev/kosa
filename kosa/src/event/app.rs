use std::{future::Future, sync::Arc};

use super::{
    DisconnectEvent, Event, GroupMessageEvent, PrivateMessageEvent, ReconnectEvent, SessionExpired,
    SessionUpdated, dispatcher::Dispatcher,
};
use crate::common::Bot;

#[derive(Clone)]
pub struct Context<S = ()> {
    bot: Arc<Bot>,
    state: Arc<S>,
}

impl<S> Context<S> {
    pub fn bot(&self) -> &Bot {
        &self.bot
    }

    pub fn state(&self) -> &S {
        &self.state
    }
}

pub struct App<S = ()> {
    dispatcher: Dispatcher,
    state: Arc<S>,
}

impl App<()> {
    pub fn new() -> Self {
        Self {
            dispatcher: Dispatcher::new(),
            state: Arc::new(()),
        }
    }

    pub fn with_state<S: Send + Sync + 'static>(self, state: S) -> App<S> {
        App {
            dispatcher: Dispatcher::new(),
            state: Arc::new(state),
        }
    }
}

impl<S: Send + Sync + 'static> App<S> {
    pub fn on<E, F, Fut>(self, f: F) -> Self
    where
        E: Event,
        F: Fn(Context<S>, E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let state = self.state.clone();
        self.dispatcher.register::<E, _, _>(move |bot, ev| {
            f(
                Context {
                    bot,
                    state: state.clone(),
                },
                ev,
            )
        });
        self
    }

    pub fn on_group_message<F, Fut>(self, f: F) -> Self
    where
        F: Fn(Context<S>, GroupMessageEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.on::<GroupMessageEvent, F, Fut>(f)
    }

    pub fn on_private_message<F, Fut>(self, f: F) -> Self
    where
        F: Fn(Context<S>, PrivateMessageEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.on::<PrivateMessageEvent, F, Fut>(f)
    }

    pub fn on_session_updated<F, Fut>(self, f: F) -> Self
    where
        F: Fn(Context<S>, SessionUpdated) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.on::<SessionUpdated, F, Fut>(f)
    }

    pub fn on_session_expired<F, Fut>(self, f: F) -> Self
    where
        F: Fn(Context<S>, SessionExpired) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.on::<SessionExpired, F, Fut>(f)
    }

    pub fn on_disconnect<F, Fut>(self, f: F) -> Self
    where
        F: Fn(Context<S>, DisconnectEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.on::<DisconnectEvent, F, Fut>(f)
    }

    pub fn on_reconnect<F, Fut>(self, f: F) -> Self
    where
        F: Fn(Context<S>, ReconnectEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.on::<ReconnectEvent, F, Fut>(f)
    }

    pub(crate) fn into_dispatcher(self) -> Dispatcher {
        self.dispatcher
    }
}

impl Default for App<()> {
    fn default() -> Self {
        Self::new()
    }
}
