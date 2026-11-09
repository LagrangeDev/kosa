use std::{fmt::Debug, future::Future, sync::Arc};

use crate::{
    common::Bot,
    event::{
        BotOffline, BotOnline, Dispatcher, Event, GroupMessageEvent, PrivateMessageEvent,
        SessionExpired, SessionUpdated,
    },
};

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
            dispatcher: self.dispatcher,
            state: Arc::new(state),
        }
    }
}

impl<S: Send + Sync + 'static> App<S> {
    /// Registers a handler whose errors are logged by the dispatcher.
    /// Each handler can return its own error type.
    pub fn on<E, F, Fut, Err>(self, f: F) -> Self
    where
        E: Event,
        F: Fn(Context<S>, E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Err>> + Send + 'static,
        Err: Debug,
    {
        let state = self.state.clone();
        self.dispatcher.register::<E, _, _, Err>(move |bot, ev| {
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

    pub fn on_group_message<F, Fut, Err>(self, f: F) -> Self
    where
        F: Fn(Context<S>, GroupMessageEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Err>> + Send + 'static,
        Err: Debug,
    {
        self.on::<GroupMessageEvent, F, Fut, Err>(f)
    }

    pub fn on_private_message<F, Fut, Err>(self, f: F) -> Self
    where
        F: Fn(Context<S>, PrivateMessageEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Err>> + Send + 'static,
        Err: Debug,
    {
        self.on::<PrivateMessageEvent, F, Fut, Err>(f)
    }

    pub fn on_session_updated<F, Fut, Err>(self, f: F) -> Self
    where
        F: Fn(Context<S>, SessionUpdated) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Err>> + Send + 'static,
        Err: Debug,
    {
        self.on::<SessionUpdated, F, Fut, Err>(f)
    }

    pub fn on_session_expired<F, Fut, Err>(self, f: F) -> Self
    where
        F: Fn(Context<S>, SessionExpired) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Err>> + Send + 'static,
        Err: Debug,
    {
        self.on::<SessionExpired, F, Fut, Err>(f)
    }

    pub fn on_online<F, Fut, Err>(self, f: F) -> Self
    where
        F: Fn(Context<S>, BotOnline) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Err>> + Send + 'static,
        Err: Debug,
    {
        self.on::<BotOnline, F, Fut, Err>(f)
    }

    pub fn on_offline<F, Fut, Err>(self, f: F) -> Self
    where
        F: Fn(Context<S>, BotOffline) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Err>> + Send + 'static,
        Err: Debug,
    {
        self.on::<BotOffline, F, Fut, Err>(f)
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
