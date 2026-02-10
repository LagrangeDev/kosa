mod text;

use std::{
    collections::VecDeque,
    fmt::Display,
    ops::{Deref, DerefMut},
};

use derive_more::Display;
use enum_dispatch::enum_dispatch;
use kosa_proto::message::v2::Elem;

pub use crate::message::text::Text;

#[enum_dispatch]
pub(crate) trait MessageEncode: Sized + Display {
    fn encode(&self) -> Vec<Elem>;
}

pub(crate) trait MessageDecode: Sized + Display {
    fn decode(elems: &mut VecDeque<Elem>) -> anyhow::Result<Option<Self>>;
}

#[enum_dispatch(MessageEncode)]
#[derive(Debug, Clone, Display)]
pub enum Message {
    Text,
}

#[derive(Debug, Clone, Default)]
pub struct MessageChain(Vec<Message>);

impl Deref for MessageChain {
    type Target = Vec<Message>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MessageChain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl MessageChain {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn text(mut self, content: impl Into<String>) -> Self {
        self.0.push(Message::Text(Text::new(content)));
        self
    }

    pub(crate) fn encode(&self) -> Vec<Elem> {
        let mut elems: Vec<Elem> = Vec::with_capacity(self.0.len());
        for msg in &self.0 {
            elems.extend(msg.encode());
        }
        elems
    }
}

#[derive(Debug, Clone, Default)]
pub struct BotMessage {
    pub random: u32,
    pub sequence: i32,
    pub client_sequence: i32,
    pub message_id: u64,
    pub messages: MessageChain,
}

impl Display for BotMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for message in self.messages.iter() {
            write!(f, "{}", message)?;
        }
        Ok(())
    }
}
