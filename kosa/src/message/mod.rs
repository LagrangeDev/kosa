mod at;
mod face;
mod image;
mod text;
mod utils;
mod voice;

use std::{
    collections::VecDeque,
    fmt::Display,
    ops::{Deref, DerefMut},
    vec::IntoIter,
};

use anyhow::Context;
use bytes::Bytes;
use derive_more::Display;
use enum_dispatch::enum_dispatch;
use kosa_proto::{message::v2::Elem, service::v2::FileInfo};

use crate::common::entity::Scene;
pub use crate::message::{
    at::{At, AtType},
    face::{QFace, Roshambo, SuperFace},
    image::{Image, LocalImage},
    text::Text,
    voice::{LocalVoice, Voice},
};

#[enum_dispatch]
pub(crate) trait MessageEncode: Sized + Display {
    fn encode(self, scene: &Scene) -> anyhow::Result<Vec<Elem>>;
}

pub(crate) trait MessageDecode: Sized + Display {
    fn decode(
        elem: &Elem,
        elems: &mut VecDeque<Elem>,
        scene: &Scene,
    ) -> anyhow::Result<Option<Self>>;
}

pub(crate) trait MessageDecodeCommonElem: Sized + Display {
    const SERVICE_TYPE: u32;
    const CATEGORY: u32;

    fn decode_commom_elem(
        pb_elem: Bytes,
        elem: Elem,
        elems: &mut VecDeque<Elem>,
        scene: &Scene,
    ) -> anyhow::Result<Option<Self>>;
}

pub(crate) trait RichMedia {
    const REQUEST_TYPE: u32;
    const BUSINESS_TYPE: u32;

    fn build_file_info(&self) -> anyhow::Result<FileInfo>;
}

#[enum_dispatch(MessageEncode)]
#[derive(Debug, Clone, Display)]
pub enum Element {
    At,
    Text,
    QFace,
    SuperFace,
    Image,
    Voice,
}

#[derive(Debug, Clone, Default)]
pub struct MessageChain(Vec<Element>);

impl IntoIterator for MessageChain {
    type Item = Element;
    type IntoIter = IntoIter<Element>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a MessageChain {
    type Item = &'a Element;
    type IntoIter = std::slice::Iter<'a, Element>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl Deref for MessageChain {
    type Target = Vec<Element>;
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

    /// @消息
    pub fn at(mut self, at: At) -> Self {
        self.push(Element::At(at));
        self
    }

    /// 纯文本消息
    pub fn text(mut self, content: impl Into<String>) -> Self {
        self.push(Element::Text(Text::new(content)));
        self
    }

    /// 小表情
    pub fn qface(mut self, face_id: u32) -> Self {
        self.push(Element::QFace(QFace::new(face_id)));
        self
    }

    /// 超级表情
    pub fn super_face(mut self, face_id: u32) -> Self {
        self.push(Element::SuperFace(SuperFace::new(face_id)));
        self
    }

    /// 掷骰子
    pub fn dice(mut self, value: u32) -> Self {
        self.push(Element::SuperFace(SuperFace::dice(value)));
        self
    }

    /// 猜拳
    pub fn roshambo(mut self, roshambo: Roshambo) -> Self {
        self.push(Element::SuperFace(SuperFace::roshambo(roshambo)));
        self
    }

    pub fn image(mut self, image: Image) -> Self {
        self.push(Element::Image(image));
        self
    }

    pub fn voice(mut self, voice: Voice) -> Self {
        self.push(Element::Voice(voice));
        self
    }

    /// 消息是否为纯文本
    pub fn is_plain_text(&self) -> bool {
        self.iter().all(|e| matches!(e, Element::Text(_)))
    }

    /// 获取一个消息中被@的所有人，不包含@全体
    pub fn mentions(&self) -> Vec<i64> {
        self.iter()
            .filter_map(|e| match e {
                Element::At(At {
                    r#type: AtType::Specific(uin, _),
                    ..
                }) => Some(*uin),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn encode(self, scene: &Scene) -> anyhow::Result<Vec<Elem>> {
        let len = self.len();
        self.into_iter()
            .try_fold(Vec::with_capacity(len), |mut acc, elem| {
                acc.extend(elem.encode(scene).context("failed to encode elem")?);
                Ok(acc)
            })
    }

    pub fn iter(&self) -> impl Iterator<Item = &Element> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Element> {
        self.0.iter_mut()
    }
}

// todo 要考虑部分无法发送的消息段怎么加入到messagechain
#[derive(Debug, Clone)]
pub struct BotMessage {
    pub random: u32,
    pub sequence: u64,
    pub client_sequence: u64,
    pub message_id: u64,
    pub scene: Scene,
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
