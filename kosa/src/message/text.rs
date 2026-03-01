use std::{collections::VecDeque, fmt::Display};

use kosa_proto::message::v2::{Elem, Text as PbText};

use crate::{
    common::entity::Scene,
    message::{MessageDecode, MessageEncode},
};

#[derive(Debug, Clone)]
pub struct Text {
    content: String,
}

impl Text {
    pub fn new<S: Into<String>>(content: S) -> Self {
        Self {
            content: content.into(),
        }
    }
}

impl Display for Text {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content)
    }
}

impl MessageEncode for Text {
    fn encode(self, _scene: &Scene) -> anyhow::Result<Vec<Elem>> {
        let elems = vec![Elem {
            text: Some(PbText {
                text_msg: self.content.into(),
                ..Default::default()
            }),
            ..Default::default()
        }];
        Ok(elems)
    }
}

impl MessageDecode for Text {
    fn decode(
        elem: &Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let res = elem
            .text
            .as_ref()
            .filter(|t| t.attr6_buf.is_none())
            .map(|t| Self {
                content: t.text_msg().to_owned(),
            });

        Ok(res)
    }
}
