use std::{collections::VecDeque, fmt::Display};

use kosa_proto::message::v2::{Elem, Text as PbText};

use crate::message::{MessageDecode, MessageEncode};

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
    fn encode(&self) -> Vec<Elem> {
        vec![Elem {
            text: Some(PbText {
                text_msg: self.content.clone(),
                ..Default::default()
            }),
            ..Default::default()
        }]
    }
}

impl MessageDecode for Text {
    fn decode(elems: &mut VecDeque<Elem>) -> anyhow::Result<Option<Self>> {
        let ok = elems
            .front()
            .and_then(|e| e.text.as_ref())
            .filter(|t| t.attr6_buf.is_empty())
            .is_some();

        if ok {
            let text = elems.pop_front().unwrap().text.unwrap();
            Ok(Some(Self {
                content: text.text_msg,
            }))
        } else {
            Ok(None)
        }
    }
}
