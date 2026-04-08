use std::{
    collections::VecDeque,
    fmt::{Display, Formatter},
};

use kosa_proto::message::v2::{Elem, Text, TextResvAttr};
use prost::Message;

use crate::{
    common::entity::Scene,
    message::{MessageDecode, MessageEncode},
};

#[derive(Debug, Clone)]
pub struct At {
    pub r#type: AtType,
    pub display: Option<String>,
}

#[derive(Debug, Clone)]
pub enum AtType {
    All,
    Specific(i64, String),
}

impl At {
    pub fn all() -> At {
        Self {
            r#type: AtType::All,
            display: Some(String::from("@全体成员")),
        }
    }

    pub fn specific(uin: i64, uid: String) -> Self {
        Self {
            r#type: AtType::Specific(uin, uid),
            display: None,
        }
    }

    pub fn display(mut self, display: impl Into<String>) -> At {
        self.display = Some(display.into());
        self
    }
}

impl Display for At {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display.as_deref().unwrap_or(""))
    }
}

impl MessageEncode for At {
    fn encode(self, scene: &Scene) -> anyhow::Result<Vec<Elem>> {
        if let Scene::Private(_, _) = scene {
            return Err(anyhow::anyhow!("only group can send at"));
        };
        let reserve = match self.r#type {
            AtType::All => TextResvAttr {
                at_type: Some(1),
                ..Default::default()
            },
            AtType::Specific(uin, uid) => TextResvAttr {
                at_type: Some(2),
                at_member_uin: Some(uin as u64),
                at_member_uid: Some(uid),
                at_member_tinyid: Some(0),
                ..Default::default()
            },
        };
        let elems = vec![Elem {
            text: Some(Text {
                text_msg: self.display,
                pb_reserve: Some(reserve.encode_to_vec().into()),
                ..Default::default()
            }),
            ..Default::default()
        }];
        Ok(elems)
    }
}

impl MessageDecode for At {
    fn decode(
        elem: &Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let res = match elem
            .text
            .as_ref()
            .filter(|t| t.attr6_buf.is_some())
            .as_ref()
            .and_then(|t| t.pb_reserve.clone())
        {
            None => None,
            Some(reserve) => {
                let reserve = TextResvAttr::decode(reserve)?;
                let at_type = match reserve.at_type {
                    Some(1) => AtType::All,
                    Some(2) => AtType::Specific(
                        reserve.at_member_uin() as i64,
                        reserve.at_member_uid().to_string(),
                    ),
                    _ => unreachable!(),
                };
                Some(Self {
                    r#type: at_type,
                    display: elem.text.as_ref().unwrap().text_msg.clone(),
                })
            }
        };
        Ok(res)
    }
}
