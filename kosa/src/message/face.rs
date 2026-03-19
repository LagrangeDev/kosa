use std::{
    collections::VecDeque,
    fmt::{Display, Formatter},
};

use bytes::Bytes;
use kosa_proto::message::v2::{CommonElem, Elem, QFaceExtra, QSmallFaceExtra};
use prost::Message;

use crate::{
    common::entity::Scene,
    message::{MessageDecode, MessageDecodeCommonElem, MessageEncode},
};

/// 小黄脸表情
#[derive(Debug, Clone)]
pub struct QFace {
    pub face_id: u32,
    pub display: Option<String>,
}

impl QFace {
    pub fn new(face_id: u32) -> Self {
        Self {
            face_id,
            display: None,
        }
    }
}

impl Display for QFace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[face: {}]", self.face_id)
    }
}

impl MessageEncode for QFace {
    fn encode(self, _scene: &Scene) -> anyhow::Result<Vec<Elem>> {
        let reserve = QSmallFaceExtra {
            face_id: Some(self.face_id),
            ..Default::default()
        }
        .encode_to_vec();
        let elems = vec![Elem {
            common_elem: Some(CommonElem {
                service_type: Some(33),
                pb_elem: Some(reserve.into()),
                business_type: Some(1),
            }),
            ..Default::default()
        }];
        Ok(elems)
    }
}

impl MessageDecode for QFace {
    fn decode(
        elem: &Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let res = elem
            .face
            .as_ref()
            .filter(|f| f.old.is_some())
            .map(|f| Self {
                face_id: f.index.unwrap_or_default() as u32,
                display: None,
            });
        Ok(res)
    }
}

impl MessageDecodeCommonElem for QFace {
    const SERVICE_TYPE: u32 = 33;
    const CATEGORY: u32 = 1;

    fn decode_commom_elem(
        pb_elem: Bytes,
        _elem: Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let q_face = QSmallFaceExtra::decode(pb_elem)?;
        Ok(Some(Self {
            face_id: q_face.face_id(),
            display: Some(q_face.preview().to_string()),
        }))
    }
}

/// 超级表情
#[derive(Debug, Clone)]
pub struct SuperFace {
    pub face_id: u32,
    /// 猜拳和掷骰子的值
    pub result_id: Option<String>,
    pub sticker_type: Option<i32>,
    pub display: Option<String>,
}

/// 猜拳
#[repr(u32)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Roshambo {
    /// 布
    Paper = 1,
    /// 剪刀
    Scissors = 2,
    /// 石头
    Rock = 3,
}

impl SuperFace {
    pub fn new(face_id: u32) -> Self {
        Self {
            face_id,
            sticker_type: Some(1),
            result_id: None,
            display: None,
        }
    }

    /// 掷骰子
    pub fn dice(value: u32) -> Self {
        let value = if (1..=6).contains(&value) {
            value
        } else {
            rand::random_range(1..=6)
        };
        Self {
            face_id: 358,
            sticker_type: Some(2),
            result_id: Some(value.to_string()),
            display: None,
        }
    }

    /// 猜拳
    pub fn roshambo(roshambo: Roshambo) -> Self {
        Self {
            face_id: 359,
            sticker_type: Some(2),
            result_id: Some((roshambo as u32).to_string()),
            display: None,
        }
    }
}

impl Display for SuperFace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[superface: {}]", self.face_id)
    }
}

impl MessageEncode for SuperFace {
    fn encode(self, _scene: &Scene) -> anyhow::Result<Vec<Elem>> {
        let reserve = QFaceExtra {
            pack_id: Some("1".to_string()),
            sticker_id: Some("8".to_string()),
            qsid: Some(self.face_id as i32),
            source_type: Some(1),
            sticker_type: self.sticker_type,
            result_id: self.result_id,
            text: None,
            random_type: Some(1),
        };
        let elems = vec![Elem {
            common_elem: Some(CommonElem {
                service_type: Some(37),
                pb_elem: Some(reserve.encode_to_vec().into()),
                business_type: Some(1),
            }),
            ..Default::default()
        }];
        Ok(elems)
    }
}

impl MessageDecodeCommonElem for SuperFace {
    const SERVICE_TYPE: u32 = 37;
    const CATEGORY: u32 = 1;

    fn decode_commom_elem(
        pb_elem: Bytes,
        _elem: Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let q_face = QFaceExtra::decode(pb_elem)?;
        Ok(Some(Self {
            face_id: q_face.qsid.unwrap_or_default() as u32,
            result_id: q_face.result_id,
            sticker_type: q_face.sticker_type,
            display: q_face.text,
        }))
    }
}
