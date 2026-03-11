use std::{
    collections::VecDeque,
    fmt::{Display, Formatter},
};

use bytes::Bytes;
use kosa_proto::message::v2::{CommonElem, Elem, QSmallFaceExtra};
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
        write!(f, "{}", self.display.as_deref().unwrap_or(""))
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
