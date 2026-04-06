use std::{collections::VecDeque, fmt::Display, io::Cursor, path::Path};

use bytes::Bytes;
use digest::Digest;
use kosa_proto::{
    message::v2::{CommonElem, Elem},
    service::highway::v2::{FileInfo, FileType, MsgInfo},
};
use md5::Md5;
use prost::Message;
use sha1::Sha1;
use tokio::fs::File;

use crate::{
    common::entity::Scene,
    message::{MessageDecodeCommonElem, MessageEncode, RichMedia, utils::extract_info},
    stream_hash, try_parse_hash,
    utils::{io::AsyncStream, silk::get_silk_duration},
};

/// 语音消息
#[derive(Debug, Clone)]
pub struct Voice {
    pub summary: String,
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub duration: u32,
    pub(crate) msg_info: Box<MsgInfo>,
}

impl Display for Voice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[语音]")
    }
}

impl MessageEncode for Voice {
    fn encode(self, scene: &Scene) -> anyhow::Result<Vec<Elem>> {
        let elems = vec![Elem {
            common_elem: Some(CommonElem {
                service_type: Some(48),
                pb_elem: Some(self.msg_info.encode_to_vec().into()),
                #[allow(clippy::identity_op)]
                business_type: Some(scene.business_type() * 10 + 2),
            }),
            ..Default::default()
        }];
        Ok(elems)
    }
}

impl MessageDecodeCommonElem for Voice {
    const SERVICE_TYPE: u32 = 48;
    const CATEGORY: u32 = 2;

    fn decode_commom_elem(
        pb_elem: Bytes,
        _elem: Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let (
            msg_info,
            _index_node,
            FileInfo {
                file_hash,
                file_sha1,
                time,
                ..
            },
        ) = extract_info(pb_elem)?;
        let pic_ext_biz_info = msg_info
            .ext_biz_info
            .as_ref()
            .and_then(|info| info.pic.as_ref());

        Ok(Some(Self {
            summary: pic_ext_biz_info
                .and_then(|t| t.text_summary.as_ref())
                .cloned()
                .unwrap_or_default(),
            md5: try_parse_hash!(file_hash.unwrap_or_default())?,
            sha1: try_parse_hash!(file_sha1.unwrap_or_default())?,
            duration: time.unwrap_or_default(),
            msg_info: Box::new(msg_info),
        }))
    }
}

pub struct LocalVoice {
    pub(crate) size: usize,
    pub(crate) summary: Option<String>,
    pub(crate) md5: [u8; 16],
    pub(crate) sha1: [u8; 20],
    pub(crate) duration: f32,
    pub(crate) stream: Option<AsyncStream>,
}

impl RichMedia for LocalVoice {
    const REQUEST_TYPE: u32 = 2;
    const BUSINESS_TYPE: u32 = 3;

    fn build_file_info(&self) -> anyhow::Result<FileInfo> {
        let md5 = hex::encode(self.md5);
        let sha1 = hex::encode(self.sha1);
        let file_name = format!("{}.{}", md5, "amr");
        let info = FileInfo {
            file_size: Some(self.size as u32),
            file_hash: Some(md5),
            file_sha1: Some(sha1),
            file_name: Some(file_name),
            r#type: Some(FileType {
                r#type: Some(3),
                voice_format: Some(1),
                ..Default::default()
            }),
            time: Some(self.duration.round() as u32),
            ..Default::default()
        };
        Ok(info)
    }
}

impl LocalVoice {
    pub async fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut file = File::open(path).await?;
        let mut md5_hasher = Md5::new();
        let mut sha1_hasher = Sha1::new();
        let (size, md5, sha1) = stream_hash!(file, md5_hasher, sha1_hasher);
        Ok(Self {
            size,
            summary: None,
            md5: md5.into(),
            sha1: sha1.into(),
            duration: 0.0,
            stream: Some(Box::new(file)),
        })
    }

    pub async fn from_bytes(data: Bytes) -> anyhow::Result<Self> {
        let duration = get_silk_duration(data.clone())?;
        let mut stream = Cursor::new(data);
        let mut md5_hasher = Md5::new();
        let mut sha1_hasher = Sha1::new();
        let (size, md5, sha1) = stream_hash!(stream, md5_hasher, sha1_hasher);
        Ok(Self {
            size,
            summary: None,
            md5: md5.into(),
            sha1: sha1.into(),
            duration,
            stream: Some(Box::new(stream)),
        })
    }
}
