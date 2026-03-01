use std::{collections::VecDeque, fmt::Display, path::Path};

use bytes::Bytes;
use imagesize::ImageSize;
use kosa_proto::{
    message::v2::{CommonElem, CustomFace, Elem, NotOnlineImage, PbReserve1},
    service::highway::v2::{ExtBizInfo, FileInfo, FileType, MsgInfo, PicExtBizInfo},
};
use md5::{Digest, Md5};
use prost::Message;
use sha1::Sha1;
use tokio::fs::File;

use crate::{
    common::entity::Scene,
    message::{MessageDecode, MessageDecodeCommonElem, MessageEncode, RichMedia},
    stream_hash,
    utils::{image, image::Format, io::AsyncStream},
};

#[derive(Debug, Clone, Default)]
pub struct Image {
    pub name: String,
    pub file_uuid: String,
    pub sub_type: u32,
    pub summary: String,
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub width: u32,
    pub height: u32,

    pub(crate) msg_info: MsgInfo,
    pub(crate) compact: Bytes,
}

impl Display for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[图片]")
    }
}

impl MessageEncode for Image {
    fn encode(self, scene: &Scene) -> anyhow::Result<Vec<Elem>> {
        let elems = vec![
            match scene {
                Scene::Private(_, _) => Elem {
                    not_online_image: Some(NotOnlineImage::decode(self.compact.clone())?),
                    ..Default::default()
                },
                Scene::Group(_) => Elem {
                    custom_face: Some(CustomFace::decode(self.compact.clone())?),
                    ..Default::default()
                },
            },
            Elem {
                common_elem: Some(CommonElem {
                    service_type: Some(48),
                    pb_elem: Some(self.msg_info.encode_to_vec().into()),
                    business_type: Some(scene.business_type() * 10 + 0),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        Ok(elems)
    }
}

impl MessageDecode for Image {
    fn decode(
        elem: &Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let ok = elem.custom_face.is_some();
        if ok {
            Ok(Some(Self {
                msg_info: Default::default(),
                ..Default::default()
            }))
        } else {
            Ok(None)
        }
    }
}

impl MessageDecodeCommonElem for Image {
    const SERVICE_TYPE: u32 = 48;
    const CATEGORY: u32 = 0;

    fn decode_commom_elem(
        mut msg_info: MsgInfo,
        _elem: Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let index0 = msg_info.msg_info_body.pop().unwrap().index.unwrap();
        let pic_ext_biz_info = msg_info
            .ext_biz_info
            .as_ref()
            .and_then(|info| info.pic.as_ref());
        Ok(Some(Self {
            name: index0.info.unwrap().file_name().to_owned(),
            file_uuid: index0.file_uuid.unwrap_or_default(),
            sub_type: pic_ext_biz_info
                .and_then(|t| t.biz_type)
                .unwrap_or_default(),
            summary: pic_ext_biz_info
                .and_then(|t| t.text_summary.as_ref())
                .cloned()
                .unwrap_or_default(),
            msg_info,
            ..Default::default()
        }))
    }
}

/// 本地图片，不能直接发送
pub struct LocalImage {
    pub(crate) size: usize,
    pub(crate) summary: Option<String>,
    pub(crate) sub_type: u32,
    pub(crate) md5: [u8; 16],
    pub(crate) sha1: [u8; 20],
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) format: Format,
    pub(crate) stream: Option<AsyncStream>,
}

impl RichMedia for LocalImage {
    const REQUEST_TYPE: u32 = 2;
    const BUSINESS_TYPE: u32 = 1;

    fn build_file_info(&self) -> anyhow::Result<FileInfo> {
        let md5 = hex::encode(&self.md5);
        let sha1 = hex::encode(&self.sha1);
        let file_name = format!("{}.{}", md5, "png");
        let info = FileInfo {
            file_size: Some(self.size as u32),
            file_hash: Some(md5),
            file_sha1: Some(sha1),
            r#type: Some(FileType {
                r#type: Some(1),
                pic_format: Some(self.format as u32),
                video_format: Some(0),
                voice_format: Some(0),
            }),
            width: Some(self.width),
            height: Some(self.height),
            file_name: Some(file_name),
            time: Some(0),
            original: Some(1),
        };
        Ok(info)
    }

    fn build_ext_info(&self) -> anyhow::Result<ExtBizInfo> {
        let reserve = PbReserve1 {
            sub_type: Some(self.sub_type as i32),
            summary: self.summary.clone(),
            ..Default::default()
        };
        let ext = ExtBizInfo {
            pic: Some(PicExtBizInfo {
                text_summary: self.summary.clone(),
                bytes_pb_reserve_c2c: Bytes::from_static(&[
                    0x08, 0x00, 0x18, 0x00, 0x20, 0x00, 0x42, 0x00, 0x50, 0x00, 0x62, 0x00, 0x92,
                    0x01, 0x00, 0x9A, 0x01, 0x00, 0xA2, 0x01, 0x0C, 0x08, 0x00, 0x12, 0x00, 0x18,
                    0x00, 0x20, 0x00, 0x28, 0x00, 0x3A, 0x00,
                ])
                .into(),
                bytes_pb_reserve_troop: Some(reserve.encode_to_vec().into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(ext)
    }
}

impl LocalImage {
    pub async fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut file = File::open(path).await?;
        let mut md5_hasher = Md5::new();
        let mut sha1_hasher = Sha1::new();
        let (size, md5, sha1) = stream_hash!(file, md5_hasher, sha1_hasher);
        let (format, ImageSize { width, height }) = image::decode(&mut file).await?;
        Ok(Self {
            size,
            summary: None,
            md5: md5.into(),
            sha1: sha1.into(),
            width: width as u32,
            height: height as u32,
            format,
            stream: Some(Box::new(file)),
            sub_type: 0,
        })
    }

    /// 0 -> 图片
    ///
    /// 1 -> 动画表情
    pub fn sub_type(mut self, sub_type: u32) -> Self {
        self.sub_type = sub_type;
        self
    }
}
