use std::{collections::VecDeque, fmt::Display, path::Path};

use bytes::Bytes;
use digest::Digest;
use imagesize::ImageSize;
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
    message::{
        MessageDecode, MessageDecodeCommonElem, MessageEncode, RichMedia, utils::extract_info,
    },
    stream_hash, try_parse_hash,
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

    pub(crate) msg_info: Box<MsgInfo>,
    #[allow(dead_code)]
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
            // 这个应该是兼容旧客户端的，如果带上第一个elem，bot收到的消息是两个图片，暂时移除这个elem
            // match scene {
            //     Scene::Private(_, _) => Elem {
            //         not_online_image: Some(NotOnlineImage::decode(self.compact.clone())?),
            //         ..Default::default()
            //     },
            //     Scene::Group(_) => Elem {
            //         custom_face: Some(CustomFace::decode(self.compact.clone())?),
            //         ..Default::default()
            //     },
            // },
            Elem {
                common_elem: Some(CommonElem {
                    service_type: Some(48),
                    pb_elem: Some(self.msg_info.encode_to_vec().into()),
                    #[allow(clippy::identity_op)]
                    business_type: Some(scene.business_type() * 10 + 0),
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
        if let Some(custom_face) = elem.custom_face.as_ref() {
            let pbres = custom_face.pb_reserve.clone().unwrap_or_default();
            Ok(Some(Self {
                name: custom_face.file_path().to_string(),
                file_uuid: "".to_string(),
                sub_type: pbres.sub_type.unwrap_or_default() as u32,
                summary: pbres.summary.unwrap_or_default(),
                md5: custom_face.md5().try_into()?,
                sha1: Default::default(),
                width: custom_face.width() as u32,
                height: custom_face.height() as u32,
                msg_info: Default::default(),
                compact: Default::default(),
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
        pb_elem: Bytes,
        _elem: Elem,
        _elems: &mut VecDeque<Elem>,
        _scene: &Scene,
    ) -> anyhow::Result<Option<Self>> {
        let (
            msg_info,
            index_node,
            FileInfo {
                file_name,
                file_hash,
                file_sha1,
                width,
                height,
                ..
            },
        ) = extract_info(pb_elem)?;
        let pic_ext_biz_info = msg_info
            .ext_biz_info
            .as_ref()
            .and_then(|info| info.pic.as_ref());
        Ok(Some(Self {
            name: file_name.unwrap_or_default(),
            file_uuid: index_node.file_uuid().to_string(),
            sub_type: pic_ext_biz_info
                .and_then(|t| t.biz_type)
                .unwrap_or_default(),
            summary: pic_ext_biz_info
                .and_then(|t| t.text_summary.as_ref())
                .cloned()
                .unwrap_or_default(),
            md5: try_parse_hash!(file_hash.unwrap_or_default())?,
            sha1: try_parse_hash!(file_sha1.unwrap_or_default())?,
            width: width.unwrap_or_default(),
            height: height.unwrap_or_default(),
            msg_info: msg_info.into(),

            compact: Default::default(),
        }))
    }
}

/// 闪照
#[derive(Debug, Clone)]
pub struct EphemeralImage {}

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
        let md5 = hex::encode(self.md5);
        let sha1 = hex::encode(self.sha1);
        let file_name = format!("{}.{}", md5, self.format);
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
