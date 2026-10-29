use bytes::Bytes;
use kosa_macros::oidb_command;
use kosa_proto::service::v2::{DownloadExt, IndexNode, Ntv2RichMediaResp};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    extract_index_node,
    message::{Image, LocalImage},
    service::{
        OidbServiceRequest, ServiceContext, message::utils::parse_download_url,
        packet::nt_v2_richmedia::build_download_request,
    },
};

#[oidb_command(0x11c5, 200)]
pub(crate) struct PrivateImageDownloadReq {
    node: IndexNode,
    ext: Option<DownloadExt>,
    scene: Scene,
}

#[oidb_command(0x11c4, 200)]
pub(crate) struct GroupImageDownloadReq {
    node: IndexNode,
    ext: Option<DownloadExt>,
    scene: Scene,
}

pub(crate) struct ImageDownloadResp {
    url: String,
}

impl OidbServiceRequest for PrivateImageDownloadReq {
    type Response = ImageDownloadResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(
            build_download_request::<LocalImage>(req.node, req.ext, req.scene)?
                .encode_to_vec()
                .into(),
        )
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        let resp = Ntv2RichMediaResp::decode(data)?;
        Ok(ImageDownloadResp {
            url: parse_download_url(resp)?,
        })
    }
}

impl OidbServiceRequest for GroupImageDownloadReq {
    type Response = ImageDownloadResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(
            build_download_request::<LocalImage>(req.node, req.ext, req.scene)?
                .encode_to_vec()
                .into(),
        )
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        let resp = Ntv2RichMediaResp::decode(data)?;
        Ok(ImageDownloadResp {
            url: parse_download_url(resp)?,
        })
    }
}

impl ServiceContext {
    pub(crate) async fn get_private_image_download_url(
        &self,
        uin: i64,
        uid: String,
        image: &Image,
    ) -> anyhow::Result<ImageDownloadResp> {
        let req = PrivateImageDownloadReq {
            node: extract_index_node!(image),
            ext: None,
            scene: Scene::Private(uin, uid),
        };
        self.send_request(req).await
    }
    pub(crate) async fn get_group_image_download_url(
        &self,
        group: i64,
        image: &Image,
    ) -> anyhow::Result<ImageDownloadResp> {
        let req = GroupImageDownloadReq {
            node: extract_index_node!(image),
            ext: None,
            scene: Scene::Group(group),
        };
        self.send_request(req).await
    }
}

impl Bot {
    /// 获取私聊图片下载链接
    pub async fn get_private_image_download_url(
        &self,
        uin: i64,
        image: &Image,
    ) -> anyhow::Result<String> {
        let resp = self
            .service
            .get_private_image_download_url(
                uin,
                self.friends().get_uid_required(uin)?.to_string(),
                image,
            )
            .await?;
        Ok(resp.url)
    }

    /// 获取群聊图片下载链接
    pub async fn get_group_image_download_url(
        &self,
        group: i64,
        image: &Image,
    ) -> anyhow::Result<String> {
        let resp = self
            .service
            .get_group_image_download_url(group, image)
            .await?;
        Ok(resp.url)
    }
}
