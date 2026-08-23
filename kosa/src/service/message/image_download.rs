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

pub(crate) struct PrivateImageDownloadResp {
    url: String,
}

impl OidbServiceRequest for PrivateImageDownloadReq {
    type Response = PrivateImageDownloadResp;
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
        Ok(PrivateImageDownloadResp {
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
    ) -> anyhow::Result<PrivateImageDownloadResp> {
        let req = PrivateImageDownloadReq {
            node: extract_index_node!(image),
            ext: None,
            scene: Scene::Private(uin, uid),
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
}
