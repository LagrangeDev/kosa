use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::service::v2::{DownloadExt, IndexNode, Ntv2RichMediaResp};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    extract_index_node,
    message::{Image, LocalImage},
    service::{
        OidbService, ServiceContext, message::utils::parse_download_url,
        packet::nt_v2_richmedia::build_download_request,
    },
};

#[oidb_command(0x11c5, 200)]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct PrivateImageDownloadService;

pub(crate) struct PrivateImageDownloadReq {
    node: IndexNode,
    ext: Option<DownloadExt>,
    scene: Scene,
}

pub(crate) struct PrivateImageDownloadResp {
    url: String,
}

#[register_oidb_service]
impl OidbService<PrivateImageDownloadReq, PrivateImageDownloadResp>
    for PrivateImageDownloadService
{
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: PrivateImageDownloadReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        Ok(
            build_download_request::<LocalImage>(req.node, req.ext, req.scene)?
                .encode_to_vec()
                .into(),
        )
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<PrivateImageDownloadResp> {
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
        self.send_request::<PrivateImageDownloadService,PrivateImageDownloadReq,PrivateImageDownloadResp>(req).await
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
