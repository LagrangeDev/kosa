use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::service::highway::v2::{DownloadExt, IndexNode, Ntv2RichMediaResp};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    extract_index_node,
    message::{LocalVoice, Voice},
    service::{
        OidbService, ServiceContext, message::utils::parse_download_url,
        packet::nt_v2_richmedia::build_download_request,
    },
};

#[oidb_command(0x126d, 200)]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct PrivateVoiceDonwloadService;

pub(crate) struct PrivateVoiceDownloadReq {
    node: IndexNode,
    ext: Option<DownloadExt>,
    scene: Scene,
}

pub(crate) struct PrivateVoiceDownloadResp {
    url: String,
}

#[register_oidb_service]
impl OidbService<PrivateVoiceDownloadReq, PrivateVoiceDownloadResp>
    for PrivateVoiceDonwloadService
{
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: PrivateVoiceDownloadReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        Ok(
            build_download_request::<LocalVoice>(req.node, req.ext, req.scene)?
                .encode_to_vec()
                .into(),
        )
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<PrivateVoiceDownloadResp> {
        let resp = Ntv2RichMediaResp::decode(data)?;
        Ok(PrivateVoiceDownloadResp {
            url: parse_download_url(resp)?,
        })
    }
}

impl ServiceContext {
    pub(crate) async fn get_private_voice_download_url(
        &self,
        uin: i64,
        uid: String,
        voice: &Voice,
    ) -> anyhow::Result<PrivateVoiceDownloadResp> {
        let req = PrivateVoiceDownloadReq {
            node: extract_index_node!(voice),
            ext: None,
            scene: Scene::Private(uin, uid),
        };
        self.send_request::<PrivateVoiceDonwloadService, PrivateVoiceDownloadReq, PrivateVoiceDownloadResp>(req).await
    }
}

impl Bot {
    /// 获取私聊图片下载链接
    pub async fn get_private_voice_download_url(
        &self,
        uin: i64,
        voice: &Voice,
    ) -> anyhow::Result<String> {
        let resp = self
            .service
            .get_private_voice_download_url(
                uin,
                self.cache.get_uid(uin).ok_or_else(|| anyhow::anyhow!(""))?,
                voice,
            )
            .await?;
        Ok(resp.url)
    }
}
