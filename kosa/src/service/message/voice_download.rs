use bytes::Bytes;
use kosa_macros::oidb_command;
use kosa_proto::service::v2::{DownloadExt, IndexNode, Ntv2RichMediaResp};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    extract_index_node,
    message::{LocalVoice, Voice},
    service::{
        OidbServiceRequest, ServiceContext, message::utils::parse_download_url,
        packet::nt_v2_richmedia::build_download_request,
    },
};

#[oidb_command(0x126d, 200)]
pub(crate) struct PrivateVoiceDownloadReq {
    uin: i64,
    uid: String,
    node: IndexNode,
    ext: Option<DownloadExt>,
}

pub(crate) struct PrivateVoiceDownloadResp {
    url: String,
}

impl OidbServiceRequest for PrivateVoiceDownloadReq {
    type Response = PrivateVoiceDownloadResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(build_download_request::<LocalVoice>(
            req.node,
            req.ext,
            Scene::Private(req.uin, req.uid),
        )?
        .encode_to_vec()
        .into())
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
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
            uin,
            uid,
            node: extract_index_node!(voice),
            ext: None,
        };
        self.send_request(req).await
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
                self.friends().get_uid_required(uin)?.to_string(),
                voice,
            )
            .await?;
        Ok(resp.url)
    }
}
