use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::service::highway::v2::{
    ExtBizInfo, FileInfo, MsgInfo, Ntv2RichMediaHighwayExt, Ntv2RichMediaResp,
};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    message::{LocalVoice, RichMedia, Voice},
    service::{
        OidbService, ServiceContext,
        packet::nt_v2_richmedia::{build_upload_request, gen_ext},
    },
};

#[oidb_command(0x126d, 100)]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct PrivateVoiceUploadService;

#[derive(Debug)]
pub(crate) struct PrivateVoiceUploadReq {
    file_info: FileInfo,
    ext_biz_info: ExtBizInfo,
    scene: Scene,
}

#[derive(Debug)]
pub(crate) struct PrivateVoiceUploadResp {
    msg_info: MsgInfo,
    ext: Option<Ntv2RichMediaHighwayExt>,
}

#[register_oidb_service]
impl OidbService<PrivateVoiceUploadReq, PrivateVoiceUploadResp> for PrivateVoiceUploadService {
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: PrivateVoiceUploadReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        Ok(
            build_upload_request::<LocalVoice>(req.scene, req.file_info, req.ext_biz_info)?
                .encode_to_vec()
                .into(),
        )
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<PrivateVoiceUploadResp> {
        let resp = Ntv2RichMediaResp::decode(data)?;
        let upload = resp
            .upload
            .ok_or_else(|| anyhow::anyhow!("empty upload response"))?;
        Ok(PrivateVoiceUploadResp {
            ext: gen_ext(upload.clone()),
            msg_info: upload.msg_info.unwrap_or_default(),
        })
    }
}

impl ServiceContext {
    pub async fn upload_private_voice(
        &self,
        uin: i64,
        uid: String,
        voice: &LocalVoice,
    ) -> anyhow::Result<PrivateVoiceUploadResp> {
        self.send_request::<PrivateVoiceUploadService,PrivateVoiceUploadReq,PrivateVoiceUploadResp>(
            PrivateVoiceUploadReq{
                scene:Scene::Private(uin,uid),
                file_info:voice.build_file_info()?,
                ext_biz_info:voice.build_ext_info()?
            }
        ).await
    }
}

impl Bot {
    pub async fn upload_private_voice(
        &self,
        uin: i64,
        mut voice: LocalVoice,
    ) -> anyhow::Result<Voice> {
        let upload_resp = self
            .service
            .upload_private_voice(
                uin,
                self.cache.get_uid(uin).ok_or_else(|| anyhow::anyhow!(""))?,
                &voice,
            )
            .await?;
        let mut stream = voice
            .stream
            .take()
            .ok_or_else(|| anyhow::anyhow!("stream empty"))?;

        if let Some(ext) = upload_resp.ext {
            self.highway
                .upload(
                    1007,
                    &mut stream,
                    voice.size,
                    voice.md5,
                    Some(ext.encode_to_vec().into()),
                )
                .await?;
        };

        let voice = Voice {
            summary: voice.summary.unwrap_or_default(),
            md5: voice.md5,
            sha1: voice.sha1,
            duration: voice.duration.round() as u32,
            msg_info: upload_resp.msg_info.into(),
        };
        Ok(voice)
    }
}
