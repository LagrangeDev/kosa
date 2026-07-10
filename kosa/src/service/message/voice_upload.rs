use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::service::v2::{
    ExtBizInfo, FileInfo, MsgInfo, Ntv2RichMediaHighwayExt, Ntv2RichMediaResp, PicExtBizInfo,
    PttExtBizInfo,
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

#[oidb_command(0x126e, 100)]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct GroupVoiceUploadService;

#[derive(Debug)]
pub(crate) struct VoiceUploadReq {
    file_info: FileInfo,
    ext_biz_info: ExtBizInfo,
    scene: Scene,
}

#[derive(Debug)]
pub(crate) struct GroupVoiceUploadResp {
    msg_info: MsgInfo,
    ext: Option<Ntv2RichMediaHighwayExt>,
}

#[register_oidb_service]
impl OidbService<VoiceUploadReq, GroupVoiceUploadResp> for PrivateVoiceUploadService {
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: VoiceUploadReq,
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
    ) -> anyhow::Result<GroupVoiceUploadResp> {
        let resp = Ntv2RichMediaResp::decode(data)?;
        let upload = resp
            .upload
            .ok_or_else(|| anyhow::anyhow!("empty upload response"))?;
        Ok(GroupVoiceUploadResp {
            ext: gen_ext(upload.clone()),
            msg_info: upload.msg_info.unwrap_or_default(),
        })
    }
}
#[register_oidb_service]
impl OidbService<VoiceUploadReq, GroupVoiceUploadResp> for GroupVoiceUploadService {
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: VoiceUploadReq,
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
    ) -> anyhow::Result<GroupVoiceUploadResp> {
        let resp = Ntv2RichMediaResp::decode(data)?;
        let upload = resp
            .upload
            .ok_or_else(|| anyhow::anyhow!("empty upload response"))?;
        Ok(GroupVoiceUploadResp {
            ext: gen_ext(upload.clone()),
            msg_info: upload.msg_info.unwrap_or_default(),
        })
    }
}

impl ServiceContext {
    pub(crate) async fn upload_private_voice(
        &self,
        uin: i64,
        uid: String,
        voice: &LocalVoice,
    ) -> anyhow::Result<GroupVoiceUploadResp> {
        let ext = ExtBizInfo {
            pic: Some(PicExtBizInfo {
                text_summary: voice.summary.clone(),
                ..Default::default()
            }),
            ptt: Some(PttExtBizInfo {
                bytes_reserve: Some(Bytes::from_static(&[0x08, 0x00, 0x38, 0x00])),
                bytes_pb_reserve: None,
                bytes_general_flags: Some(Bytes::from_static(&[
                    0x9a, 0x01, 0x0b, 0xaa, 0x03, 0x08, 0x08, 0x04, 0x12, 0x04, 0x00, 0x00, 0x00,
                    0x00,
                ])),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.send_request::<PrivateVoiceUploadService, VoiceUploadReq, GroupVoiceUploadResp>(
            VoiceUploadReq {
                scene: Scene::Private(uin, uid),
                file_info: voice.build_file_info()?,
                ext_biz_info: ext,
            },
        )
        .await
    }

    pub(crate) async fn upload_group_voice(
        &self,
        group: i64,
        voice: &LocalVoice,
    ) -> anyhow::Result<GroupVoiceUploadResp> {
        let ext = ExtBizInfo {
            pic: Some(PicExtBizInfo {
                text_summary: voice.summary.clone(),
                ..Default::default()
            }),
            ptt: Some(PttExtBizInfo {
                bytes_reserve: None,
                bytes_pb_reserve: Some(Bytes::from_static(&[0x08, 0x00, 0x38, 0x00])),
                bytes_general_flags: Some(Bytes::from_static(&[
                    0x9a, 0x01, 0x07, 0xaa, 0x03, 0x04, 0x08, 0x08, 0x12, 0x00,
                ])),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.send_request::<GroupVoiceUploadService, VoiceUploadReq, GroupVoiceUploadResp>(
            VoiceUploadReq {
                scene: Scene::Group(group),
                file_info: voice.build_file_info()?,
                ext_biz_info: ext,
            },
        )
        .await
    }
}

impl Bot {
    /// 上传私聊语音
    pub async fn upload_private_voice(
        &self,
        uin: i64,
        mut voice: LocalVoice,
    ) -> anyhow::Result<Voice> {
        let upload_resp = self
            .service
            .upload_private_voice(
                uin,
                self.friends().get_uid_required(uin)?.to_string(),
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

    /// 上传群聊语音
    pub async fn upload_group_voice(
        &self,
        group: i64,
        mut voice: LocalVoice,
    ) -> anyhow::Result<Voice> {
        let upload_resp = self.service.upload_group_voice(group, &voice).await?;
        let mut stream = voice
            .stream
            .take()
            .ok_or_else(|| anyhow::anyhow!("stream empty"))?;

        if let Some(ext) = upload_resp.ext {
            self.highway
                .upload(
                    1008,
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
