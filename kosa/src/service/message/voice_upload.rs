use bytes::Bytes;
use kosa_macros::oidb_command;
use kosa_proto::service::v2::{
    ExtBizInfo, FileInfo, MsgInfo, Ntv2RichMediaHighwayExt, Ntv2RichMediaResp, PicExtBizInfo,
    PttExtBizInfo,
};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    message::{LocalVoice, RichMedia, Voice},
    service::{
        OidbServiceRequest, ServiceContext,
        packet::nt_v2_richmedia::{build_upload_request, gen_ext},
    },
};

#[oidb_command(0x126d, 100)]
pub(crate) struct PrivateVoiceUploadReq {
    uin: i64,
    uid: String,
    file_info: FileInfo,
    ext_biz_info: ExtBizInfo,
}

#[oidb_command(0x126e, 100)]
pub(crate) struct GroupVoiceUploadReq {
    group: i64,
    file_info: FileInfo,
    ext_biz_info: ExtBizInfo,
}

#[derive(Debug)]
pub(crate) struct VoiceUploadResp {
    msg_info: MsgInfo,
    ext: Option<Ntv2RichMediaHighwayExt>,
}

impl OidbServiceRequest for PrivateVoiceUploadReq {
    type Response = VoiceUploadResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(build_upload_request::<LocalVoice>(
            Scene::Private(req.uin, req.uid),
            req.file_info,
            req.ext_biz_info,
        )?
        .encode_to_vec()
        .into())
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        decode_voice_upload_resp(data)
    }
}

impl OidbServiceRequest for GroupVoiceUploadReq {
    type Response = VoiceUploadResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(build_upload_request::<LocalVoice>(
            Scene::Group(req.group),
            req.file_info,
            req.ext_biz_info,
        )?
        .encode_to_vec()
        .into())
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        decode_voice_upload_resp(data)
    }
}

fn decode_voice_upload_resp(data: Bytes) -> anyhow::Result<VoiceUploadResp> {
    let resp = Ntv2RichMediaResp::decode(data)?;
    let upload = resp
        .upload
        .ok_or_else(|| anyhow::anyhow!("empty upload response"))?;
    Ok(VoiceUploadResp {
        ext: gen_ext(upload.clone()),
        msg_info: upload.msg_info.unwrap_or_default(),
    })
}

impl ServiceContext {
    pub(crate) async fn upload_private_voice(
        &self,
        uin: i64,
        uid: String,
        voice: &LocalVoice,
    ) -> anyhow::Result<VoiceUploadResp> {
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
        self.send_request(PrivateVoiceUploadReq {
            uin,
            uid,
            file_info: voice.build_file_info()?,
            ext_biz_info: ext,
        })
        .await
    }

    pub(crate) async fn upload_group_voice(
        &self,
        group: i64,
        voice: &LocalVoice,
    ) -> anyhow::Result<VoiceUploadResp> {
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
        self.send_request(GroupVoiceUploadReq {
            group,
            file_info: voice.build_file_info()?,
            ext_biz_info: ext,
        })
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

        Ok(build_voice(voice, upload_resp.msg_info))
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

        Ok(build_voice(voice, upload_resp.msg_info))
    }
}

fn build_voice(voice: LocalVoice, msg_info: MsgInfo) -> Voice {
    Voice {
        summary: voice.summary.unwrap_or_default(),
        md5: voice.md5,
        sha1: voice.sha1,
        duration: voice.duration.round() as u32,
        msg_info: msg_info.into(),
    }
}
