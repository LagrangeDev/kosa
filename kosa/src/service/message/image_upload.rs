use bytes::Bytes;
use kosa_macros::oidb_command;
use kosa_proto::{
    message::v2::CustomFacePbReserve1,
    service::v2::{
        ExtBizInfo, FileInfo, MsgInfo, Ntv2RichMediaHighwayExt, Ntv2RichMediaResp, PicExtBizInfo,
    },
};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    message::{Image, LocalImage, RichMedia},
    service::{
        OidbServiceRequest, ServiceContext,
        packet::nt_v2_richmedia::{build_upload_request, gen_ext},
    },
};

#[oidb_command(0x11c5, 100)]
pub(crate) struct PrivateImageUploadReq {
    uin: i64,
    uid: String,
    file_info: FileInfo,
    ext_biz_info: ExtBizInfo,
}

#[oidb_command(0x11c4, 100)]
pub(crate) struct GroupImageUploadReq {
    group: i64,
    file_info: FileInfo,
    ext_biz_info: ExtBizInfo,
}

#[derive(Debug)]
pub(crate) struct ImageUploadResp {
    msg_info: MsgInfo,
    compat_qmsg: Bytes,
    ext: Option<Ntv2RichMediaHighwayExt>,
}

impl OidbServiceRequest for PrivateImageUploadReq {
    type Response = ImageUploadResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(build_upload_request::<LocalImage>(
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
        decode_image_upload_resp(data)
    }
}

impl OidbServiceRequest for GroupImageUploadReq {
    type Response = ImageUploadResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(build_upload_request::<LocalImage>(
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
        decode_image_upload_resp(data)
    }
}

fn decode_image_upload_resp(data: Bytes) -> anyhow::Result<ImageUploadResp> {
    let resp = Ntv2RichMediaResp::decode(data)?;
    let upload = resp
        .upload
        .ok_or_else(|| anyhow::anyhow!("empty upload response"))?;
    Ok(ImageUploadResp {
        ext: gen_ext(upload.clone()),
        msg_info: upload.msg_info.unwrap_or_default(),
        compat_qmsg: upload.compat_q_msg.unwrap_or_default(),
    })
}

impl ServiceContext {
    pub(crate) async fn upload_private_image(
        &self,
        uin: i64,
        uid: String,
        image: &LocalImage,
    ) -> anyhow::Result<ImageUploadResp> {
        let reserve = CustomFacePbReserve1 {
            sub_type: Some(image.sub_type as i32),
            summary: image.summary.clone(),
            ..Default::default()
        };
        let ext = ExtBizInfo {
            pic: Some(PicExtBizInfo {
                text_summary: image.summary.clone(),
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
        self.send_request(PrivateImageUploadReq {
            uin,
            uid,
            file_info: image.build_file_info()?,
            ext_biz_info: ext,
        })
        .await
    }

    pub(crate) async fn upload_group_image(
        &self,
        group: i64,
        image: &LocalImage,
    ) -> anyhow::Result<ImageUploadResp> {
        let reserve = CustomFacePbReserve1 {
            sub_type: Some(image.sub_type as i32),
            summary: image.summary.clone(),
            ..Default::default()
        };
        let ext = ExtBizInfo {
            pic: Some(PicExtBizInfo {
                text_summary: image.summary.clone(),
                bytes_pb_reserve_c2c: Bytes::from_static(&[
                    0x08, 0x00, 0x18, 0x00, 0x20, 0x00, 0x4A, 0x00, 0x50, 0x00, 0x62, 0x00, 0x92,
                    0x01, 0x00, 0x9A, 0x01, 0x00, 0xAA, 0x01, 0x0C, 0x08, 0x00, 0x12, 0x00, 0x18,
                    0x00, 0x20, 0x00, 0x28, 0x00, 0x3A, 0x00,
                ])
                .into(),
                bytes_pb_reserve_troop: Some(reserve.encode_to_vec().into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.send_request(GroupImageUploadReq {
            group,
            file_info: image.build_file_info()?,
            ext_biz_info: ext,
        })
        .await
    }
}

impl Bot {
    pub async fn upload_private_image(
        &self,
        uin: i64,
        mut image: LocalImage,
    ) -> anyhow::Result<Image> {
        let upload_resp = self
            .service
            .upload_private_image(
                uin,
                self.friends().get_uid_required(uin)?.to_string(),
                &image,
            )
            .await?;
        let mut stream = image
            .stream
            .take()
            .ok_or_else(|| anyhow::anyhow!("stream empty"))?;

        if let Some(ext) = upload_resp.ext {
            self.highway
                .upload(
                    1003,
                    &mut stream,
                    image.size,
                    image.md5,
                    Some(ext.encode_to_vec().into()),
                )
                .await?;
        }

        build_image(image, upload_resp.msg_info, upload_resp.compat_qmsg)
    }

    pub async fn upload_group_image(
        &self,
        group: i64,
        mut image: LocalImage,
    ) -> anyhow::Result<Image> {
        let upload_resp = self.service.upload_group_image(group, &image).await?;
        let mut stream = image
            .stream
            .take()
            .ok_or_else(|| anyhow::anyhow!("stream empty"))?;

        if let Some(ext) = upload_resp.ext {
            self.highway
                .upload(
                    1004,
                    &mut stream,
                    image.size,
                    image.md5,
                    Some(ext.encode_to_vec().into()),
                )
                .await?;
        }

        build_image(image, upload_resp.msg_info, upload_resp.compat_qmsg)
    }
}

fn build_image(
    local_image: LocalImage,
    msg_info: MsgInfo,
    compact: Bytes,
) -> anyhow::Result<Image> {
    let index0 = msg_info
        .msg_info_body
        .first()
        .ok_or_else(|| anyhow::anyhow!("message info body empty"))?
        .index
        .as_ref();
    let image = Image {
        name: index0
            .and_then(|t| t.info.as_ref())
            .and_then(|t| t.file_name.clone())
            .unwrap_or_default(),
        file_uuid: index0.and_then(|t| t.file_uuid.clone()).unwrap_or_default(),
        sub_type: local_image.sub_type,
        summary: local_image.summary.unwrap_or_default(),
        md5: local_image.md5,
        sha1: local_image.sha1,
        width: local_image.width,
        height: local_image.height,
        msg_info: msg_info.into(),
        compact,
    };
    Ok(image)
}
