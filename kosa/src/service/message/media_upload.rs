use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::service::highway::v2::{
    ExtBizInfo, FileInfo, MsgInfo, Ntv2RichMediaHighwayExt, Ntv2RichMediaResp,
};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    message::{Image, LocalImage, RichMedia},
    service::{
        OidbService, ServiceContext,
        packet::nt_v2_richmedia::{build_upload_request, gen_ext},
    },
};

#[oidb_command(0x11c5, 100)]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct PrivateImageUploadService;

#[derive(Debug)]
pub(crate) struct PrivateImageUploadReq {
    file_info: FileInfo,
    ext_biz_info: ExtBizInfo,
    scene: Scene,
}

#[derive(Debug)]
pub(crate) struct PrivateImageUploadResp {
    msg_info: MsgInfo,
    compat_qmsg: Bytes,
    ext: Option<Ntv2RichMediaHighwayExt>,
}

#[register_oidb_service]
impl OidbService<PrivateImageUploadReq, PrivateImageUploadResp> for PrivateImageUploadService {
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: PrivateImageUploadReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        Ok(
            build_upload_request::<LocalImage>(req.scene, req.file_info, req.ext_biz_info)?
                .encode_to_vec()
                .into(),
        )
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<PrivateImageUploadResp> {
        let resp = Ntv2RichMediaResp::decode(data)?;
        let upload = resp
            .upload
            .ok_or_else(|| anyhow::anyhow!("empty upload response"))?;
        Ok(PrivateImageUploadResp {
            ext: gen_ext(upload.clone()),
            msg_info: upload.msg_info.unwrap_or_default(),
            compat_qmsg: upload.compat_q_msg.unwrap_or_default(),
        })
    }
}

impl ServiceContext {
    pub(crate) async fn upload_private_image(
        &self,
        uin: i64,
        uid: String,
        image: &LocalImage,
    ) -> anyhow::Result<PrivateImageUploadResp> {
        self.send_request::<PrivateImageUploadService,PrivateImageUploadReq,PrivateImageUploadResp>(PrivateImageUploadReq{
            scene:Scene::Private(uin,uid),
            file_info:image.build_file_info()?,
            ext_biz_info:image.build_ext_info()?
        }).await
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
                self.cache.get_uid(uin).ok_or_else(|| anyhow::anyhow!(""))?,
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

        let index0 = upload_resp.msg_info.msg_info_body[0].index.as_ref();

        let image = Image {
            name: index0
                .and_then(|t| t.info.as_ref())
                .and_then(|t| t.file_name.clone())
                .unwrap_or_default(),
            file_uuid: index0.and_then(|t| t.file_uuid.clone()).unwrap_or_default(),
            sub_type: image.sub_type,
            summary: image.summary.unwrap_or_default(),
            md5: image.md5,
            sha1: image.sha1,
            width: image.width,
            height: image.height,
            msg_info: upload_resp.msg_info,
            compact: upload_resp.compat_qmsg,
        };
        Ok(image)
    }
}
