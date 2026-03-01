use std::net::Ipv4Addr;

use bytes::Bytes;
use kosa_proto::service::highway::v2::{
    C2cUserInfo, ClientMeta, CommonHead, ExtBizInfo, FileInfo, GroupInfo, MultiMediaReqHead,
    NtHighwayDomain, NtHighwayHash, NtHighwayIPv4, NtHighwayNetwork, Ntv2RichMediaHighwayExt,
    Ntv2RichMediaReq, SceneInfo, UploadInfo, UploadReq, UploadResp,
};

use crate::{
    common::{entity::Scene, highway::BLOCK_SIZE},
    message::RichMedia,
};

pub(crate) fn build_upload_request<M: RichMedia>(
    scene: Scene,
    file_info: FileInfo,
    ext_biz_info: ExtBizInfo,
) -> anyhow::Result<Ntv2RichMediaReq> {
    let req = Ntv2RichMediaReq {
        req_head: Some(build_head::<M>(100, scene)),
        upload: Some(UploadReq {
            upload_info: vec![UploadInfo {
                file_info: Some(file_info),
                sub_file_type: Some(0),
            }],
            try_fast_upload_completed: Some(true),
            srv_send_msg: Some(false),
            client_random_id: Some(rand::random()),
            compat_q_msg_scene_type: Some(1),
            client_seq: Some(10),
            ext_biz_info: Some(ext_biz_info),
            no_need_compat_msg: Some(false),
        }),
        ..Default::default()
    };
    Ok(req)
}

pub(crate) fn build_head<M: RichMedia>(cmd: u32, scene: Scene) -> MultiMediaReqHead {
    MultiMediaReqHead {
        common: Some(CommonHead {
            request_id: Some(1),
            command: Some(cmd),
        }),
        scene: Some(build_scene_info(scene, M::REQUEST_TYPE, M::BUSINESS_TYPE)),
        client: Some(ClientMeta {
            agent_type: Some(2),
        }),
    }
}

pub(crate) fn build_scene_info(scene: Scene, request_type: u32, business_type: u32) -> SceneInfo {
    let mut scene_info = SceneInfo {
        request_type: Some(request_type),
        business_type: Some(business_type),
        ..Default::default()
    };
    match scene {
        Scene::Private(_uin, uid) => {
            scene_info.scene_type = Some(1);
            scene_info.c2c = Some(C2cUserInfo {
                target_uid: Some(uid),
                account_type: Some(2),
            });
        }
        Scene::Group(uin) => {
            scene_info.scene_type = Some(2);
            scene_info.group = Some(GroupInfo {
                group_uin: Some(uin),
            })
        }
    };
    scene_info
}

pub(crate) fn gen_ext(upload_resp: UploadResp) -> Option<Ntv2RichMediaHighwayExt> {
    match upload_resp.u_key {
        None => None,
        Some(ukey) => {
            let msg_info = upload_resp.msg_info?;
            let index = msg_info.msg_info_body[0].index.as_ref();
            let sha1: Bytes = hex::decode(
                index
                    .and_then(|t| t.info.as_ref())
                    .map(|t| t.file_sha1())
                    .unwrap(),
            )
            .unwrap()
            .into();
            Some(Ntv2RichMediaHighwayExt {
                file_uuid: index?.file_uuid.clone(),
                u_key: Some(ukey),
                network: Some(NtHighwayNetwork {
                    ipv4s: upload_resp
                        .ipv4s
                        .iter()
                        .map(|x| NtHighwayIPv4 {
                            domain: Some(NtHighwayDomain {
                                is_enable: Some(true),
                                ip: Some(
                                    Ipv4Addr::from(x.out_ip.unwrap().to_le_bytes()).to_string(),
                                ),
                            }),
                            port: x.out_port,
                        })
                        .collect(),
                }),
                msg_info_body: msg_info.msg_info_body,
                block_size: Some(BLOCK_SIZE as u32),
                hash: Some(NtHighwayHash {
                    file_sha1: vec![sha1],
                }),
            })
        }
    }
}
