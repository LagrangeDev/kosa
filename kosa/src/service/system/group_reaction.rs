use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::service::v2::SetGroupMessageReactionReq;
use prost::Message;
use tracing::info;

use crate::{
    common::{AppInfo, Bot, Protocol, Session},
    service::{OidbService, ServiceContext},
};

#[oidb_command(0x9082, 1)]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct GroupAddReactionService;

#[oidb_command(0x9082, 2)]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct GroupRemoveReactionService;

pub(crate) struct GroupReactionReq {
    pub(crate) group_uin: i64,
    pub(crate) sequence: i32,
    pub(crate) code: String,
    pub(crate) r#type: ReactionType,
}

pub(crate) struct GroupReactionResp;

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ReactionType {
    FACE = 1,
    EMOJI = 2,
}

#[register_oidb_service]
impl OidbService<GroupReactionReq, GroupReactionResp> for GroupAddReactionService {
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: GroupReactionReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        let req = SetGroupMessageReactionReq {
            group_uin: Some(req.group_uin),
            sequence: Some(req.sequence as u32),
            code: Some(req.code),
            r#type: Some(req.r#type as u32),
        };
        Ok(req.encode_to_vec().into())
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<GroupReactionResp> {
        info!("resp: {}", hex::encode(&data));
        Ok(GroupReactionResp)
    }
}

#[register_oidb_service]
impl OidbService<GroupReactionReq, GroupReactionResp> for GroupRemoveReactionService {
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: GroupReactionReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        let req = SetGroupMessageReactionReq {
            group_uin: Some(req.group_uin),
            sequence: Some(req.sequence as u32),
            code: Some(req.code),
            r#type: Some(req.r#type as u32),
        };
        Ok(req.encode_to_vec().into())
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<GroupReactionResp> {
        info!("resp: {}", hex::encode(&data));
        Ok(GroupReactionResp)
    }
}

impl ServiceContext {
    pub async fn add_group_reaction(
        &self,
        group: i64,
        seq: i32,
        face_id: i32,
        r#type: ReactionType,
    ) -> anyhow::Result<()> {
        let _resp = self
            .send_request::<GroupAddReactionService, GroupReactionReq, GroupReactionResp>(
                GroupReactionReq {
                    group_uin: group,
                    sequence: seq,
                    code: face_id.to_string(),
                    r#type,
                },
            )
            .await?;
        Ok(())
    }

    pub async fn remove_group_reaction(
        &self,
        group: i64,
        seq: i32,
        face_id: i32,
        r#type: ReactionType,
    ) -> anyhow::Result<()> {
        let _resp = self
            .send_request::<GroupRemoveReactionService, GroupReactionReq, GroupReactionResp>(
                GroupReactionReq {
                    group_uin: group,
                    sequence: seq,
                    code: face_id.to_string(),
                    r#type,
                },
            )
            .await?;
        Ok(())
    }
}

impl Bot {
    /// 添加群消息回应
    pub async fn add_group_reaction(
        &self,
        group: i64,
        seq: i32,
        face_id: i32,
        r#type: ReactionType,
    ) -> anyhow::Result<()> {
        self.service
            .add_group_reaction(group, seq, face_id, r#type)
            .await
    }

    /// 移除群消息回应
    pub async fn remove_group_reaction(
        &self,
        group: i64,
        seq: i32,
        face_id: i32,
        r#type: ReactionType,
    ) -> anyhow::Result<()> {
        self.service
            .remove_group_reaction(group, seq, face_id, r#type)
            .await
    }
}
