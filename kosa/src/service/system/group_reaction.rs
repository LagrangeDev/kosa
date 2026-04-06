use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::service::v2::SetGroupMessageReactionReq;
use prost::Message;

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
    pub(crate) reaction: Reaction,
}

pub(crate) struct GroupReactionResp;

#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Reaction {
    FACE(u32),
    EMOJI(String),
}

impl Reaction {
    pub fn code(self) -> String {
        match self {
            Reaction::FACE(face_id) => face_id.to_string(),
            Reaction::EMOJI(emoji) => emoji,
        }
    }

    pub fn r#type(&self) -> u32 {
        match self {
            Reaction::FACE(_) => 1,
            Reaction::EMOJI(_) => 2,
        }
    }
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
            r#type: Some(req.reaction.r#type()),
            code: Some(req.reaction.code()),
        };
        Ok(req.encode_to_vec().into())
    }

    fn parse(
        _state: &Self,
        _data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<GroupReactionResp> {
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
            r#type: Some(req.reaction.r#type()),
            code: Some(req.reaction.code()),
        };
        Ok(req.encode_to_vec().into())
    }

    fn parse(
        _state: &Self,
        _data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<GroupReactionResp> {
        Ok(GroupReactionResp)
    }
}

impl ServiceContext {
    pub async fn add_group_reaction(
        &self,
        group: i64,
        seq: i32,
        reaction: Reaction,
    ) -> anyhow::Result<()> {
        let _resp = self
            .send_request::<GroupAddReactionService, GroupReactionReq, GroupReactionResp>(
                GroupReactionReq {
                    group_uin: group,
                    sequence: seq,
                    reaction,
                },
            )
            .await?;
        Ok(())
    }

    pub async fn remove_group_reaction(
        &self,
        group: i64,
        seq: i32,
        reaction: Reaction,
    ) -> anyhow::Result<()> {
        let _resp = self
            .send_request::<GroupRemoveReactionService, GroupReactionReq, GroupReactionResp>(
                GroupReactionReq {
                    group_uin: group,
                    sequence: seq,
                    reaction,
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
        reaction: Reaction,
    ) -> anyhow::Result<()> {
        self.service.add_group_reaction(group, seq, reaction).await
    }

    /// 移除群消息回应
    pub async fn remove_group_reaction(
        &self,
        group: i64,
        seq: i32,
        reaction: Reaction,
    ) -> anyhow::Result<()> {
        self.service
            .remove_group_reaction(group, seq, reaction)
            .await
    }
}
