use bytes::Bytes;
use kosa_macros::oidb_command;
use kosa_proto::service::v2::SetGroupReactionRequest;
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session},
    service::{OidbServiceRequest, ServiceContext},
};

#[oidb_command(0x9082, 1)]
pub(crate) struct GroupAddReactionReq(GroupReactionReq);

#[oidb_command(0x9082, 2)]
pub(crate) struct GroupRemoveReactionReq(GroupReactionReq);

pub(crate) struct GroupReactionReq {
    pub(crate) group_uin: i64,
    pub(crate) sequence: u64,
    pub(crate) reaction: Reaction,
}

impl GroupReactionReq {
    fn build(self) -> SetGroupReactionRequest {
        SetGroupReactionRequest {
            group_uin: Some(self.group_uin),
            sequence: Some(self.sequence),
            r#type: Some(self.reaction.r#type()),
            code: Some(self.reaction.code()),
        }
    }
}

pub(crate) struct GroupReactionResp;

/// 消息表态
///
/// FACE是qq自带的小表情，EMOJI就是系统的emoji
///
/// example
/// ```
/// use kosa::service::system::Reaction;
///
/// Reaction::FACE(35);
/// Reaction::EMOJI('😰');
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Reaction {
    FACE(u32),
    EMOJI(char),
}

impl Reaction {
    pub fn code(self) -> String {
        match self {
            Reaction::FACE(face_id) => face_id.to_string(),
            Reaction::EMOJI(emoji) => (emoji as u32).to_string(),
        }
    }

    pub fn r#type(&self) -> u64 {
        match self {
            Reaction::FACE(_) => 1,
            Reaction::EMOJI(_) => 2,
        }
    }
}

impl OidbServiceRequest for GroupAddReactionReq {
    type Response = GroupReactionResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(req.0.build().encode_to_vec().into())
    }

    fn decode(
        _data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        Ok(GroupReactionResp)
    }
}

impl OidbServiceRequest for GroupRemoveReactionReq {
    type Response = GroupReactionResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(req.0.build().encode_to_vec().into())
    }

    fn decode(
        _data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        Ok(GroupReactionResp)
    }
}

impl ServiceContext {
    pub async fn add_group_reaction(
        &self,
        group: i64,
        seq: u64,
        reaction: Reaction,
    ) -> anyhow::Result<()> {
        let _resp = self
            .send_request(GroupAddReactionReq(GroupReactionReq {
                group_uin: group,
                sequence: seq,
                reaction,
            }))
            .await?;
        Ok(())
    }

    pub async fn remove_group_reaction(
        &self,
        group: i64,
        seq: u64,
        reaction: Reaction,
    ) -> anyhow::Result<()> {
        let _resp = self
            .send_request(GroupRemoveReactionReq(GroupReactionReq {
                group_uin: group,
                sequence: seq,
                reaction,
            }))
            .await?;
        Ok(())
    }
}

impl Bot {
    /// 添加群消息回应
    pub async fn add_group_reaction(
        &self,
        group: i64,
        seq: u64,
        reaction: Reaction,
    ) -> anyhow::Result<()> {
        self.service.add_group_reaction(group, seq, reaction).await
    }

    /// 移除群消息回应
    pub async fn remove_group_reaction(
        &self,
        group: i64,
        seq: u64,
        reaction: Reaction,
    ) -> anyhow::Result<()> {
        self.service
            .remove_group_reaction(group, seq, reaction)
            .await
    }
}
