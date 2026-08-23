use arcstr::ArcStr;
use bytes::Bytes;
use chrono::DateTime;
use kosa_macros::oidb_command;
use kosa_proto::service::v2::{
    FetchGroupMembersRequest, FetchGroupMembersRequestBody, FetchGroupMembersResponse,
};
use prost::Message;

use crate::{
    common::{
        AppInfo, Bot, Protocol, Session,
        entity::{GroupMember, GroupPermission},
    },
    service::{OidbServiceRequest, ServiceContext},
};

#[oidb_command(0xfe7, 3)]
pub(crate) struct FetchMemberReq {
    pub(crate) group: i64,
    pub(crate) cookie: Bytes,
}

pub(crate) struct FetchMemberResp {
    pub(crate) members: Vec<GroupMember>,
    pub(crate) cookie: Bytes,
}

impl OidbServiceRequest for FetchMemberReq {
    type Response = FetchMemberResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        let req = FetchGroupMembersRequest {
            group_uin: Some(req.group),
            field2: Some(5),
            field3: Some(2),
            body: Some(FetchGroupMembersRequestBody {
                member_name: Some(true),
                member_card: Some(true),
                level: Some(true),
                special_title: Some(true),
                join_timestamp: Some(true),
                last_msg_timestamp: Some(true),
                shut_up_timestamp: Some(true),
                permission: Some(true),
                ..Default::default()
            }),
            cookie: Some(req.cookie),
        };
        Ok(req.encode_to_vec().into())
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        let resp = FetchGroupMembersResponse::decode(data)?;

        let members = resp
            .members
            .into_iter()
            .map(|member| {
                let timestamp = |secs: Option<u32>| {
                    DateTime::from_timestamp_secs(secs.unwrap_or_default() as i64)
                        .ok_or_else(|| anyhow::anyhow!("invalid member timestamp"))
                };
                let id = member.id.unwrap_or_default();
                let member_card = member.member_card.unwrap_or_default();
                let level = member.level.unwrap_or_default();

                Ok(GroupMember {
                    uin: id.uin.unwrap_or_default() as i64,
                    uid: ArcStr::from(id.uid.unwrap_or_default()),
                    nick_name: ArcStr::from(member.member_name.unwrap_or_default()),
                    member_card: member_card.member_card.unwrap_or_default(),
                    special_title: member.special_title.unwrap_or_default(),
                    level: level.level.unwrap_or_default() as i32,
                    permission: GroupPermission::from(member.permission.unwrap_or_default() as i32),
                    join_time: timestamp(member.join_timestamp)?,
                    last_msg_time: timestamp(member.last_msg_timestamp)?,
                    shutup_time: timestamp(member.shut_up_timestamp)?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>();

        Ok(FetchMemberResp {
            members: members?,
            cookie: resp.cookie.unwrap_or_default(),
        })
    }
}

impl ServiceContext {
    pub async fn fetch_members(&self, group: i64) -> anyhow::Result<Vec<GroupMember>> {
        let mut members = Vec::new();
        let mut cookie: Bytes = Bytes::default();
        loop {
            let resp = self
                .send_request(FetchMemberReq {
                    group,
                    cookie: cookie.clone(),
                })
                .await?;
            cookie = resp.cookie;
            members.extend(resp.members);
            if cookie.is_empty() {
                break;
            }
        }
        Ok(members)
    }
}

impl Bot {
    /// 获取群成员列表
    pub async fn fetch_members(&self, group: i64) -> anyhow::Result<Vec<GroupMember>> {
        self.service.fetch_members(group).await
    }
}
