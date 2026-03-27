use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::service::v2::{
    FetchGroupsRequest, FetchGroupsRequestConfig, FetchGroupsRequestConfig1,
    FetchGroupsRequestConfig2, FetchGroupsRequestConfig3, FetchGroupsResponse,
};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Group},
    service::{OidbService, ServiceContext},
};

#[oidb_command(0xfe5, 2)]
#[derive(Debug, Default, ServiceState)]
struct FetchGroupService;

struct FetchGroupReq;

struct FetchGroupResp {
    groups: Vec<Group>,
}

#[register_oidb_service]
impl OidbService<FetchGroupReq, FetchGroupResp> for FetchGroupService {
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        _req: FetchGroupReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        let req = FetchGroupsRequest {
            config: Some(FetchGroupsRequestConfig {
                config1: Some(FetchGroupsRequestConfig1 {
                    group_owner: Some(true),
                    field2: Some(true),
                    member_max: Some(true),
                    member_count: Some(true),
                    group_name: Some(true),
                    field8: Some(true),
                    field9: Some(true),
                    field10: Some(true),
                    field11: Some(true),
                    field12: Some(true),
                    field13: Some(true),
                    field14: Some(true),
                    field15: Some(true),
                    field16: Some(true),
                    field17: Some(true),
                    field18: Some(true),
                    question: Some(true),
                    field20: Some(true),
                    field22: Some(true),
                    field23: Some(true),
                    field24: Some(true),
                    field25: Some(true),
                    field26: Some(true),
                    field27: Some(true),
                    field28: Some(true),
                    field29: Some(true),
                    field30: Some(true),
                    field31: Some(true),
                    field32: Some(true),
                    field5001: Some(true),
                    field5002: Some(true),
                    field5003: Some(true),
                }),
                config2: Some(FetchGroupsRequestConfig2 {
                    field1: Some(true),
                    field2: Some(true),
                    field3: Some(true),
                    field4: Some(true),
                    field5: Some(true),
                    field6: Some(true),
                    field7: Some(true),
                    field8: Some(true),
                }),
                config3: Some(FetchGroupsRequestConfig3 {
                    field5: Some(true),
                    field6: Some(true),
                }),
            }),
        };
        Ok(req.encode_to_vec().into())
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<FetchGroupResp> {
        let resp = FetchGroupsResponse::decode(data)?;

        let groups: Vec<Group> = resp
            .groups
            .into_iter()
            .map(|group| {
                let info = group.info.unwrap_or_default();
                Group {
                    uin: group.group_uin.unwrap_or_default(),
                    name: info.group_name().to_string(),
                    member_count: info.member_count() as i32,
                    max_member_count: info.member_max() as i32,
                    create_time: info.created_time() as i64,
                    description: info.description().to_string(),
                    question: info.question().to_string(),
                    announcement: info.announcement().to_string(),
                }
            })
            .collect();
        Ok(FetchGroupResp { groups })
    }
}

impl ServiceContext {
    pub async fn fetch_groups(&self) -> anyhow::Result<Vec<Group>> {
        let resp = self
            .send_request::<FetchGroupService, FetchGroupReq, FetchGroupResp>(FetchGroupReq)
            .await?;
        Ok(resp.groups)
    }
}

impl Bot {
    /// 获取群列表
    pub async fn fetch_groups(&self) -> anyhow::Result<Vec<Group>> {
        self.service.fetch_groups().await
    }
}
