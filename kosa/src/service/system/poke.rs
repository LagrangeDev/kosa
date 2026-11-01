use bytes::Bytes;
use kosa_macros::oidb_command;
use kosa_proto::service::v2::Ded3ReqBody;
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Target},
    service::{OidbServiceRequest, ServiceContext},
};

#[oidb_command(0xed3, 1)]
struct PokeReq(Target);

struct GroupPokeResp;

impl OidbServiceRequest for PokeReq {
    type Response = GroupPokeResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        let req = match req.0 {
            Target::Private(uin) => Ded3ReqBody {
                to_uin: Some(uin),
                aio_uin: Some(uin),
                ..Default::default()
            },
            Target::Group { group, uin } => Ded3ReqBody {
                to_uin: Some(uin),
                group_code: Some(group),
                ..Default::default()
            },
        };
        Ok(req.encode_to_vec().into())
    }

    fn decode(
        _data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        Ok(GroupPokeResp)
    }
}

impl ServiceContext {
    pub async fn send_group_poke(&self, group: i64, uin: i64) -> anyhow::Result<()> {
        let _resp = self
            .send_request(PokeReq(Target::Group { group, uin }))
            .await?;
        Ok(())
    }

    pub async fn send_friend_poke(&self, uin: i64) -> anyhow::Result<()> {
        let _resp = self.send_request(PokeReq(Target::Private(uin))).await?;
        Ok(())
    }
}

impl Bot {
    /// 戳一戳群友
    pub async fn send_group_poke(&self, group: i64, uin: i64) -> anyhow::Result<()> {
        self.service.send_group_poke(group, uin).await
    }

    /// 戳一戳好友
    pub async fn send_friend_poke(&self, uin: i64) -> anyhow::Result<()> {
        self.service.send_friend_poke(uin).await
    }
}
