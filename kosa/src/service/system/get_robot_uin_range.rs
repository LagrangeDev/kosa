use bytes::Bytes;
use kosa_macros::oidb_command;
use kosa_proto::service::v2::{RobotUinRangeReq, RobotUinRangeResp};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session},
    service::{OidbServiceRequest, ServiceContext},
};

#[oidb_command(0x496, 0, reserved = 1)]
struct GetRobotUinRangeReq;

struct GetRobotUinRangeResp {
    ranges: Vec<(i64, i64)>,
}

impl OidbServiceRequest for GetRobotUinRangeReq {
    type Response = GetRobotUinRangeResp;
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn encode(_req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        let req = RobotUinRangeReq {
            just_fetch_msg_config: Some(1),
            r#type: Some(1),
            version: Some(0),
            aio_keyword_version: Some(0),
        };
        Ok(req.encode_to_vec().into())
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        let resp = RobotUinRangeResp::decode(data)?;
        let ranges = resp
            .robot_config
            .map(|config| config.robot_uin_ranges)
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                let min = r.min_uin.ok_or(anyhow::anyhow!("min_uin is missing"))? as i64;
                let max = r.max_uin.ok_or(anyhow::anyhow!("max_uin is missing"))? as i64;

                Ok((min, max))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(GetRobotUinRangeResp { ranges })
    }
}

impl ServiceContext {
    pub async fn get_robot_uin_range(&self) -> anyhow::Result<Vec<(i64, i64)>> {
        let resp = self.send_request(GetRobotUinRangeReq).await?;
        Ok(resp.ranges)
    }
}

impl Bot {
    pub async fn get_robot_uin_range(&self) -> anyhow::Result<Vec<(i64, i64)>> {
        self.service.get_robot_uin_range().await
    }
}
