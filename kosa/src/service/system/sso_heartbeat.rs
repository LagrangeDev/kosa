use bytes::Bytes;
use chrono::Utc;
use kosa_macros::command;
use kosa_proto::system::v2::{SilenceState, SsoHeartBeatRequest, SsoHeartBeatResponse};
use prost::Message;

use crate::{
    common::{AppInfo, Protocol, Session},
    service::{EncryptType, Metadata, RequestType, ServiceContext, ServiceRequest},
};

#[command("trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat")]
pub(crate) struct SsoHeartBeatEventReq;
pub(crate) struct SsoHeartBeatEventResp {
    _interval: i32,
}

impl ServiceRequest for SsoHeartBeatEventReq {
    type Response = SsoHeartBeatEventResp;
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::D2,
        request_type: RequestType::D2Auth,
        support_protocols: Protocol::all(),
    };

    fn encode(_req: Self, app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        match app_info.protocol {
            protocol if Protocol::PC.contains(protocol) => Ok(SsoHeartBeatRequest {
                r#type: Some(1),
                ..Default::default()
            }
            .encode_to_vec()
            .into()),
            protocol if Protocol::ANDROID.contains(protocol) => Ok(SsoHeartBeatRequest {
                r#type: Some(1),
                time: Some(Utc::now().timestamp_millis() as u64),
                local_silence: Some(SilenceState {
                    local_silence: Some(1),
                }),
                ..Default::default()
            }
            .encode_to_vec()
            .into()),
            _ => {
                unimplemented!()
            }
        }
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        let resp = SsoHeartBeatResponse::decode(data)?;
        Ok(SsoHeartBeatEventResp {
            _interval: resp.interval.unwrap_or_default() as i32,
        })
    }
}

impl ServiceContext {
    pub async fn sso_heartbeat(&self) -> anyhow::Result<()> {
        let _resp = self.send_request(SsoHeartBeatEventReq).await?;
        Ok(())
    }
}
