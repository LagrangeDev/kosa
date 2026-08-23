use bytes::Bytes;
use kosa_macros::command;

use crate::{
    common::{AppInfo, Protocol, Session},
    service::{EncryptType, Metadata, RequestType, ServiceContext, ServiceRequest},
};

#[command("Heartbeat.Alive")]
pub(crate) struct AliveEventReq;
pub(crate) struct AliveEventResp;

impl ServiceRequest for AliveEventReq {
    type Response = AliveEventResp;
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::None,
        request_type: RequestType::Simple,
        support_protocols: Protocol::all(),
    };

    fn encode(_req: Self, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<Bytes> {
        Ok(Bytes::from_static(&[0x00, 0x00, 0x00, 0x04]))
    }

    fn decode(
        _data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Self::Response> {
        Ok(AliveEventResp {})
    }
}

impl ServiceContext {
    pub(crate) async fn heart_beat(&self) -> anyhow::Result<()> {
        let _resp = self.send_request(AliveEventReq).await?;
        Ok(())
    }
}
