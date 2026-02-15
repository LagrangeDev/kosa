use bytes::Bytes;
use kosa_macros::{ServiceState, command, register_service};

use crate::{
    common::{AppInfo, Protocol, Session},
    service::{EncryptType, Metadata, RequestType, Service, ServiceContext},
};

#[command("Heartbeat.Alive")]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct AliveService;
pub(crate) struct AliveEventReq;
pub(crate) struct AliveEventResp;

#[register_service]
impl Service<AliveEventReq, AliveEventResp> for AliveService {
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::None,
        request_type: RequestType::Simple,
        support_protocols: Protocol::all(),
    };

    fn build(
        _state: &Self,
        _req: AliveEventReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        Ok(Bytes::from_static(&[0x00, 0x00, 0x00, 0x04]))
    }

    fn parse(
        _state: &Self,
        _data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<AliveEventResp> {
        Ok(AliveEventResp {})
    }
}

impl ServiceContext {
    pub(crate) async fn heart_beat(&self) -> anyhow::Result<()> {
        let _resp = self
            .send_request::<AliveService, AliveEventReq, AliveEventResp>(AliveEventReq)
            .await?;
        Ok(())
    }
}
