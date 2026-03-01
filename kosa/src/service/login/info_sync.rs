use std::{collections::HashMap, time::Duration};

use bytes::Bytes;
use kosa_macros::{ServiceState, command, register_service};
use kosa_proto::system::v2::{
    CurAppState, DeviceInfo, NormalConfig, OnlineBusinessInfo, RegisterInfo, SsoC2cMsgCookie,
    SsoC2cSyncInfo, SsoInfoSyncRequest, SsoSyncInfoResponse,
};
use prost::Message;
use tokio::time;
use tracing::error;

use crate::{
    common::{AppInfo, Bot, Protocol, Session},
    service::{EncryptType, Metadata, RequestType, Service, ServiceContext},
};

#[command("trpc.msg.register_proxy.RegisterProxy.SsoInfoSync")]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct InfoSyncService;

pub(crate) struct InfoSyncReq;

pub(crate) struct InfoSyncResponse {
    pub(crate) message: String,
}

#[register_service]
impl Service<InfoSyncReq, InfoSyncResponse> for InfoSyncService {
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::D2,
        request_type: RequestType::D2Auth,
        support_protocols: Protocol::all(),
    };

    fn build(
        _state: &Self,
        _req: InfoSyncReq,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Bytes> {
        // todo support android
        let pkt = SsoInfoSyncRequest {
            sync_flag: Some(735),
            req_random: Some(rand::random()),
            cur_active_status: Some(2),
            group_last_msg_time: Some(0),
            c2c_sync_info: Some(SsoC2cSyncInfo {
                c2c_msg_cookie: Some(SsoC2cMsgCookie {
                    c2c_last_msg_time: Some(0),
                }),
                c2c_last_msg_time: Some(0),
                last_c2c_msg_cookie: Some(SsoC2cMsgCookie {
                    c2c_last_msg_time: Some(0),
                }),
            }),
            normal_config: Some(NormalConfig {
                int_cfg: HashMap::new(),
            }),
            register_info: Some(RegisterInfo {
                guid: Some(hex::encode_upper(session.guid.as_slice())),
                kick_pc: Some(0),
                build_ver: Some(app_info.current_version.clone()),
                is_first_register_proxy_online: Some(1),
                locale_id: Some(2052),
                device_info: Some(DeviceInfo {
                    dev_name: Some(session.device_name.clone()),
                    dev_type: Some(app_info.kernel.clone()),
                    os_ver: Some("".to_string()),
                    brand: Some("".to_string()),
                    vendor_os_name: Some(app_info.vendor_os.clone()),
                }),
                set_mute: Some(0),
                register_vendor_type: Some(6),
                reg_type: Some(0),
                business_info: Some(OnlineBusinessInfo {
                    notify_switch: Some(1),
                    bind_uin_notify_switch: Some(1),
                }),
                battery_status: Some(0),
                field12: Some(1),
            }),
            unknown: HashMap::from_iter([(0, 2)]),
            app_state: Some(CurAppState {
                is_delay_request: Some(0),
                app_status: Some(0),
                silence_status: Some(0),
            }),
        };
        Ok(Bytes::from(pkt.encode_to_vec()))
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<InfoSyncResponse> {
        let resp = SsoSyncInfoResponse::decode(data)?;
        let msg = resp
            .register_response
            .unwrap_or_default()
            .msg
            .unwrap_or_default();
        Ok(InfoSyncResponse { message: msg })
    }
}

impl ServiceContext {
    pub(crate) async fn register(&self) -> anyhow::Result<InfoSyncResponse> {
        let resp = self
            .send_request::<InfoSyncService, InfoSyncReq, InfoSyncResponse>(InfoSyncReq)
            .await?;
        Ok(resp)
    }
}

impl Bot {
    pub async fn online(&self) -> anyhow::Result<()> {
        let resp = self.service.register().await?;
        if resp.message == "register success" {
            self.set_online(
                true,
                #[cfg(feature = "opentelemetry")]
                Some(resp.message),
            );
            let service = self.service.clone();

            let handle = tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(270));
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    if let Err(e) = service.sso_heartbeat().await {
                        error!("sso heartbeat failed: {}", e);
                    }
                }
            });
            self.tasks.insert("sso_heartbeat".to_string(), handle);

            Ok(())
        } else {
            Err(anyhow::anyhow!("online failed: {}", resp.message))
        }
    }
}
