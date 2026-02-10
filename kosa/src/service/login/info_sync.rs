use std::{collections::HashMap, sync::atomic::Ordering, time::Duration};

use bytes::Bytes;
use kosa_macros::{ServiceState, command, register_service};
use kosa_proto::system::v2::{
    CurAppState, DeviceInfo, NormalConfig, OnlineBusinessInfo, RegisterInfo, SsoC2cMsgCookie,
    SsoC2cSyncInfo, SsoInfoSyncRequest, SsoSyncInfoResponse,
};
use prost::Message;
use tokio::time;

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
            sync_flag: 735,
            req_random: rand::random(),
            cur_active_status: 2,
            group_last_msg_time: 0,
            c2_c_sync_info: Some(SsoC2cSyncInfo {
                c2_c_msg_cookie: Some(SsoC2cMsgCookie {
                    c2_c_last_msg_time: 0,
                }),
                c2_c_last_msg_time: 0,
                last_c2_c_msg_cookie: Some(SsoC2cMsgCookie {
                    c2_c_last_msg_time: 0,
                }),
            }),
            normal_config: Some(NormalConfig {
                int_cfg: HashMap::new(),
            }),
            register_info: Some(RegisterInfo {
                guid: hex::encode_upper(session.guid.as_slice()),
                kick_pc: 0,
                build_ver: app_info.current_version.clone(),
                is_first_register_proxy_online: 1,
                locale_id: 2052,
                device_info: Some(DeviceInfo {
                    dev_name: session.device_name.clone(),
                    dev_type: app_info.kernel.clone(),
                    os_ver: "".to_string(),
                    brand: "".to_string(),
                    vendor_os_name: app_info.vendor_os.clone(),
                }),
                set_mute: 0,
                register_vendor_type: 6,
                reg_type: 0,
                business_info: Some(OnlineBusinessInfo {
                    notify_switch: 1,
                    bind_uin_notify_switch: 1,
                }),
                battery_status: 0,
                field12: Some(1),
            }),
            unknown: HashMap::from_iter([(0, 2)]),
            app_state: Some(CurAppState {
                is_delay_request: 0,
                app_status: 0,
                silence_status: 0,
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
        let msg = resp.register_response.unwrap_or_default().msg;
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
            self.online.store(true, Ordering::SeqCst);
            let service = self.service.clone();

            tokio::spawn(async move {
                // todo 心跳包
                let mut interval = time::interval(Duration::from_secs(180));

                interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

                loop {
                    let _ = service.heart_beat().await;
                    interval.tick().await;
                }
            });

            Ok(())
        } else {
            Err(anyhow::anyhow!("online failed: {}", resp.message))
        }
    }
}
