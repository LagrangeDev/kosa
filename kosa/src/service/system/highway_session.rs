use std::net::Ipv4Addr;

use ahash::AHashMap;
use bytes::Bytes;
use kosa_macros::{ServiceState, command, register_service};
use kosa_proto::service::v2::{C501ReqBody, C501RspBody, SubCmd0x501ReqBody};
use prost::Message;
use reqwest::Url;

use crate::{
    common::{AppInfo, Protocol, Session},
    service::{EncryptType, Metadata, RequestType, Service, ServiceContext},
};

#[command("HttpConn.0x6ff_501")]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct HighwaySessionService;

pub(crate) struct HighwaySessionReq;

pub(crate) struct HighwaySessionResp {
    pub(crate) servers: AHashMap<u32, Vec<Url>>,
    pub(crate) sig_session: Bytes,
}

#[register_service]
impl Service<HighwaySessionReq, HighwaySessionResp> for HighwaySessionService {
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::D2,
        request_type: RequestType::D2Auth,
        support_protocols: Protocol::all(),
    };

    fn build(
        _state: &Self,
        _req: HighwaySessionReq,
        _app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Bytes> {
        Ok(C501ReqBody {
            req_body: Some(SubCmd0x501ReqBody {
                uin: Some(0),
                idc_id: Some(0),
                appid: Some(16),
                login_sig_type: Some(0),
                login_sig_ticket: Some(session.wlogin_sigs.load().a2.clone()),
                request_flag: Some(3),
                service_types: [1, 5, 10, 21].to_vec(),
                field9: Some(2),
                field10: Some(9),
                field11: Some(8),
                version: Some("1.0.1".to_string()),
                ..Default::default()
            }),
        }
        .encode_to_vec()
        .into())
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<HighwaySessionResp> {
        let resp = C501RspBody::decode(data)?;
        if let Some(body) = resp.rsp_body {
            let mut servers: AHashMap<u32, Vec<Url>> = AHashMap::with_capacity(body.addrs.len());
            for srv_addr in body.addrs {
                let mut addresses = Vec::with_capacity(srv_addr.addrs.len());
                for addr in srv_addr.addrs {
                    let ip = Ipv4Addr::from(addr.ip.unwrap_or_default().to_le_bytes());
                    addresses.push(Url::parse(
                        format!(
                            "http://{}:{}/cgi-bin/httpconn?htcmd=0x6FF0087&uin={}",
                            ip,
                            addr.port.unwrap_or_default(),
                            session.uin()
                        )
                        .as_str(),
                    )?)
                }
                servers.insert(srv_addr.service_type.unwrap_or_default(), addresses);
            }
            Ok(HighwaySessionResp {
                servers,
                sig_session: body.sig_session.unwrap_or_default(),
            })
        } else {
            Err(anyhow::anyhow!("body is empty"))
        }
    }
}

impl ServiceContext {
    pub(crate) async fn get_highway_ticket(&self) -> anyhow::Result<HighwaySessionResp> {
        self.send_request::<HighwaySessionService, HighwaySessionReq, HighwaySessionResp>(
            HighwaySessionReq,
        )
        .await
    }
}
