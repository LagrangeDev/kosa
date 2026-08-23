use bytes::Bytes;
use kosa_proto::service::v2::Oidb;
use prost::Message;
use thiserror::Error;

use crate::{
    common::{AppInfo, Protocol, Session},
    service::{EncryptType, Metadata, RequestType, ServiceRequest},
    utils::marker::CommandMarker,
};

#[derive(Debug, Error)]
#[error("oidb error (code: {code}): {message}")]
pub struct OidbError {
    pub code: u32,
    pub message: String,
}

pub(crate) fn encode(command: u32, service: u32, reserved: u32, req: Bytes) -> Bytes {
    let oidb = Oidb {
        command: Some(command),
        service: Some(service),
        body: Some(req),
        reserved: Some(reserved),
        ..Default::default()
    };
    oidb.encode_to_vec().into()
}

pub(crate) fn decode(data: Bytes) -> anyhow::Result<Bytes> {
    let oidb = Oidb::decode(data)?;
    if oidb.result.unwrap_or_default() != 0 {
        anyhow::bail!(OidbError {
            code: oidb.result.unwrap_or_default(),
            message: oidb.message.unwrap_or_default(),
        })
    };
    Ok(oidb.body.unwrap_or_default())
}

pub trait OidbCommandMarker: CommandMarker {
    const COMMAND: u32;
    const SERVICE: u32;
    const RESERVED: u32 = 0;
}

pub trait OidbServiceRequest: OidbCommandMarker + Send + 'static {
    type Response: Send + 'static;
    const SUPPORT_PROTOCOLS: Protocol;

    fn encode(req: Self, app_info: &AppInfo, session: &Session) -> anyhow::Result<Bytes>;
    fn decode(data: Bytes, app_info: &AppInfo, session: &Session)
    -> anyhow::Result<Self::Response>;
}

impl<T: OidbServiceRequest> ServiceRequest for T {
    type Response = T::Response;
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::D2,
        request_type: RequestType::D2Auth,
        support_protocols: T::SUPPORT_PROTOCOLS,
    };

    fn encode(req: Self, app_info: &AppInfo, session: &Session) -> anyhow::Result<Bytes> {
        let oidb_data = T::encode(req, app_info, session)?;
        let data = encode(
            <T as OidbCommandMarker>::COMMAND,
            T::SERVICE,
            T::RESERVED,
            oidb_data,
        );
        Ok(data)
    }

    fn decode(
        data: Bytes,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Self::Response> {
        let oidb_data = decode(data)?;
        T::decode(oidb_data, app_info, session)
    }
}
