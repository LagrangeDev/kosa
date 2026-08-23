mod context;
pub mod login;
pub mod message;
mod oidb;
pub mod packet;
pub mod system;

use std::fmt::Debug;

use bytes::Bytes;
pub(crate) use context::ServiceContext;
pub(crate) use oidb::{OidbCommandMarker, OidbServiceRequest};
use strum::FromRepr;

use crate::{
    common::{AppInfo, Protocol, Session},
    utils::marker::CommandMarker,
};

#[derive(Debug)]
pub struct Metadata {
    pub(crate) encrypt_type: EncryptType,
    pub(crate) request_type: RequestType,
    pub(crate) support_protocols: Protocol,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, FromRepr)]
#[repr(u8)]
pub enum EncryptType {
    None = 0,
    D2 = 1,
    Empty = 2,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, FromRepr)]
#[repr(u8)]
pub enum RequestType {
    /// Protocol12
    D2Auth = 0x0C,
    /// Protocol13
    Simple = 0x0D,
}

pub trait ServiceRequest: CommandMarker + Send + 'static {
    type Response: Send + 'static;
    const METADATA: Metadata;

    fn encode(req: Self, app_info: &AppInfo, session: &Session) -> anyhow::Result<Bytes>;
    fn decode(data: Bytes, app_info: &AppInfo, session: &Session)
    -> anyhow::Result<Self::Response>;
}
