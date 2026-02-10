mod context;
pub mod login;
pub mod message;
pub(crate) mod oidb;
pub mod packet;
pub mod system;

use std::{any::Any, fmt::Debug};

use bytes::Bytes;
pub(crate) use context::ServiceContext;
use strum::FromRepr;

use crate::{
    common::{AppInfo, Protocol, Session},
    utils::marker::CommandMarker,
};

pub(crate) struct ServiceEntry {
    pub(crate) creator: fn() -> (&'static str, Box<dyn ServiceState>),
}

inventory::collect!(ServiceEntry);

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
    D2Auth = 0x0C,
    Simple = 0x0D,
}

pub(crate) trait ServiceState: Debug + Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
}

pub(crate) trait Service<Req, Resp>:
    Default + Send + Sync + CommandMarker + ServiceState
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    const METADATA: Metadata;

    fn build(
        state: &Self,
        req: Req,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Bytes>;

    fn parse(
        state: &Self,
        data: Bytes,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Resp>;
}

pub(crate) trait OidbCommandMarker: CommandMarker {
    const COMMAND: u32;
    const SERVICE: u32;
    const RESERVED: u32 = 0;
}

pub(crate) trait OidbService<Req, Resp>:
    Default + Send + Sync + OidbCommandMarker + ServiceState
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    const SUPPORT_PROTOCOLS: Protocol;

    fn build(
        state: &Self,
        req: Req,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Bytes>;

    fn parse(
        state: &Self,
        data: Bytes,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Resp>;
}
