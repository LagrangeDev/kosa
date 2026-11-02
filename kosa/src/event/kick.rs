use kosa_macros::push_handler;
use kosa_proto::service::v2::KickNtReq;
use prost::Message;

use crate::{
    common::{AppInfo, Session},
    event::{Event, EventContext, PushHandler},
    service::packet::sso_packet::SsoPacket,
};

#[derive(Debug, Clone)]
#[push_handler("trpc.qq_new_tech.status_svc.StatusService.KickNT")]
struct KickNT;

#[derive(Debug, Clone)]
pub struct KickEvent {
    pub title: String,
    pub info: String,
}
impl Event for KickEvent {
    const NAME: &'static str = "kick_nt";
}

impl PushHandler for KickNT {
    fn handle(
        packet: &SsoPacket,
        ctx: &EventContext,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<()> {
        let e = KickNtReq::decode(packet.data.as_ref())?;
        ctx.emit(KickEvent {
            title: e.tips_title.unwrap_or_default(),
            info: e.tips_info.unwrap_or_default(),
        });
        Ok(())
    }
}
