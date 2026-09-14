use kosa_macros::push_event;

use crate::{
    common::{AppInfo, Session},
    event::{EventContext, PushEvent, SessionExpired},
    service::packet::sso_packet::SsoPacket,
};

#[derive(Debug, Clone)]
#[push_event("")]
pub(crate) struct EmptyEvent {}

impl PushEvent for EmptyEvent {
    fn handle(
        packet: &SsoPacket,
        ctx: &EventContext,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<()> {
        #[allow(clippy::single_match)]
        match packet.ret_code {
            -10001 => ctx.emit(SessionExpired {
                msg: packet.extra.clone(),
            }),
            _ => {}
        }
        Ok(())
    }
}
