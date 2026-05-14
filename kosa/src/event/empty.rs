use kosa_macros::push_event;

use crate::{
    common::{AppInfo, Session},
    event::{PushEvent, SessionExpired},
    service::packet::sso_packet::SsoPacket,
    utils::broker::Broker,
};

#[derive(Debug, Clone)]
#[push_event("")]
pub(crate) struct EmptyEvent {}

impl PushEvent for EmptyEvent {
    fn handle(
        packet: &SsoPacket,
        broker: &Broker,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<()> {
        #[allow(clippy::single_match)]
        match packet.ret_code {
            -10001 => broker.issue_async(SessionExpired {
                msg: packet.extra.clone(),
            }),
            _ => {}
        }
        Ok(())
    }
}
