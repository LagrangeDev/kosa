use std::{
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
};

use actix::{Actor, Addr};

use crate::{
    common::{AppInfo, PacketContext, Session, Sign, SsoRequest},
    event::EventContext,
    service::{Metadata, ServiceRequest, packet::sso_packet::SsoPacket},
};

#[derive(Debug)]
pub(crate) struct ServiceContext {
    pub(crate) app_info: Arc<AppInfo>,
    pub(crate) session: Arc<Session>,
    pub(crate) sequence: AtomicI32,
    pub(crate) packet: Addr<PacketContext>,
}

impl ServiceContext {
    pub(crate) fn new(
        seq: i32,
        app_info: Arc<AppInfo>,
        session: Arc<Session>,
        event: Arc<EventContext>,
        sign: Arc<dyn Sign>,
    ) -> anyhow::Result<Self> {
        let packet_context = PacketContext::new(app_info.clone(), session.clone(), event, sign)?;
        let addr = packet_context.start();

        Ok(Self {
            app_info,
            session,
            sequence: AtomicI32::new(seq),
            packet: addr,
        })
    }

    fn new_sequence(&self) -> i32 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    fn encode<S>(
        &self,
        req: S,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<(SsoPacket, &'static Metadata)>
    where
        S: ServiceRequest,
    {
        let data = S::encode(req, app_info, session)?;
        Ok((
            SsoPacket {
                command: S::COMMAND.to_string(),
                data,
                sequence: self.new_sequence(),
                ..Default::default()
            },
            &S::METADATA,
        ))
    }

    fn decode<S>(
        &self,
        packet: SsoPacket,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<S::Response>
    where
        S: ServiceRequest,
    {
        let resp = S::decode(packet.data, app_info, session)?;
        Ok(resp)
    }

    pub(crate) async fn send_request<S>(&self, req: S) -> anyhow::Result<S::Response>
    where
        S: ServiceRequest,
    {
        let (sso_packet, metadata) =
            self.encode(req, self.app_info.deref(), self.session.deref())?;
        let resp_sso_packet = self
            .packet
            .send(SsoRequest {
                sso_packet,
                metadata,
            })
            .await??;
        self.decode::<S>(resp_sso_packet, self.app_info.deref(), self.session.deref())
    }
}
