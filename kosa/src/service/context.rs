use std::{
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
};

use actix::{Actor, Addr};
use ahash::AHashMap;
use tracing::trace;

use crate::{
    common::{AppInfo, PacketContext, Session, Sign, SsoRequest},
    event::EventContext,
    service::{Metadata, Service, ServiceEntry, ServiceState, packet::sso_packet::SsoPacket},
};

#[derive(Debug)]
pub(crate) struct ServiceContext {
    pub(crate) app_info: Arc<AppInfo>,
    pub(crate) session: Arc<Session>,
    pub(crate) sequence: AtomicI32,
    pub(crate) services: AHashMap<&'static str, Box<dyn ServiceState>>,
    pub(crate) packet: Addr<PacketContext>,
}

impl ServiceContext {
    pub(crate) async fn new(
        seq: i32,
        app_info: Arc<AppInfo>,
        session: Arc<Session>,
        event: Arc<EventContext>,
        sign: Arc<dyn Sign>,
    ) -> anyhow::Result<Self> {
        let mut services = AHashMap::new();

        for entry in inventory::iter::<ServiceEntry> {
            let (cmd, service) = (entry.creator)();
            trace!(service = cmd, "register service");
            services.insert(cmd, service);
        }

        let packet_context =
            PacketContext::new(app_info.clone(), session.clone(), event, sign).await?;
        let addr = packet_context.start();

        Ok(Self {
            app_info,
            session,
            sequence: AtomicI32::new(seq),
            services,
            packet: addr,
        })
    }

    pub(crate) fn new_sequence(&self) -> i32 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    pub(crate) fn encode<S, Req, Resp>(
        &self,
        req: Req,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<(SsoPacket, &'static Metadata)>
    where
        S: Service<Req, Resp>,
        Req: Send + Sync + 'static,
        Resp: Send + Sync + 'static,
    {
        let cmd = S::COMMAND;
        if !S::METADATA.support_protocols.contains(app_info.protocol) {
            anyhow::bail!("service {} not support", cmd);
        }
        let state = self
            .services
            .get(cmd)
            .ok_or_else(|| anyhow::anyhow!("service {} not found", cmd))?;

        let data = S::build(
            state.as_any().downcast_ref::<S>().unwrap(),
            req,
            app_info,
            session,
        )?;

        Ok((
            SsoPacket {
                command: cmd.to_owned(),
                data,
                sequence: self.new_sequence(),
                ..Default::default()
            },
            &S::METADATA,
        ))
    }

    pub(crate) fn decode<S, Req, Resp>(
        &self,
        packet: SsoPacket,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Resp>
    where
        S: Service<Req, Resp>,
        Req: Send + Sync + 'static,
        Resp: Send + Sync + 'static,
    {
        let state = match self.services.get(packet.command.as_str()) {
            Some(svc) => svc.deref(),
            None => {
                return Err(anyhow::anyhow!("service not found: {}", packet.command));
            }
        };
        let resp = S::parse(
            state.as_any().downcast_ref::<S>().unwrap(),
            packet.data,
            app_info,
            session,
        )?;
        Ok(resp)
    }

    pub(crate) async fn send_request<S, Req, Resp>(&self, req: Req) -> anyhow::Result<Resp>
    where
        S: Service<Req, Resp>,
        Req: Send + Sync + 'static,
        Resp: Send + Sync + 'static,
    {
        let (sso_packet, metadata) =
            self.encode::<S, Req, Resp>(req, self.app_info.deref(), self.session.deref())?;
        let resp_sso_packet = self
            .packet
            .send(SsoRequest {
                sso_packet,
                metadata,
            })
            .await??;
        self.decode::<S, Req, Resp>(resp_sso_packet, self.app_info.deref(), self.session.deref())
    }
}
