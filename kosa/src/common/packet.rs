use std::{io, ops::Deref, rc::Rc, sync::Arc, time::Duration};

use actix::{Actor, ActorFutureExt, Addr, Handler, Message, ResponseActFuture, WrapFuture};
use anyhow::Context;
use dashmap::DashMap;
use futures::channel::oneshot;
#[cfg(feature = "opentelemetry")]
use opentelemetry::{InstrumentationScope, KeyValue, global, metrics::Counter};
use scopeguard::defer;
use tokio::time::timeout;
use tracing::{debug, error};

use crate::{
    common::{
        AppInfo, Session, Sign,
        network::{DEFAULT_PORT, DEFAULT_SERVER, Packet, TcpClient},
    },
    event::EventContext,
    service::{Metadata, packet::sso_packet::SsoPacket},
    utils::broker::Broker,
};

#[derive(Debug)]
pub(crate) struct PacketContext {
    pub(crate) app_info: Arc<AppInfo>,
    pub(crate) session: Arc<Session>,
    pub(crate) event: Rc<EventContext>,
    pub(crate) network: Addr<TcpClient>,

    pub(crate) pending: Arc<DashMap<i32, oneshot::Sender<SsoPacket>>>,
    pub(crate) sign: Arc<dyn Sign>,
    broker: Rc<Broker>,
    #[cfg(feature = "opentelemetry")]
    metrics: Arc<PacketMetrics>,
}

#[cfg(feature = "opentelemetry")]
#[derive(Debug)]
struct PacketMetrics {
    sso_tx: Counter<u64>,
    sso_rx: Counter<u64>,
}

#[cfg(feature = "opentelemetry")]
impl PacketMetrics {
    fn new() -> Self {
        let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let meter = global::meter_with_scope(scope);
        let sso_tx = meter.u64_counter("sso_tx").build();
        let sso_rx = meter.u64_counter("sso_rx").build();
        Self { sso_tx, sso_rx }
    }
}

impl PacketContext {
    pub(crate) async fn new(
        app_info: Arc<AppInfo>,
        session: Arc<Session>,
        event: Rc<EventContext>,
        sign: Arc<dyn Sign>,
    ) -> Result<Self, io::Error> {
        let broker = Rc::new(Broker::new());
        let tcp_client = TcpClient::new(
            format!("{}:{}", DEFAULT_SERVER, DEFAULT_PORT),
            broker.clone(),
        );
        let tcp_client_addr = tcp_client.start();

        Ok(Self {
            app_info,
            session,
            event,
            network: tcp_client_addr,
            pending: Arc::new(DashMap::new()),
            sign,
            broker,
            #[cfg(feature = "opentelemetry")]
            metrics: Arc::new(PacketMetrics::new()),
        })
    }
}

impl Actor for PacketContext {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.broker.subscribe_async::<Self, Packet>(ctx);
    }
}

impl Handler<Packet> for PacketContext {
    type Result = ();

    fn handle(&mut self, msg: Packet, _ctx: &mut Self::Context) -> Self::Result {
        match SsoPacket::decode(msg.0, self.session.deref()) {
            Ok(pkt) => {
                #[cfg(feature = "opentelemetry")]
                self.metrics.sso_rx.add(
                    1,
                    &[
                        KeyValue::new("uin", self.session.uin()),
                        KeyValue::new("command", pkt.command.clone()),
                    ],
                );

                debug!(
                    command = pkt.command,
                    seq = pkt.sequence,
                    packet_len = pkt.data.len(),
                    "received packet"
                );
                match self.pending.remove(&pkt.sequence) {
                    Some((_seq, sender)) => {
                        let _ = sender.send(pkt);
                    }
                    None => {
                        if let Err(e) =
                            self.event
                                .decode(pkt, self.app_info.deref(), self.session.deref())
                        {
                            error!(err = %e, "failed to decode packet");
                        };
                    }
                }
            }
            Err(e) => {
                error!(err = %e, "error decoding Sso packet");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SsoRequest {
    pub(crate) sso_packet: SsoPacket,
    pub(crate) metadata: &'static Metadata,
}

impl Message for SsoRequest {
    type Result = anyhow::Result<SsoPacket>;
}

impl Handler<SsoRequest> for PacketContext {
    type Result = ResponseActFuture<Self, anyhow::Result<SsoPacket>>;

    fn handle(&mut self, sso_request: SsoRequest, _ctx: &mut Self::Context) -> Self::Result {
        let uin = self.session.uin();
        let app_info = self.app_info.clone();
        let session = self.session.clone();
        let tcp_cleint = self.network.clone();
        let sign = self.sign.clone();
        let pending = self.pending.clone();

        #[cfg(feature = "opentelemetry")]
        let metrics = self.metrics.clone();

        async move {
            let SsoRequest {
                sso_packet,
                metadata,
            } = sso_request;
            let (tx, rx) = oneshot::channel();
            pending.insert(sso_packet.sequence, tx);
            defer! {
                pending.remove(&sso_packet.sequence);
            }

            let secure_info = sign
                .get_sec_sign(
                    uin,
                    sso_packet.command.as_str(),
                    sso_packet.sequence,
                    sso_packet.data.clone(),
                )
                .await?;
            let data = sso_packet.encode(metadata, app_info.deref(), session.deref(), secure_info);
            tcp_cleint.send(Packet(data)).await?;

            #[cfg(feature = "opentelemetry")]
            metrics.sso_tx.add(
                1,
                &[
                    KeyValue::new("uin", uin),
                    KeyValue::new("command", sso_packet.command.clone()),
                ],
            );

            debug!(
                seq = sso_packet.sequence,
                command = sso_packet.command,
                packet_len = sso_packet.data.len(),
                "send packet"
            );

            let resp_sso_packet = timeout(Duration::from_secs(10), rx)
                .await
                .context("packet timeout")??;
            Ok(resp_sso_packet)
        }
        .into_actor(self)
        .map(|res, _act, _ctx| res)
        .boxed_local()
    }
}
