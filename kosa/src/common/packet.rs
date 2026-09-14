use std::{io, ops::Deref, sync::Arc, time::Duration};

use anyhow::Context;
use dashmap::DashMap;
use futures::channel::oneshot;
#[cfg(feature = "opentelemetry")]
use opentelemetry::{InstrumentationScope, KeyValue, global, metrics::Counter};
use scopeguard::defer;
use tokio::{sync::Mutex, time::timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::{
    common::{
        AppInfo, Session, Sign,
        network::{Packet, TcpClient},
    },
    event::EventContext,
    service::{Metadata, packet::sso_packet::SsoPacket},
};

#[derive(Debug)]
pub(crate) struct PacketContext {
    app_info: Arc<AppInfo>,
    session: Arc<Session>,
    event: Arc<EventContext>,
    network: Mutex<TcpClient>,

    pending: Arc<DashMap<i32, oneshot::Sender<SsoPacket>>>,
    sign: Box<dyn Sign>,
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
    pub(crate) async fn connect_with(
        app_info: Arc<AppInfo>,
        session: Arc<Session>,
        event: Arc<EventContext>,
        sign: Box<dyn Sign>,
    ) -> Result<Self, io::Error> {
        #[cfg(feature = "opentelemetry")]
        let metrics = Arc::new(PacketMetrics::new());
        let pending = Arc::new(DashMap::new());
        let tcp_client = TcpClient::connector()
            .connect(build_callback(
                session.clone(),
                app_info.clone(),
                pending.clone(),
                event.clone(),
                #[cfg(feature = "opentelemetry")]
                metrics.clone(),
            ))
            .await?;
        Ok(Self {
            app_info,
            session,
            event,
            network: Mutex::new(tcp_client),
            pending,
            sign,
            #[cfg(feature = "opentelemetry")]
            metrics,
        })
    }

    pub(crate) async fn closed_token(&self) -> CancellationToken {
        self.network.lock().await.closed()
    }

    pub(crate) fn fail_pending(&self) {
        self.pending.clear();
    }

    pub(crate) async fn replace_network(&self) -> Result<(), io::Error> {
        let client = TcpClient::connector()
            .connect(build_callback(
                self.session.clone(),
                self.app_info.clone(),
                self.pending.clone(),
                self.event.clone(),
                #[cfg(feature = "opentelemetry")]
                self.metrics.clone(),
            ))
            .await?;
        *self.network.lock().await = client;
        Ok(())
    }
}

impl PacketContext {
    pub async fn send_sso_request(
        &self,
        sso_packet: SsoPacket,
        metadata: &Metadata,
    ) -> anyhow::Result<SsoPacket> {
        #[cfg(feature = "opentelemetry")]
        let metrics = self.metrics.clone();

        let app_info = self.app_info.deref();
        let session = self.session.deref();

        let (tx, rx) = oneshot::channel();
        self.pending.insert(sso_packet.sequence, tx);
        let pending = self.pending.clone();
        defer! {
            pending.remove(&sso_packet.sequence);
        }

        let secure_info = self
            .sign
            .get_sec_sign(
                sso_packet.command.as_str(),
                sso_packet.sequence,
                sso_packet.data.clone(),
                session,
                app_info,
            )
            .await?;
        let data = sso_packet.encode(metadata, app_info, session, secure_info);
        self.network.lock().await.send(Packet(data)).await?;

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
}

fn build_callback(
    session: Arc<Session>,
    app_info: Arc<AppInfo>,
    pending: Arc<DashMap<i32, oneshot::Sender<SsoPacket>>>,
    event: Arc<EventContext>,
    #[cfg(feature = "opentelemetry")] metrics: Arc<PacketMetrics>,
) -> impl Fn(Packet) {
    move |packet: Packet| match SsoPacket::decode(packet.0, session.deref()) {
        Ok(pkt) => {
            #[cfg(feature = "opentelemetry")]
            metrics.sso_rx.add(
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
            match pending.remove(&pkt.sequence) {
                Some((_seq, sender)) => {
                    let _ = sender.send(pkt);
                }
                None => {
                    if let Err(e) = event.decode(pkt, app_info.deref(), session.deref()) {
                        error!(err = ?e, "failed to decode packet");
                    };
                }
            }
        }
        Err(e) => {
            error!(err = %e, "error decoding Sso packet");
        }
    }
}
