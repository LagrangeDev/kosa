use std::{io, sync::Arc, time::Duration};

use actix::{
    Actor, ActorContext, ActorFutureExt, AsyncContext, Context, ContextFutureSpawner, Handler,
    Running, StreamHandler, WrapFuture,
    io::{FramedWrite, WriteHandler},
};
#[cfg(feature = "opentelemetry")]
use opentelemetry::{InstrumentationScope, global, metrics::Counter};
use tokio::{io::WriteHalf, net::TcpStream, time};
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info, trace};

use crate::{
    common::network::codec::{LengthCodec, Packet},
    utils::broker::Broker,
};

pub const DEFAULT_SERVER: &str = "msfwifi.3g.qq.com";
pub const DEFAULT_PORT: u16 = 8080;

#[cfg(feature = "opentelemetry")]
#[derive(Debug)]
struct TcpMetrics {
    tx_bytes: Counter<u64>,
    rx_bytes: Counter<u64>,
}

#[derive(Debug)]
struct DisconnectState {
    reason: &'static str,
    detail: String,
}

#[cfg(feature = "opentelemetry")]
impl TcpMetrics {
    fn new() -> Self {
        let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let meter = global::meter_with_scope(scope);
        let tx_bytes = meter.u64_counter("tx_bytes").build();
        let rx_bytes = meter.u64_counter("rx_bytes").build();
        Self { tx_bytes, rx_bytes }
    }
}

pub(crate) struct TcpClient {
    pub(crate) address: String,
    pub(crate) framed: Option<FramedWrite<Packet, WriteHalf<TcpStream>, LengthCodec>>,
    peer_addr: Option<String>,
    disconnect_state: Option<DisconnectState>,

    broker: Arc<Broker>,

    #[cfg(feature = "opentelemetry")]
    metrics: TcpMetrics,
}

impl TcpClient {
    pub(crate) fn new(address: String, broker: Arc<Broker>) -> Self {
        Self {
            address,
            framed: None,
            peer_addr: None,
            disconnect_state: None,
            broker,
            #[cfg(feature = "opentelemetry")]
            metrics: TcpMetrics::new(),
        }
    }

    fn set_disconnect_state(&mut self, reason: &'static str, detail: String) {
        self.disconnect_state = Some(DisconnectState { reason, detail });
    }

    pub(crate) fn connect(&mut self, ctx: &mut Context<Self>) {
        let addr = self.address.clone();
        async move { time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await }
            .into_actor(self)
            .map(|res, act, ctx| match res {
                Ok(stream_res) => match stream_res {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        act.peer_addr = stream.peer_addr().ok().map(|addr| addr.to_string());
                        act.disconnect_state = None;
                        info!(
                            peer_addr = act.peer_addr.as_deref().unwrap_or("unknown"),
                            "tcp connected"
                        );
                        let (r, w) = tokio::io::split(stream);
                        let reader = FramedRead::new(r, LengthCodec);
                        act.framed = Some(FramedWrite::new(w, LengthCodec, ctx));
                        ctx.add_stream(reader);
                    }
                    Err(e) => {
                        error!(
                            err = %e,
                            err_kind = ?e.kind(),
                            os_code = ?e.raw_os_error(),
                            "tcp connect error"
                        )
                    }
                },
                Err(e) => {
                    error!(err = %e, "tcp connect timeout");
                    ctx.run_later(Duration::from_secs(5), |act, ctx| {
                        act.connect(ctx);
                    });
                }
            })
            .wait(ctx)
    }
}

impl Actor for TcpClient {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.connect(ctx)
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        let reason = self.disconnect_state.take();
        info!(
            peer_addr = self.peer_addr.as_deref().unwrap_or("unknown"),
            reason = reason
                .as_ref()
                .map(|state| state.reason)
                .unwrap_or("unknown"),
            detail = reason
                .as_ref()
                .map(|state| state.detail.as_str())
                .unwrap_or("missing disconnect context"),
            "tcp disconnected"
        );
    }
}

impl StreamHandler<Result<Packet, io::Error>> for TcpClient {
    /// 收包
    fn handle(&mut self, item: Result<Packet, io::Error>, ctx: &mut Self::Context) {
        match item {
            Ok(packet) => {
                trace!("received a packet");
                #[cfg(feature = "opentelemetry")]
                self.metrics.rx_bytes.add((packet.0.len() + 4) as u64, &[]);
                self.broker.issue_async(packet)
            }
            Err(e) => {
                let detail = format!(
                    "kind={:?}, os_code={:?}, err={}",
                    e.kind(),
                    e.raw_os_error(),
                    e
                );
                self.set_disconnect_state("read_error", detail);
                error!(
                    peer_addr = self.peer_addr.as_deref().unwrap_or("unknown"),
                    err = %e,
                    err_kind = ?e.kind(),
                    os_code = ?e.raw_os_error(),
                    "tcp read error"
                );
                ctx.stop();
            }
        }
    }

    fn finished(&mut self, ctx: &mut Self::Context) {
        self.set_disconnect_state(
            "remote_closed",
            "read stream finished (peer likely closed the connection)".to_string(),
        );
        info!(
            peer_addr = self.peer_addr.as_deref().unwrap_or("unknown"),
            "tcp read stream finished"
        );
        ctx.stop();
    }
}

impl Handler<Packet> for TcpClient {
    type Result = ();

    /// 发包
    fn handle(&mut self, packet: Packet, _ctx: &mut Self::Context) -> Self::Result {
        match self.framed {
            None => {
                debug!("no active connection, dropped message")
            }
            Some(ref mut framed) => {
                #[cfg(feature = "opentelemetry")]
                let packet_len = packet.0.len();
                framed.write(packet);
                #[cfg(feature = "opentelemetry")]
                {
                    self.metrics.tx_bytes.add((packet_len + 4) as u64, &[])
                }
            }
        }
    }
}

impl WriteHandler<io::Error> for TcpClient {
    fn error(&mut self, err: io::Error, ctx: &mut Self::Context) -> Running {
        let detail = format!(
            "kind={:?}, os_code={:?}, err={}",
            err.kind(),
            err.raw_os_error(),
            err
        );
        self.set_disconnect_state("write_error", detail);
        error!(
            address = %self.address,
            peer_addr = self.peer_addr.as_deref().unwrap_or("unknown"),
            err = %err,
            err_kind = ?err.kind(),
            os_code = ?err.raw_os_error(),
            "tcp write error"
        );
        ctx.stop();
        Running::Stop
    }
}
