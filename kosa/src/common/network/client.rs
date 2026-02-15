use std::{io, time::Duration};

use actix::{
    Actor, ActorContext, ActorFutureExt, AsyncContext, Context, ContextFutureSpawner, Handler,
    Running, StreamHandler, WrapFuture,
    io::{FramedWrite, WriteHandler},
};
use actix_broker::{ArbiterBroker, Broker};
#[cfg(feature = "telemetry")]
use opentelemetry::{InstrumentationScope, global, metrics::Counter};
use tokio::{io::WriteHalf, net::TcpStream, time};
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info, trace};

use crate::common::network::codec::{LengthCodec, Packet};

pub const DEFAULT_SERVER: &str = "msfwifi.3g.qq.com";
pub const DEFAULT_PORT: u16 = 8080;

#[cfg(feature = "telemetry")]
#[derive(Debug)]
struct TcpMetrics {
    tx_bytes: Counter<u64>,
    rx_bytes: Counter<u64>,
}

#[cfg(feature = "telemetry")]
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

    #[cfg(feature = "telemetry")]
    metrics: TcpMetrics,
}

impl TcpClient {
    pub(crate) fn new(address: String) -> Self {
        Self {
            address,
            framed: None,
            #[cfg(feature = "telemetry")]
            metrics: TcpMetrics::new(),
        }
    }

    pub(crate) fn connect(&mut self, ctx: &mut Context<Self>) {
        let addr = self.address.clone();
        async move { time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await }
            .into_actor(self)
            .map(|res, act, ctx| match res {
                Ok(stream_res) => match stream_res {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        info!("connected to {}", stream.peer_addr().unwrap());
                        let (r, w) = tokio::io::split(stream);
                        let reader = FramedRead::new(r, LengthCodec);
                        act.framed = Some(FramedWrite::new(w, LengthCodec, ctx));
                        ctx.add_stream(reader);
                    }
                    Err(e) => error!(err = %e, "connect error"),
                },
                Err(e) => {
                    error!(err = %e, "connect timeout");
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
        info!("tcp disconnected");
    }
}

impl StreamHandler<Result<Packet, io::Error>> for TcpClient {
    /// 收包
    fn handle(&mut self, item: Result<Packet, io::Error>, ctx: &mut Self::Context) {
        match item {
            // 收包用全局broker
            Ok(packet) => {
                trace!("received a packet");
                #[cfg(feature = "telemetry")]
                self.metrics.tx_bytes.add((packet.0.len() + 4) as u64, &[]);
                Broker::<ArbiterBroker>::issue_async(packet)
            }
            Err(e) => {
                error!(err = %e, "received from server error");
                ctx.stop();
            }
        }
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
                #[cfg(feature = "telemetry")]
                let packet_len = packet.0.len();
                framed.write(packet);
                #[cfg(feature = "telemetry")]
                {
                    self.metrics.rx_bytes.add((packet_len + 4) as u64, &[])
                }
            }
        }
    }
}

impl WriteHandler<io::Error> for TcpClient {
    fn error(&mut self, err: io::Error, ctx: &mut Self::Context) -> Running {
        error!(err = %err, "tcp write error");
        ctx.stop();
        Running::Stop
    }
}
