use std::{io, io::Error, time::Duration};

use futures::{SinkExt, StreamExt, stream::SplitSink};
use tokio::{net::TcpStream, sync::Mutex, task::JoinHandle, time};
use tokio_util::{codec::Framed, sync::CancellationToken};
use tracing::{error, info};

use crate::common::network::codec::{LengthCodec, Packet};

const DEFAULT_SERVER: &str = "msfwifi.3g.qq.com";
const DEFAULT_PORT: u16 = 14000;

pub(crate) struct TcpConnector {
    addr: String,
    timeout: Duration,
}

impl Default for TcpConnector {
    fn default() -> Self {
        TcpConnector {
            addr: format!("{}:{}", DEFAULT_SERVER, DEFAULT_PORT),
            timeout: Duration::from_secs(5),
        }
    }
}

impl TcpConnector {
    #[allow(unused)]
    pub(crate) fn addr(&mut self, addr: impl Into<String>) -> &mut Self {
        self.addr = addr.into();
        self
    }

    #[allow(unused)]
    pub(crate) fn timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = timeout;
        self
    }

    pub async fn connect(
        &self,
        callback: impl Fn(Packet) + Send + 'static,
    ) -> Result<TcpClient, Error> {
        let stream = match time::timeout(self.timeout, TcpStream::connect(self.addr.clone())).await
        {
            // connected
            Ok(Ok(stream)) => stream,
            // failed
            Ok(Err(e)) => {
                error!(
                    err = %e,
                    err_kind = ?e.kind(),
                    os_code = ?e.raw_os_error(),
                    "tcp connect error"
                );

                return Err(e);
            }
            // timeout
            Err(e) => {
                error!(err = %e, "tcp connect timeout");
                return Err(e.into());
            }
        };
        let _ = stream.set_nodelay(true);
        let peer_addr = stream.peer_addr().ok().map(|addr| addr.to_string());
        info!(
            peer_addr = peer_addr.as_deref().unwrap_or("unknown"),
            "tcp connected"
        );
        Ok(TcpClient::new(stream, callback))
    }
}

#[derive(Debug)]
pub(crate) struct TcpClient {
    sink: Mutex<SplitSink<Framed<TcpStream, LengthCodec>, Packet>>,
    recv_task: JoinHandle<anyhow::Result<()>>,
    cancel: CancellationToken,
}

impl Drop for TcpClient {
    fn drop(&mut self) {
        self.recv_task.abort();
    }
}

impl TcpClient {
    pub(crate) fn connector() -> TcpConnector {
        TcpConnector::default()
    }

    fn new(stream: TcpStream, callback: impl Fn(Packet) + Send + 'static) -> Self {
        let framed = Framed::new(stream, LengthCodec);
        let (sink, mut stream) = framed.split();
        let canceller = CancellationToken::new();
        let canceller_clone = canceller.clone();
        let recv_task = async move {
            loop {
                tokio::select! {
                    packet = stream.next() => {
                        match packet {
                            Some(Ok(packet)) => {
                                callback(packet);
                            }
                            Some(Err(e)) => {
                                error!(err = %e, "tcp receive error");
                                break;
                            }
                            None => {
                                info!("tcp disconnected");
                                break;
                            }
                        }
                    }

                    _ = canceller_clone.cancelled() => break,
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        let recv_task = tokio::spawn(recv_task);
        TcpClient {
            sink: Mutex::new(sink),
            recv_task,
            cancel: canceller,
        }
    }

    pub(crate) async fn send(&self, packet: Packet) -> Result<(), io::Error> {
        self.sink.lock().await.send(packet).await
    }

    pub(crate) async fn disconnect(self) {
        self.cancel.cancel();
        let _ = self.sink.lock().await.close().await;
    }
}
