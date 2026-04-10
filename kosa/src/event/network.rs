use actix::Message;

/// 网络重连
#[derive(Debug, Clone, Message)]
#[rtype(result = "()")]
pub struct ReconnectEvent;

/// 网络断开
#[derive(Debug, Clone, Message)]
#[rtype(result = "()")]
pub struct DisconnectEvent {
    pub reason: String,
}
