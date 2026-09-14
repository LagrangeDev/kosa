use crate::event::Event;

/// 网络重连
#[derive(Debug, Clone)]
pub struct ReconnectEvent;

impl Event for ReconnectEvent {
    const NAME: &'static str = "reconnect";
}

/// 网络断开
#[derive(Debug, Clone)]
pub struct DisconnectEvent {
    pub reason: String,
}

impl Event for DisconnectEvent {
    const NAME: &'static str = "disconnect";
}
