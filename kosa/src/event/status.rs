use crate::event::Event;

#[derive(Debug, Clone)]
pub struct BotOnline;

impl Event for BotOnline {
    const NAME: &'static str = "bot_online";
}

#[derive(Debug, Clone)]
pub struct BotOffline {
    pub reason: OfflineReason,
}

impl Event for BotOffline {
    const NAME: &'static str = "bot_offline";
}

#[derive(Debug, Clone)]
pub enum OfflineReason {
    Network,
    Kick { title: String, message: String },
}
