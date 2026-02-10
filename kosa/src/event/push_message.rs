use bytes::Bytes;
use kosa_macros::command;
use kosa_proto::message::v2::{CommonMessage, MsgPush};
use prost::Message;
use strum::FromRepr;

use crate::{
    common::{AppInfo, Session},
    event::{EventEntry, PushEvent, message::handle_message},
};

#[derive(Debug, Clone)]
#[command("trpc.msg.olpush.OlPushService.MsgPush")]
pub(crate) struct PushMessageEvent {
    pub(crate) message: CommonMessage,
}

inventory::submit! {
    EventEntry {
        creator: || {
            ("trpc.msg.olpush.OlPushService.MsgPush", <PushMessageEvent as PushEvent>::handle)
        }
    }
}

impl PushEvent for PushMessageEvent {
    fn handle(data: Bytes, _app_info: &AppInfo, _session: &Session) -> anyhow::Result<()> {
        let message = if let Some(common_message) = MsgPush::decode(data.clone())?.common_message {
            common_message
        } else {
            return Err(anyhow::anyhow!("push message empty"));
        };
        let content_head = &message.content_head.unwrap_or_default();

        let event = PushMessageEvent { message };

        if let Some(event_type) = PushEventType::from_repr(content_head.r#type) {
            match event_type {
                PushEventType::GroupMessage
                | PushEventType::PrivateMessage
                | PushEventType::TempMessage => {
                    handle_message(event)?;
                }
                PushEventType::GroupMemberIncreaseNotice => {}
                PushEventType::GroupMemberDecreaseNotice => {}
                PushEventType::GroupJoinNotification => {}
                PushEventType::Event0x20D => {}
                PushEventType::Event0x210 => {}
                PushEventType::Event0x2DC => {}
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, FromRepr)]
#[repr(i32)]
pub enum PushEventType {
    GroupMemberIncreaseNotice = 33,
    GroupMemberDecreaseNotice = 34,
    GroupMessage = 82,
    GroupJoinNotification = 84,
    TempMessage = 141,
    PrivateMessage = 166,
    Event0x20D = 525,
    Event0x210 = 528,
    Event0x2DC = 732,
}
