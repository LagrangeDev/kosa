use bytes::Bytes;
use kosa_macros::push_event;
use kosa_proto::message::v2::{CommonMessage, MsgPush};
use prost::Message;
use strum::FromRepr;

use crate::{
    common::{AppInfo, Session},
    event::{
        PushEvent,
        message::{handle_group_message, handle_private_message},
    },
    utils::broker::Broker,
};

#[derive(Debug, Clone)]
#[push_event("trpc.msg.olpush.OlPushService.MsgPush")]
pub(crate) struct PushMessageEvent {
    pub(crate) message: CommonMessage,
}

impl PushEvent for PushMessageEvent {
    fn handle(
        data: Bytes,
        broker: &Broker,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<()> {
        let message = if let Some(common_message) = MsgPush::decode(data.clone())?.common_message {
            common_message
        } else {
            return Err(anyhow::anyhow!("push message empty"));
        };
        let content_head = &message.content_head.unwrap_or_default();

        let event = PushMessageEvent { message };

        if let Some(event_type) = PushEventType::from_repr(content_head.r#type.unwrap_or_default())
        {
            match event_type {
                PushEventType::GroupMessage => {
                    handle_group_message(event, broker)?;
                }
                PushEventType::PrivateMessage => {
                    handle_private_message(event, broker)?;
                }
                PushEventType::TempMessage => {}
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
