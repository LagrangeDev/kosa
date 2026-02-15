use std::collections::VecDeque;

use actix::Message as ActixMessage;
use chrono::{DateTime, TimeZone, Utc};
use kosa_proto::message::v2::Elem;

use crate::{
    event::{Broker as EB, push_message::PushMessageEvent},
    message::{BotMessage, Message, MessageChain, MessageDecode, Text},
};

#[derive(Debug, Clone, ActixMessage)]
#[rtype(result = "()")]
pub struct GroupMessageEvent {
    pub group_uin: i64,
    pub group_name: String,
    pub member_uin: i64,
    pub member_card: String,
    pub timestamp: DateTime<Utc>,
    pub message: BotMessage,
}

pub(crate) fn handle_message(event: PushMessageEvent, broker: &EB) -> anyhow::Result<()> {
    let common = event.message;
    let content_head = common.content_head.unwrap_or_default();
    let chain = if let Some(elems) = common
        .message_body
        .and_then(|message_body| message_body.rich_text)
        .map(|rich_text| rich_text.elems)
    {
        parse_elements(elems)?
    } else {
        MessageChain::default()
    };

    let message = BotMessage {
        random: content_head.random.unwrap_or_default(),
        sequence: content_head.sequence.unwrap_or_default(),
        client_sequence: content_head.client_sequence.unwrap_or_default(),
        message_id: content_head.msg_uid.unwrap_or_default(),
        messages: chain,
    };

    let routing_head = common.routing_head.unwrap_or_default();

    if let Some(group) = routing_head.group {
        let event = GroupMessageEvent {
            group_uin: group.group_code.unwrap_or_default(),
            group_name: group.group_name.unwrap_or_default(),
            member_uin: routing_head.from_uin.unwrap_or_default(),
            member_card: group.group_card.unwrap_or_default(),
            timestamp: Utc
                .timestamp_opt(content_head.time.unwrap_or_default(), 0)
                .single()
                .unwrap(),
            message,
        };
        broker.issue_async(event);
    }

    Ok(())
}

macro_rules! decode_messages {
    ($data:expr, $chain:expr, [ $($msg_type:ident),* ]) => {
        $(
            if let Some(message) = $msg_type::decode(&mut $data)? {
                $chain.push(Message::$msg_type(message));
                continue;
            }
        )*
    };
}

pub(crate) fn parse_elements(elems: Vec<Elem>) -> anyhow::Result<MessageChain> {
    let mut elems = VecDeque::from(elems);
    let mut chain = MessageChain::default();

    while !elems.is_empty() {
        decode_messages!(elems, chain, [Text]);
        // 遍历完所有消息都没有解码的情况，需要消耗一个elem，不然变成死循环
        elems.pop_front();
    }

    Ok(chain)
}
