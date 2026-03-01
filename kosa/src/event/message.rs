use std::collections::VecDeque;

use actix::Message as ActixMessage;
use chrono::{DateTime, Utc};
use kosa_proto::{
    message::v2::{ContentHead, Elem, MessageBody},
    service::highway::v2::MsgInfo,
};
use prost::Message as PbMessage;

use crate::{
    common::entity::Scene,
    event::{Broker, push_message::PushMessageEvent},
    message::{
        BotMessage, Element, Image, MessageChain, MessageDecode, MessageDecodeCommonElem, Text,
    },
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

pub(crate) fn handle_group_message(event: PushMessageEvent, broker: &Broker) -> anyhow::Result<()> {
    let common = event.message;
    let content_head = common.content_head.unwrap_or_default();
    let routing_head = common.routing_head.unwrap_or_default();
    match routing_head.group {
        None => {
            unreachable!()
        }
        Some(ref group) => {
            let event = GroupMessageEvent {
                group_uin: group.group_code(),
                group_name: group.group_name().to_string(),
                member_uin: routing_head.from_uin(),
                member_card: group.group_card().to_string(),
                timestamp: DateTime::from_timestamp(content_head.time.unwrap_or_default(), 0)
                    .unwrap_or_default(),
                message: handle_message(
                    Scene::Group(group.group_code()),
                    content_head,
                    common.message_body.unwrap_or_default(),
                )?,
            };
            broker.issue_async(event);
            Ok(())
        }
    }
}

pub(crate) fn handle_private_message(
    event: PushMessageEvent,
    broker: &Broker,
) -> anyhow::Result<()> {
    let common = event.message;
    let content_head = common.content_head.unwrap_or_default();
    let routing_head = common.routing_head.unwrap_or_default();
    match routing_head.from_uin {
        None => {
            unreachable!()
        }
        Some(uin) => Ok(()),
    }
}

pub(crate) fn handle_message(
    scene: Scene,
    content_head: ContentHead,
    message_body: MessageBody,
) -> anyhow::Result<BotMessage> {
    let chain = if let Some(elems) = message_body.rich_text.map(|rich_text| rich_text.elems) {
        parse_elements(&scene, elems)?
    } else {
        MessageChain::default()
    };

    let message = BotMessage {
        random: content_head.random.unwrap_or_default(),
        sequence: content_head.sequence.unwrap_or_default(),
        client_sequence: content_head.client_sequence.unwrap_or_default(),
        message_id: content_head.msg_uid.unwrap_or_default(),
        scene,
        messages: chain,
    };

    Ok(message)
}

macro_rules! decode_messages {
    ($source:expr, $data:expr, $chain:expr, [ $($msg_type:ident),* ], [ $($msg_type_common_elem:ident),* ]) => {
        while let Some(elem) = $data.pop_front() {
            if let Some((Some(service_type), Some(business_type))) = elem
                .common_elem
                .as_ref()
                .map(|c| (c.service_type, c.business_type))
            {
                let msg_info = MsgInfo::decode(
                    elem.common_elem
                        .as_ref()
                        .and_then(|common_elem| common_elem.pb_elem.clone())
                        .unwrap_or_default(),
                )?;
                match (service_type, business_type % 10) {
                    $(
                        ($msg_type_common_elem::SERVICE_TYPE, $msg_type_common_elem::CATEGORY) => {
                            if let Some(message) = $msg_type_common_elem::decode_commom_elem(msg_info, elem, &mut $data, $source)?{
                                $chain.push(Element::$msg_type_common_elem(message));
                            }
                        }
                    )*
                    (_, _) => {}
                }
                continue;
            } else {
                $(
                    if let Some(message) = $msg_type::decode(&elem, &mut $data, $source)? {
                        $chain.push(Element::$msg_type(message));
                        continue;
                    }
                )*
            };
        }
    };
}

pub(crate) fn parse_elements(scene: &Scene, elems: Vec<Elem>) -> anyhow::Result<MessageChain> {
    let mut elems = VecDeque::from(elems);
    let mut chain = MessageChain::default();

    decode_messages!(scene, elems, chain, [Text, Image], [Image]);

    Ok(chain)
}
