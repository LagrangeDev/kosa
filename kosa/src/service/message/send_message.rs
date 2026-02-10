use bytes::Bytes;
use kosa_macros::{ServiceState, command, register_service};
use kosa_proto::message::v2::{
    C2c, Grp, MessageBody, PbSendMsgReq, PbSendMsgResp, RichText, SendContentHead, SendRoutingHead,
};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session},
    message::MessageChain,
    service::{EncryptType, Metadata, RequestType, Service, ServiceContext},
};

#[command("MessageSvc.PbSendMsg")]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct SendMessageService;

pub(crate) enum Receiver {
    /// 临时消息 uin uid
    // Temp(i64, String),
    /// 私聊 uin uid
    Friend(i64, String),
    /// 群 uin
    Group(i64),
}

pub(crate) struct SendMessageReq {
    pub(crate) receiver: Receiver,
    pub(crate) messages: MessageChain,

    pub(crate) sequence: i32,
    pub(crate) random: u32,
}

pub(crate) struct SendMessageResp {
    // pub(crate) message: BotMessage,
    pub(crate) sequence: i32,
}

#[register_service]
impl Service<SendMessageReq, SendMessageResp> for SendMessageService {
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::D2,
        request_type: RequestType::D2Auth,
        support_protocols: Protocol::all(),
    };

    fn build(
        _state: &Self,
        req: SendMessageReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        let routing_head = match req.receiver {
            Receiver::Friend(uin, uid) => SendRoutingHead {
                c2_c: Some(C2c {
                    peer_uin: uin,
                    peer_uid: uid,
                }),
                ..Default::default()
            },
            Receiver::Group(group) => SendRoutingHead {
                group: Some(Grp { group_uin: group }),
                ..Default::default()
            },
        };

        let content_head = SendContentHead {
            pkg_num: 1,
            pkg_index: 0,
            div_seq: 0,
            ..Default::default()
        };

        let elems = req.messages.encode();
        let msg_body = MessageBody {
            rich_text: Some(RichText {
                elems,
                ..Default::default()
            }),
            ..Default::default()
        };

        Ok(PbSendMsgReq {
            routing_head: Some(routing_head),
            content_head: Some(content_head),
            message_body: Some(msg_body),
            client_sequence: req.sequence,
            random: req.random,
        }
        .encode_to_vec()
        .into())
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<SendMessageResp> {
        let resp = PbSendMsgResp::decode(data)?;
        let seq = if resp.client_sequence != 0 {
            // 私聊
            resp.client_sequence
        } else {
            // 群聊
            resp.sequence
        };
        Ok(SendMessageResp { sequence: seq })
    }
}

impl ServiceContext {
    pub(crate) async fn send_private_message(
        &self,
        uin: i64,
        uid: String,
        messages: MessageChain,
    ) -> anyhow::Result<()> {
        let req = SendMessageReq {
            receiver: Receiver::Friend(uin, uid),
            messages,
            sequence: rand::random(),
            random: rand::random(),
        };
        let resp = self
            .send_request::<SendMessageService, SendMessageReq, SendMessageResp>(req)
            .await?;
        Ok(())
    }

    pub async fn send_group_message(
        &self,
        group: i64,
        messages: MessageChain,
    ) -> anyhow::Result<()> {
        let req = SendMessageReq {
            receiver: Receiver::Group(group),
            messages,
            sequence: rand::random(),
            random: rand::random(),
        };
        let resp = self
            .send_request::<SendMessageService, SendMessageReq, SendMessageResp>(req)
            .await?;
        Ok(())
    }
}

impl Bot {
    pub async fn send_private_message(
        &self,
        uin: i64,
        messages: MessageChain,
    ) -> anyhow::Result<()> {
        let uid = self
            .cache
            .get_uid(uin)
            .await
            .ok_or_else(|| anyhow::anyhow!("not found uid for {}", uin))?;
        self.service.send_private_message(uin, uid, messages).await
    }

    pub async fn send_group_message(
        &self,
        group: i64,
        messages: MessageChain,
    ) -> anyhow::Result<()> {
        self.service.send_group_message(group, messages).await
    }
}
