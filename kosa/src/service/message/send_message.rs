use bytes::Bytes;
use kosa_macros::{ServiceState, command, register_service};
use kosa_proto::message::v2::{
    C2c, Grp, MessageBody, PbSendMsgReq, PbSendMsgResp, RichText, SendContentHead, SendRoutingHead,
};
use prost::Message;

use crate::{
    common::{AppInfo, Bot, Protocol, Session, entity::Scene},
    message::MessageChain,
    service::{EncryptType, Metadata, RequestType, Service, ServiceContext},
};

#[command("MessageSvc.PbSendMsg")]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct SendMessageService;

#[derive(Debug)]
pub(crate) struct SendMessageReq {
    pub(crate) scene: Scene,
    pub(crate) messages: MessageChain,

    pub(crate) sequence: i32,
    pub(crate) random: u32,
}

#[derive(Debug)]
pub(crate) struct SendMessageResp {
    pub(crate) resp: PbSendMsgResp,
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
        let elems = req.messages.encode(&req.scene)?;
        let msg_body = MessageBody {
            rich_text: Some(RichText {
                elems,
                ..Default::default()
            }),
            ..Default::default()
        };

        let routing_head = match req.scene {
            Scene::Private(uin, uid) => SendRoutingHead {
                c2c: Some(C2c {
                    peer_uin: Some(uin),
                    peer_uid: Some(uid),
                }),
                ..Default::default()
            },
            Scene::Group(group) => SendRoutingHead {
                group: Some(Grp {
                    group_uin: Some(group),
                }),
                ..Default::default()
            },
        };

        let content_head = SendContentHead {
            pkg_num: Some(1),
            pkg_index: Some(0),
            div_seq: Some(0),
            ..Default::default()
        };

        Ok(PbSendMsgReq {
            routing_head: Some(routing_head),
            content_head: Some(content_head),
            message_body: Some(msg_body),
            client_sequence: Some(req.sequence),
            random: Some(req.random),
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
        // todo 上层判断
        // let seq = if resp.client_sequence != 0 {
        //     // 私聊
        //     resp.client_sequence
        // } else {
        //     // 群聊
        //     resp.sequence
        // };
        Ok(SendMessageResp { resp })
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
            scene: Scene::Private(uin, uid),
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
            scene: Scene::Group(group),
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
