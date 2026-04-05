use std::{path::PathBuf, sync::Arc, time::Duration};

use actix::prelude::*;
use ahash::AHashSet;
use async_trait::async_trait;
use bytes::Bytes;
use kosa::{
    common::{AppInfo, Bot, DEFAULT_PC_CMD_LIST, Protocol, Session, Sig, Sign, WtLoginSdkInfo},
    event::{GroupMessageEvent, PrivateMessageEvent, SessionUpdated},
    message::{Element, LocalImage, LocalVoice, MessageChain},
    service::{login::QrcodeState, system::ReactionType},
};
use kosa_proto::common::v2::SsoSecureInfo;
#[cfg(feature = "opentelemetry")]
use opentelemetry::{KeyValue, global};
#[cfg(feature = "opentelemetry")]
use opentelemetry_otlp::WithExportConfig;
#[cfg(feature = "opentelemetry")]
use opentelemetry_sdk::logs;
#[cfg(feature = "opentelemetry")]
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use serde::{Deserialize, Serialize};
use silk_codec::{convert_audio_to_pcm, encode_silk};
use tokio::{fs, time};
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::fmt::time::LocalTime;
#[cfg(feature = "opentelemetry")]
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

struct EventSubscriber {
    bot: Arc<Bot>,
}

impl Actor for EventSubscriber {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.bot.event.subscribe_async::<Self, SessionUpdated>(ctx);
        self.bot
            .event
            .subscribe_async::<Self, GroupMessageEvent>(ctx);
        self.bot
            .event
            .subscribe_async::<Self, PrivateMessageEvent>(ctx);
    }
}

impl Handler<SessionUpdated> for EventSubscriber {
    type Result = ();
    fn handle(&mut self, msg: SessionUpdated, ctx: &mut Self::Context) {
        let future = async move {
            let _ = msg.session.save("./session.bin").await;
            println!("Handler<SessionUpdated>: uin: {}", msg.session.uin());
        };
        ctx.spawn(fut::wrap_future(future));
    }
}

impl Handler<GroupMessageEvent> for EventSubscriber {
    type Result = ();
    fn handle(&mut self, msg: GroupMessageEvent, ctx: &mut Self::Context) {
        info!(
            "Handler<BotMessageEvent>:{}: msg: {}",
            msg.member_uin, msg.message
        );

        for message in &msg.message.messages {
            match message {
                Element::Image(img) => {
                    info!("image subtype:{}", img.sub_type)
                }
                Element::SuperFace(face) => {
                    info!("SuperFace:{:?}", face)
                }
                Element::QFace(face) => {
                    info!("QFace:{:?}", face)
                }
                Element::At(at) => {
                    info!("At:{:?}", at)
                }
                _ => {}
            }
        }

        if msg.member_uin == self.bot.uin() {
            return;
        }
        let bot = self.bot.clone();
        let future = async move {
            let _ = bot
                .add_group_reaction(msg.group_uin, msg.message.sequence, 32, ReactionType::FACE)
                .await;
            time::sleep(Duration::from_secs(3)).await;
            let _ = bot
                .remove_group_reaction(msg.group_uin, msg.message.sequence, 32, ReactionType::FACE)
                .await;
            if msg.message.to_string() == "114514" {
                if let Err(e) = bot
                    .send_group_message(msg.group_uin, MessageChain::new().text("1919810"))
                    .await
                {
                    error!("send_group_message error: {:?}", e)
                }
                let groups = bot.fetch_groups().await.unwrap();
                println!("groups: {:?}", groups);
            }
            if msg.message.to_string() == "voice" {
                let wav_path = PathBuf::from("test.wav");
                let pcm_path = wav_path.with_extension("pcm");
                convert_audio_to_pcm(&wav_path, &pcm_path).unwrap();
                let pcm_data = fs::read(&pcm_path).await.unwrap();
                let silk_data = encode_silk(pcm_data, 24000, 24000, true).unwrap();
                let local_voice = LocalVoice::from_bytes(silk_data.into()).await.unwrap();
                if let Ok(voice) = bot
                    .upload_private_voice(msg.member_uin, local_voice)
                    .await
                    .inspect_err(|err| error!("upload_private_voice error: {:?}", err))
                {
                    debug!("upload_private_voice response: {:?}", voice);
                    if let Err(e) = bot
                        .send_private_message(msg.member_uin, MessageChain::new().voice(voice))
                        .await
                    {
                        error!("send_private_message error: {:?}", e)
                    }
                }
            }

            if msg.message.to_string() == "img" {
                let image = LocalImage::from_path("./test.jpg").await.unwrap();
                if let Ok(img) = bot
                    .upload_private_image(msg.member_uin, image)
                    .await
                    .inspect_err(|e| error!("upload_private_image error: {:?}", e))
                {
                    debug!("uploaded image: {:?}", img);
                    if let Err(e) = bot
                        .send_private_message(msg.member_uin, MessageChain::new().image(img))
                        .await
                    {
                        error!("send_group_message error: {:?}", e)
                    }
                } else {
                    warn!("upload failed")
                }
            }
        };
        ctx.spawn(fut::wrap_future(future));
    }
}

impl Handler<PrivateMessageEvent> for EventSubscriber {
    type Result = ();

    fn handle(&mut self, msg: PrivateMessageEvent, ctx: &mut Self::Context) -> Self::Result {
        let bot = self.bot.clone();
        info!(
            "Handler<PrivateMessageEvent>:{}: msg: {}",
            msg.uin, msg.message
        );
        let future = async move {
            for message in &msg.message.messages {
                match message {
                    Element::Image(img) => {
                        info!("image subtype:{}", img.sub_type);
                        let url_res = bot.get_private_image_download_url(msg.uin, img).await;
                        info!("url_res: {:?}", url_res);
                    }
                    Element::SuperFace(face) => {
                        info!("SuperFace:{:?}", face)
                    }
                    Element::QFace(face) => {
                        info!("QFace:{:?}", face)
                    }
                    Element::At(at) => {
                        info!("At:{:?}", at)
                    }
                    Element::Voice(voice) => {
                        info!("Voice:{:?}", voice);
                        let url_res = bot.get_private_voice_download_url(msg.uin, voice).await;
                        info!("url_res: {:?}", url_res);
                    }
                    _ => {}
                }
            }
        };

        ctx.spawn(fut::wrap_future(future));
    }
}

#[actix::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(not(feature = "opentelemetry"))]
    tracing_subscriber::fmt()
        .with_timer(LocalTime::rfc_3339())
        .with_max_level(Level::TRACE)
        .init();
    let app_info = AppInfo {
        os: "Mac".to_string(),
        vendor_os: "Darwin".to_string(),
        kernel: "mac".to_string(),
        current_version: "6.9.87-44204".to_string(),
        pt_version: "2.0.0".to_string(),
        sso_version: 23,
        package_name: "com.tencent.qq".to_string(),
        apk_signature_md5: Bytes::from_static("com.tencent.qq".as_bytes()),
        sdk_info: WtLoginSdkInfo {
            sdk_build_time: 0,
            sdk_version: "nt.wtlogin.0.0.1".to_string(),
            misc_bitmap: 12058620,
            sub_sigmap: 0,
            main_sigmap: Sig::WLOGIN_ST_WEB
                | Sig::WLOGIN_A2
                | Sig::WLOGIN_ST
                | Sig::WLOGIN_S_KEY
                | Sig::WLOGIN_V_KEY
                | Sig::WLOGIN_D2
                | Sig::WLOGIN_SID
                | Sig::WLOGIN_PS_KEY
                | Sig::WLOGIN_DA2
                | Sig::WLOGIN_PT4_TOKEN,
        },
        app_id: 1600001602,
        sub_app_id: 537336475,
        app_client_version: 13172,
        protocol: Protocol::MACOS,
    };

    #[cfg(feature = "opentelemetry")]
    let resource = Resource::builder()
        .with_attributes([KeyValue::new("service.name", "kosa")])
        .build();

    #[cfg(feature = "opentelemetry")]
    let metrics_provider = {
        let metrics_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint("http://192.168.3.96:30318/v1/metrics")
            .build()?;

        let reader = PeriodicReader::builder(metrics_exporter)
            .with_interval(Duration::from_secs(10))
            .build();

        let metrics_provider = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(reader)
            .build();

        global::set_meter_provider(metrics_provider.clone());
        metrics_provider
    };

    #[cfg(feature = "opentelemetry")]
    {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_timer(LocalTime::rfc_3339()) // 使用本地时间
            .with_writer(std::io::stdout)
            .with_filter(LevelFilter::TRACE);
        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint("http://192.168.3.96:30318/v1/logs")
            .build()?;

        let log_provider = logs::SdkLoggerProvider::builder()
            .with_resource(resource.clone())
            .with_batch_exporter(log_exporter)
            .build();
        let otel_log_filter = Targets::new()
            .with_default(Level::INFO)
            .with_target("hyper_util", Level::WARN)
            .with_target("reqwest", Level::WARN)
            .with_target("opentelemetry-otlp", Level::WARN)
            .with_target("opentelemetry_sdk", Level::WARN)
            .with_target(env!("CARGO_PKG_NAME"), Level::DEBUG);
        let otel_log_layer =
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&log_provider)
                .with_filter(otel_log_filter);
        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(otel_log_layer)
            .init();
    }

    let session_path = "session.bin";
    let session = if let Ok(sess) = Session::load(session_path).await {
        sess
    } else {
        let sess: Session = rand::random();
        let _ = sess.save(session_path).await;
        sess
    };

    let bot = Arc::new(
        Bot::new(
            Arc::new(app_info),
            Arc::new(session),
            Arc::new(LinuxSign::new()),
        )
        .await?,
    );

    let event_subscriber = EventSubscriber { bot: bot.clone() };
    event_subscriber.start();

    if !bot.can_fast_login() {
        info!("login");
        let image = bot.fetch_qrcode(2).await?;
        fs::write("./qrcode.png", image.1).await?;

        loop {
            time::sleep(Duration::from_secs(1)).await;
            let state = bot.get_qrcode_result().await?;
            info!("QR code result: {:?}", state);
            if state == QrcodeState::Confirmed {
                break;
            }
        }

        match bot.qrcode_login().await {
            Ok(_) => {
                info!("login successful!");
            }
            Err(err) => {
                error!("login failed: {}", err);
            }
        }
    }

    if let Err(err) = bot.online().await {
        anyhow::bail!("{}", err);
    }

    bot.cache.refresh_friends().await?;

    tokio::signal::ctrl_c().await?;
    bot.release();
    #[cfg(feature = "opentelemetry")]
    metrics_provider.force_flush()?;
    Ok(())
}

#[derive(Debug)]
struct LinuxSign {
    client: reqwest::Client,
    list: AHashSet<&'static str>,
}

impl LinuxSign {
    fn new() -> Self {
        Self {
            client: reqwest::Client::default(),
            list: AHashSet::from_iter(DEFAULT_PC_CMD_LIST),
        }
    }
}

#[async_trait]
impl Sign for LinuxSign {
    async fn get_sec_sign(
        &self,
        _uin: i64,
        command: &str,
        seq: i32,
        body: Bytes,
    ) -> anyhow::Result<Option<SsoSecureInfo>> {
        if !self.list.contains(&command) {
            return Ok(None);
        };
        let payload = SignReq {
            cmd: command.to_owned(),
            seq,
            src: hex::encode_upper(body),
        };
        let resp: SignResp = self
            .client
            .post("http://127.0.0.1:8080/sign")
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        Ok(Some(SsoSecureInfo {
            sec_sign: Some(hex::decode(resp.sign.as_str())?.into()),
            sec_token: Some(hex::decode(resp.token.as_str())?.into()),
            sec_extra: Some(hex::decode(resp.extra.as_str())?.into()),
        }))
    }

    async fn get_energy(&self, _uin: i64, _data: &str) -> anyhow::Result<Bytes> {
        unimplemented!()
    }

    async fn get_debug_xwid(&self, _uin: i64, _data: &str) -> anyhow::Result<Bytes> {
        unimplemented!()
    }
}

#[derive(Serialize)]
struct SignReq {
    cmd: String,
    seq: i32,
    src: String,
}

#[derive(Deserialize)]
struct SignResp {
    sign: String,
    token: String,
    extra: String,
}
