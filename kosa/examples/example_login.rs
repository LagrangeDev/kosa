use std::{sync::Arc, time::Duration};

use ahash::AHashSet;
use async_trait::async_trait;
use bytes::Bytes;
use kosa::{
    common::{AppInfo, Bot, Protocol, Session, Sig, Sign, WtLoginSdkInfo},
    event::{GroupMessageEvent, SessionUpdated},
    message::MessageChain,
    prelude::*,
    service::login::QrcodeState,
};
use kosa_proto::common::v2::SsoSecureInfo;
#[cfg(feature = "telemetry")]
use opentelemetry::{KeyValue, global};
#[cfg(feature = "telemetry")]
use opentelemetry_otlp::WithExportConfig;
#[cfg(feature = "telemetry")]
use opentelemetry_sdk::logs;
#[cfg(feature = "telemetry")]
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use serde::{Deserialize, Serialize};
use tokio::{fs, time};
use tracing::{Level, error, info};
use tracing_subscriber::fmt::time::LocalTime;
#[cfg(feature = "telemetry")]
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

#[derive(Debug)]
struct LinuxSign {
    client: reqwest::Client,
    list: AHashSet<&'static str>,
}

impl LinuxSign {
    fn new() -> Self {
        Self {
            client: reqwest::Client::default(),
            list: AHashSet::from_iter([
                "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey",
                "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess",
                "trpc.o3.report.Report.SsoReport",
                "MessageSvc.PbSendMsg",
                "wtlogin.trans_emp",
                "wtlogin.login",
                "wtlogin.exchange_emp",
                "trpc.login.ecdh.EcdhService.SsoKeyExchange",
                "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin",
                "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin",
                "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginNewDevice",
                "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLoginUnusualDevice",
                "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginUnusualDevice",
                "trpc.login.ecdh.EcdhService.SsoNTLoginRefreshTicket",
                "trpc.login.ecdh.EcdhService.SsoNTLoginRefreshA2",
                "OidbSvcTrpcTcp.0x11ec_1",
                "OidbSvcTrpcTcp.0x758_1",
                "OidbSvcTrpcTcp.0x7c1_1",
                "OidbSvcTrpcTcp.0x7c2_5",
                "OidbSvcTrpcTcp.0x10db_1",
                "OidbSvcTrpcTcp.0x8a1_7",
                "OidbSvcTrpcTcp.0x89a_0",
                "OidbSvcTrpcTcp.0x89a_15",
                "OidbSvcTrpcTcp.0x88d_0",
                "OidbSvcTrpcTcp.0x88d_14",
                "OidbSvcTrpcTcp.0x112a_1",
                "OidbSvcTrpcTcp.0x587_74",
                "OidbSvcTrpcTcp.0x1100_1",
                "OidbSvcTrpcTcp.0x1102_1",
                "OidbSvcTrpcTcp.0x1103_1",
                "OidbSvcTrpcTcp.0x1107_1",
                "OidbSvcTrpcTcp.0x1105_1",
                "OidbSvcTrpcTcp.0xf88_1",
                "OidbSvcTrpcTcp.0xf89_1",
                "OidbSvcTrpcTcp.0xf57_1",
                "OidbSvcTrpcTcp.0xf57_106",
                "OidbSvcTrpcTcp.0xf57_9",
                "OidbSvcTrpcTcp.0xf55_1",
                "OidbSvcTrpcTcp.0xf67_1",
                "OidbSvcTrpcTcp.0xf67_5",
                "OidbSvcTrpcTcp.0x6d9_4",
            ]),
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

        if msg.member_uin == self.bot.uin() {
            return;
        }
        let bot = self.bot.clone();
        let future = async move {
            if msg.message.to_string() == "114514" {
                if let Err(e) = bot
                    .send_private_message(msg.member_uin, MessageChain::new().text("1919810"))
                    .await
                {
                    error!("send_group_message error: {:?}", e)
                }
            }

            if msg.message.to_string() == "fr" {
                let (friends, _) = bot.fetch_friends().await.unwrap();
                let _ = friends
                    .iter()
                    .for_each(|(_, f)| info!("friend: {}", f.nick_name));
            };
        };
        ctx.spawn(fut::wrap_future(future));
    }
}

#[kosa::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(not(feature = "telemetry"))]
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

    #[cfg(feature = "telemetry")]
    let resource = Resource::builder()
        .with_attributes([KeyValue::new("service.name", "kosa")])
        .build();

    #[cfg(feature = "telemetry")]
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

    #[cfg(feature = "telemetry")]
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
                error!("login failed{}", err);
            }
        }
    }

    if let Err(err) = bot.online().await {
        anyhow::bail!("{}", err);
    }

    bot.cache.refresh_friends().await?;

    tokio::signal::ctrl_c().await?;
    bot.release();
    #[cfg(feature = "telemetry")]
    metrics_provider.force_flush()?;
    Ok(())
}
