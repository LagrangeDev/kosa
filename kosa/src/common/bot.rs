use std::{
    fmt::{Debug, Formatter},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
use delegate::delegate;
#[cfg(feature = "opentelemetry")]
use opentelemetry::{InstrumentationScope, KeyValue, global, metrics::Gauge};
use tokio::{task::JoinHandle, time};
use tracing::{error, info, warn};

use crate::{
    common::{
        App, AppInfo, PacketContext, Session, Sign, cache::Cache, highway::HighWayContext,
        network::reconnect_delay,
    },
    event::{BotOffline, Dispatcher, Event, EventContext, OfflineReason, SessionExpired},
    service::ServiceContext,
};

pub struct BotBuilder {
    app_info: AppInfo,
    session: Session,
    sign_provider: Option<Box<dyn Sign>>,
    dispatcher: Dispatcher,
}

impl BotBuilder {
    fn new(app_info: AppInfo) -> Self {
        Self {
            app_info,
            session: rand::random(),
            sign_provider: None,
            dispatcher: Dispatcher::new(),
        }
    }

    pub fn session(mut self, session: Session) -> Self {
        self.session = session;
        self
    }

    pub fn sign_provider(mut self, sign: Box<dyn Sign>) -> Self {
        self.sign_provider.replace(sign);
        self
    }

    pub fn app<S: Send + Sync + 'static>(mut self, app: App<S>) -> Self {
        self.dispatcher = app.into_dispatcher();
        self
    }

    pub async fn run(self) -> anyhow::Result<Arc<Bot>> {
        let app_info = Arc::new(self.app_info);
        let session = Arc::new(self.session);
        let sign_provider = self
            .sign_provider
            .ok_or_else(|| anyhow::anyhow!("sign provider not configured"))?;
        let event = Arc::new(EventContext::new(self.dispatcher));

        let packet = PacketContext::connect_with(
            app_info.clone(),
            session.clone(),
            event.clone(),
            sign_provider,
        )
        .await?;
        let service = ServiceContext::new(1, app_info.clone(), session.clone(), packet);
        let service = Arc::new(service);
        let highway = Arc::new(HighWayContext::new(
            service.clone(),
            app_info.clone(),
            session.clone(),
        ));
        let cache = Arc::new(Cache::new(service.clone()));
        let tasks = DashMap::new();

        let service_clone = service.clone();
        let handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(10));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if let Err(e) = service_clone.heart_beat().await {
                    error!("heartbeat failed: {}", e);
                };
            }
        });
        tasks.insert("heartbeat".to_string(), handle);

        let bot = Arc::new(Bot {
            online: AtomicBool::new(false),
            session,
            cache,
            event: event.clone(),
            service,
            highway,
            tasks,
            #[cfg(feature = "opentelemetry")]
            metrics: BotMetrics::new(),
        });
        event.bind_bot(Arc::downgrade(&bot));
        bot.spawn_reconnect();
        Ok(bot)
    }
}

pub struct Bot {
    pub(crate) online: AtomicBool,
    pub(crate) session: Arc<Session>,

    pub(crate) cache: Arc<Cache>,
    pub(crate) event: Arc<EventContext>,
    pub(crate) service: Arc<ServiceContext>,
    pub(crate) highway: Arc<HighWayContext>,
    pub(crate) tasks: DashMap<String, JoinHandle<()>>,

    #[cfg(feature = "opentelemetry")]
    metrics: BotMetrics,
}

impl Debug for Bot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "bot: {}, online: {}",
            self.session.uin(),
            self.online.load(Ordering::SeqCst)
        )
    }
}

#[cfg(feature = "opentelemetry")]
#[derive(Debug)]
pub struct BotMetrics {
    online: Gauge<u64>,
}

#[cfg(feature = "opentelemetry")]
impl BotMetrics {
    fn new() -> Self {
        let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let meter = global::meter_with_scope(scope);
        let online = meter.u64_gauge("online").build();

        Self { online }
    }
}

impl Bot {
    pub fn builder(app_info: AppInfo) -> BotBuilder {
        BotBuilder::new(app_info)
    }

    pub fn set_online(
        &self,
        online: bool,
        #[cfg(feature = "opentelemetry")] reason: Option<String>,
    ) {
        self.online.store(online, Ordering::SeqCst);
        #[cfg(feature = "opentelemetry")]
        self.metrics.online.record(
            online as u64,
            &[
                KeyValue::new("uin", self.uin()),
                KeyValue::new("reason", reason.unwrap_or_default()),
            ],
        )
    }

    delegate! {
        to self.cache {
            pub fn friends(&self) -> Arc<crate::common::FriendCache>;
            pub fn groups(&self) -> Arc<crate::common::GroupCache>;
            pub async fn refresh_friends(&self) -> anyhow::Result<(usize,usize)>;
            pub async fn refresh_group_info(&self) -> anyhow::Result<usize>;
            pub async fn refresh_members(&self, group: i64) -> anyhow::Result<usize>;
        }
    }

    pub fn emit<E: Event>(&self, event: E) {
        self.event.emit(event);
    }

    fn spawn_reconnect(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let handle = tokio::spawn(reconnect_loop(weak));
        self.tasks.insert("reconnect".to_string(), handle);
    }

    pub(crate) fn abort_task(&self, name: &str) {
        if let Some((_, handle)) = self.tasks.remove(name) {
            handle.abort();
        }
    }

    fn handle_disconnect(&self) -> bool {
        let was_online = self.online.load(Ordering::SeqCst);
        if was_online {
            self.set_online(
                false,
                #[cfg(feature = "opentelemetry")]
                Some("disconnected".to_string()),
            );
            self.abort_task("sso_heartbeat");
            self.emit(BotOffline {
                reason: OfflineReason::Network,
            });
        }
        self.service.packet.fail_pending();
        was_online
    }

    async fn restore_online(&self, was_online: bool) {
        if !was_online {
            return;
        }
        if !self.can_fast_login() {
            self.emit(SessionExpired {
                msg: "session missing after reconnect".to_string(),
            });
            return;
        }
        if let Err(e) = self.online().await {
            error!(err = %e, "register after reconnect failed");
            self.emit(SessionExpired { msg: e.to_string() });
        }
    }
}

async fn reconnect_loop(weak: Weak<Bot>) {
    loop {
        let Some(bot) = weak.upgrade() else {
            return;
        };
        let closed = bot.service.packet.closed_token().await;
        drop(bot);
        closed.cancelled().await;

        let Some(bot) = weak.upgrade() else {
            return;
        };
        let was_online = bot.handle_disconnect();
        drop(bot);

        let mut attempt = 0u32;
        loop {
            time::sleep(reconnect_delay(attempt)).await;
            let Some(bot) = weak.upgrade() else {
                return;
            };
            match bot.service.packet.replace_network().await {
                Ok(()) => {
                    info!(attempt, "tcp reconnected");
                    drop(bot);
                    break;
                }
                Err(e) => {
                    warn!(err = %e, attempt, "tcp reconnect failed");
                    attempt = attempt.saturating_add(1);
                }
            }
        }

        let Some(bot) = weak.upgrade() else {
            return;
        };
        bot.restore_online(was_online).await;
    }
}

impl Drop for Bot {
    fn drop(&mut self) {
        for task in self.tasks.iter() {
            task.value().abort();
        }
        self.set_online(
            false,
            #[cfg(feature = "opentelemetry")]
            Some("exited".to_string()),
        );
    }
}
