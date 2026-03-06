use std::{
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
#[cfg(feature = "opentelemetry")]
use opentelemetry::{InstrumentationScope, KeyValue, global, metrics::Gauge};
use tokio::{task::JoinHandle, time};
use tracing::error;

use crate::{
    common::{
        appinfo::AppInfo, cache::Cache, highway::HighWayContext, session::Session, sign::Sign,
    },
    event::EventContext,
    service::ServiceContext,
};

#[derive(Debug)]
pub struct Bot {
    pub(crate) online: AtomicBool,
    pub(crate) session: Arc<Session>,

    pub cache: Arc<Cache>,
    pub event: Rc<EventContext>,
    pub(crate) service: Arc<ServiceContext>,
    pub(crate) highway: Arc<HighWayContext>,
    pub(crate) tasks: DashMap<String, JoinHandle<()>>,

    #[cfg(feature = "opentelemetry")]
    metrics: BotMetrics,
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
    pub async fn new(
        app_info: Arc<AppInfo>,
        session: Arc<Session>,
        sign: Arc<dyn Sign>,
    ) -> anyhow::Result<Self> {
        let event = Rc::new(EventContext::new());
        let service =
            ServiceContext::new(1, app_info.clone(), session.clone(), event.clone(), sign).await?;
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

        Ok(Self {
            online: AtomicBool::new(false),
            session,
            cache,
            event,
            service,
            highway,
            tasks,
            #[cfg(feature = "opentelemetry")]
            metrics: BotMetrics::new(),
        })
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

    pub fn release(&self) {
        self.set_online(
            false,
            #[cfg(feature = "opentelemetry")]
            Some("exited".to_string()),
        );
    }
}
