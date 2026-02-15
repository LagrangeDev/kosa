use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[cfg(feature = "telemetry")]
use opentelemetry::{InstrumentationScope, KeyValue, global, metrics::Gauge};

use crate::{
    common::{appinfo::AppInfo, cache::Cache, session::Session, sign::Sign},
    service::ServiceContext,
};

#[derive(Debug)]
pub struct Bot {
    pub(crate) online: AtomicBool,
    pub(crate) session: Arc<Session>,

    pub cache: Arc<Cache>,
    pub(crate) service: Arc<ServiceContext>,

    #[cfg(feature = "telemetry")]
    metrics: BotMetrics,
}

#[cfg(feature = "telemetry")]
#[derive(Debug)]
pub struct BotMetrics {
    online: Gauge<u64>,
}

#[cfg(feature = "telemetry")]
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
        let service = ServiceContext::new(1, app_info.clone(), session.clone(), sign).await?;
        let service = Arc::new(service);
        let cache = Arc::new(Cache::new(service.clone()));
        Ok(Self {
            online: AtomicBool::new(false),
            session,
            cache,
            service,
            #[cfg(feature = "telemetry")]
            metrics: BotMetrics::new(),
        })
    }

    pub fn set_online(&self, online: bool, #[cfg(feature = "telemetry")] reason: Option<String>) {
        self.online.store(online, Ordering::SeqCst);
        #[cfg(feature = "telemetry")]
        self.metrics.online.record(
            online as u64,
            &[KeyValue::new("reason", reason.unwrap_or_default())],
        )
    }
}
