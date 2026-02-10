use std::sync::{Arc, atomic::AtomicBool};

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
        })
    }
}
