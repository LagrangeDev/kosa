use std::fmt::Debug;

use async_trait::async_trait;
use bytes::Bytes;
use kosa_proto::common::v2::SsoSecureInfo;

#[async_trait]
pub trait Sign: Debug + Send + Sync {
    async fn get_sec_sign(
        &self,
        uin: i64,
        command: &str,
        seq: i32,
        body: Bytes,
    ) -> anyhow::Result<Option<SsoSecureInfo>>;
    async fn get_energy(&self, uin: i64, data: &str) -> anyhow::Result<Bytes>;
    async fn get_debug_xwid(&self, uin: i64, data: &str) -> anyhow::Result<Bytes>;
}
