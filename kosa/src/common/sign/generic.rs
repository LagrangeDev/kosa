use ahash::AHashSet;
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use kosa_proto::common::v2::SsoSecureInfo;
use serde::{Deserialize, Serialize};

use super::{DEFAULT_PC_CMD_LIST, Sign};
use crate::common::{AppInfo, Session};

#[derive(Debug)]
pub struct GenericSign {
    base_url: String,
    client: reqwest::Client,
    list: AHashSet<&'static str>,
}

impl GenericSign {
    pub fn new<S: Into<String>>(url: S) -> Self {
        Self {
            base_url: url.into(),
            client: reqwest::Client::default(),
            list: AHashSet::from_iter(DEFAULT_PC_CMD_LIST),
        }
    }
}

#[async_trait]
impl Sign for GenericSign {
    async fn get_sec_sign(
        &self,
        command: &str,
        seq: i32,
        body: Bytes,
        session: &Session,
        app_info: &AppInfo,
    ) -> anyhow::Result<Option<SsoSecureInfo>> {
        if !self.list.contains(&command) {
            return Ok(None);
        };
        let payload = SignReq {
            command: command.to_owned(),
            seq,
            guid: hex::encode(session.guid),
            body: hex::encode_upper(body),
            qua: app_info.qua.clone(),
        };
        let resp: SignResp = self
            .client
            .post(self.base_url.as_str())
            .json(&payload)
            .send()
            .await
            .context("sign request failed")?
            .error_for_status()?
            .json()
            .await
            .context("deserialize sign failed")?;

        if resp.code != 0 {
            return Err(anyhow::anyhow!("sign request failed: {}", resp.message));
        }
        let resp = resp.value;

        Ok(Some(SsoSecureInfo {
            sec_sign: Some(hex::decode(resp.sec_sign.as_str())?.into()),
            sec_token: Some(hex::decode(resp.sec_token.as_str())?.into()),
            sec_extra: Some(hex::decode(resp.sec_extra.as_str())?.into()),
        }))
    }
}

#[derive(Serialize)]
struct SignReq {
    command: String,
    seq: i32,
    body: String,
    guid: String,
    qua: String,
}

#[derive(Deserialize)]
struct SignResp {
    code: i32,
    message: String,
    value: SignData,
}

#[derive(Deserialize)]
struct SignData {
    sec_sign: String,
    sec_token: String,
    sec_extra: String,
}
