use std::{ops::Deref, path::Path, sync::Arc};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use bytes::Bytes;
use md5::{Digest, Md5};
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{common::Bot, utils::crypto::ecdh::EcdhClient};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Session {
    #[serde(skip)]
    pub(crate) p256: Arc<EcdhClient>,
    pub(crate) state: State,
    pub(crate) channel_state: ChannelState,

    pub(crate) bot_info: Arc<ArcSwap<BotInfo>>,
    pub(crate) wlogin_sigs: Arc<ArcSwap<WLoginSigs>>,

    pub(crate) guid: [u8; 16],
    pub(crate) android_id: String,
    pub(crate) qimei: String,
    pub(crate) device_name: String,
}

impl Session {
    pub fn new() -> Self {
        rand::random()
    }

    pub fn uin(&self) -> i64 {
        self.bot_info.load().uin
    }

    pub fn uid(&self) -> String {
        self.bot_info.load().uid.clone()
    }

    pub(crate) fn update_bot_info<F>(&self, f: F) -> anyhow::Result<()>
    where
        F: Fn(&mut BotInfo) -> anyhow::Result<()>,
    {
        let mut new_bot_info = (*self.bot_info.load().deref().deref()).clone();
        match f(&mut new_bot_info) {
            Ok(_) => {
                self.bot_info.store(Arc::new(new_bot_info));
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
    pub(crate) fn update_wlogin_sigs<F>(&self, f: F) -> anyhow::Result<()>
    where
        F: Fn(&mut WLoginSigs) -> anyhow::Result<()>,
    {
        let mut new_wlogin_sigs = (*self.wlogin_sigs.load().deref().deref()).clone();
        match f(&mut new_wlogin_sigs) {
            Ok(_) => {
                self.wlogin_sigs.store(Arc::new(new_wlogin_sigs));
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub fn reset(&self) {
        self.bot_info.store(Arc::new(BotInfo::default()));
        self.wlogin_sigs.store(Arc::new(WLoginSigs::default()));
    }

    pub async fn save(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let data = rmp_serde::to_vec(&self)?;
        let hash: [u8; 16] = *Md5::digest(data.as_slice()).as_ref();
        let mut ser = Vec::with_capacity(hash.len() + data.len());
        ser.extend(hash);
        ser.extend(data);
        fs::write(path, &ser).await?;
        Ok(())
    }

    pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dec = fs::read(path).await?;
        let hash = dec
            .get(..16)
            .ok_or_else(|| anyhow::Error::msg("invalid session"))?;
        let data = dec
            .get(16..)
            .ok_or_else(|| anyhow::Error::msg("invalid session"))?;
        if hash != Md5::digest(data).as_slice() {
            anyhow::bail!("invalid session");
        };
        rmp_serde::from_slice::<Self>(data).map_err(|e| anyhow::anyhow!(e))
    }
}

impl Distribution<Session> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Session {
        let android_id: [u8; 8] = rng.random();
        Session {
            guid: rng.random(),
            android_id: hex::encode(android_id),
            device_name: format!("Lagrange-{:06X}", rng.random::<u32>()),
            ..Default::default()
        }
    }
}

impl Bot {
    pub fn uin(&self) -> i64 {
        self.session.uin()
    }

    pub fn uid(&self) -> String {
        self.session.uid()
    }

    pub fn can_fast_login(&self) -> bool {
        let sigs = self.session.wlogin_sigs.load();
        !sigs.a2.is_empty() && !sigs.d2.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct BotInfo {
    pub(crate) uin: i64,
    pub(crate) uid: String,
    pub(crate) age: u8,
    pub(crate) gender: u8,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct State {
    pub(crate) tlv104: Bytes,
    pub(crate) tlv547: Bytes,
    pub(crate) tlv174: Bytes,
    pub(crate) key_exchange_session: KeyExchangeSession,
    pub(crate) cookie: String,
    pub(crate) ntlogin_phone_sig: String,
    pub(crate) ntlogin_sms_sign: String,
    pub(crate) ntlogin_get_sms_sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChannelState {
    pub(crate) sec_rand: u64,
    pub(crate) sec_uid: [u8; 32],
    pub(crate) share_key: Bytes,
    pub(crate) public_key: Bytes,
}

impl Default for ChannelState {
    fn default() -> Self {
        let public_key: Bytes =
            hex::decode("03E4024579726E7373D865732C7BF45F0AF7E5EFCBDEAEA1AE63139ABD55D4D07E")
                .unwrap()
                .into();
        let share_key: Bytes =
            hex::decode("1fe5933a761c9ee7a0a43305feae76dce50afcfca377aee388a2bb89cbbf12ae")
                .unwrap()
                .into();

        let sec_uid: [u8; 32] = rand::random();

        Self {
            sec_rand: rand::random(),
            sec_uid,
            public_key,
            share_key,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct KeyExchangeSession {
    pub(crate) ticket: Bytes,
    pub(crate) key: Bytes,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct WLoginSigs {
    pub(crate) a2: Bytes,
    pub(crate) a2_key: [u8; 16],
    pub(crate) d2: Bytes,
    pub(crate) d2_key: [u8; 16],
    pub(crate) a1: Bytes,
    pub(crate) a1_key: [u8; 16],
    pub(crate) no_pic_sig: Bytes,
    pub(crate) tgtgt_key: [u8; 16],
    pub(crate) ksid: Bytes,
    pub(crate) super_key: Bytes,
    pub(crate) st_key: [u8; 16],
    pub(crate) st_web: Bytes,
    pub(crate) st: Bytes,
    pub(crate) wt_session_ticket: Bytes,
    pub(crate) wt_session_ticket_key: [u8; 16],
    pub(crate) random_key: [u8; 16],
    pub(crate) s_key: Bytes,
    pub(crate) ps_key: AHashMap<String, String>,
}
