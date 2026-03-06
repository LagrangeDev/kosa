use std::{
    io::SeekFrom,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use arc_swap::ArcSwap;
use bytes::{BufMut, Bytes, BytesMut};
use chrono::{DateTime, Duration, Utc};
use kosa_proto::service::highway::v2::{
    DataHighwayHead, LoginSigHead, ReqDataHighwayHead, RespDataHighwayHead, SegHead,
};
use md5::{Digest, Md5};
use prost::Message;
use reqwest::{
    Client, Url,
    header::{ACCEPT_ENCODING, CONNECTION, HeaderMap, HeaderValue, USER_AGENT},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use tracing::debug;

use crate::{
    common::{AppInfo, Session},
    service::ServiceContext,
    utils::binary::Reader,
};

// 1MB
pub const BLOCK_SIZE: usize = 1024 * 1024;

struct Block<'a> {
    offset: usize,
    file_size: usize,
    md5: [u8; 16],
    file_md5: [u8; 16],
    data: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct HighWayContext {
    http_client: Client,
    service: Arc<ServiceContext>,

    session: Arc<Session>,
    app_info: Arc<AppInfo>,

    sequence: AtomicU32,
    ticket: ArcSwap<Option<(Bytes, DateTime<Utc>)>>,
    url: ArcSwap<Vec<Url>>,
}

impl HighWayContext {
    pub(crate) fn new(
        service: Arc<ServiceContext>,
        app_info: Arc<AppInfo>,
        session: Arc<Session>,
    ) -> Self {
        let headers = HeaderMap::from_iter([
            (ACCEPT_ENCODING, HeaderValue::from_static("identity")),
            (
                USER_AGENT,
                HeaderValue::from_static("Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)"),
            ),
        ]);
        let http_client = Client::builder()
            .no_proxy()
            .default_headers(headers)
            .build()
            .unwrap();
        Self {
            http_client,
            service,
            app_info,
            session,
            sequence: AtomicU32::new(1),
            ticket: ArcSwap::default(),
            url: ArcSwap::default(),
        }
    }

    fn new_sequence(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    pub(crate) async fn refresh_ticket(&self) -> anyhow::Result<()> {
        let mut resp = self.service.get_highway_ticket().await?;
        let ticket = (resp.sig_session, Utc::now());
        let url = resp
            .servers
            .remove(&1)
            .ok_or_else(|| anyhow::anyhow!("no server"))?;
        self.ticket.store(Arc::new(Some(ticket)));
        self.url.store(Arc::new(url));
        Ok(())
    }

    pub(crate) async fn upload<R: AsyncRead + AsyncSeek + Unpin>(
        &self,
        command_id: u32,
        stream: &mut R,
        file_size: usize,
        file_md5: [u8; 16],
        ext_info: Option<Bytes>,
    ) -> anyhow::Result<()> {
        let ticket = self.ticket.load();
        if ticket
            .as_ref()
            .as_ref()
            .is_none_or(|t| Utc::now() - t.1 >= Duration::hours(12))
        {
            self.refresh_ticket().await?;
            debug!("refresh highway ticket");
        }
        let url = self
            .url
            .load()
            .first()
            .ok_or_else(|| anyhow::anyhow!("no url"))?
            .clone();

        stream.seek(SeekFrom::Start(0)).await?;

        let mut buffer = Vec::with_capacity(BLOCK_SIZE);
        for offset in (0..file_size).step_by(BLOCK_SIZE) {
            buffer.clear();
            let block_size = BLOCK_SIZE.min(file_size - offset);
            buffer.resize(block_size, 0);

            let n = stream.read_exact(&mut buffer).await?;
            let chunk = &buffer[..n];
            let block_md5: [u8; 16] = *Md5::digest(chunk).as_ref();
            let block = Block {
                offset,
                file_size,
                md5: block_md5,
                file_md5,
                data: chunk,
            };
            self.upload_block(url.clone(), command_id, block, ext_info.clone())
                .await?;
        }
        Ok(())
    }

    async fn upload_block(
        &self,
        server: Url,
        command_id: u32,
        block: Block<'_>,
        ext_info: Option<Bytes>,
    ) -> anyhow::Result<()> {
        let head = self.build_head(command_id, &block, ext_info.clone())?;
        let is_end = block.offset + block.data.len() == block.file_size;
        let body_len = 1 + 1 + 4 + 4 + head.len() + block.data.len();
        let mut body = BytesMut::with_capacity(body_len);
        body.put_u8(0x28);
        body.put_u32(head.len() as u32);
        body.put_u32(block.data.len() as u32);
        body.put_slice(head.as_ref());
        body.put_slice(block.data);
        body.put_u8(0x29);

        let body = body.freeze();

        let resp = self
            .http_client
            .post(server)
            .header(CONNECTION, if !is_end { "keep-alive" } else { "close" })
            .body(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "highway upload failed, http status: {}",
                resp.status()
            ));
        }
        let data = resp.bytes().await?;
        let mut reader = Reader::new(data);

        if reader.read_u8()? != 0x28 {
            return Err(anyhow::anyhow!("invalid highway packet"));
        }
        let head_len = reader.read_i32()?;
        let body_len = reader.read_i32()?;
        let head = reader.read_bytes(head_len as usize)?;
        let _body = reader.read_bytes(body_len as usize)?;

        if reader.read_u8()? != 0x29 {
            return Err(anyhow::anyhow!("invalid highway head"));
        }
        let ret = RespDataHighwayHead::decode(head)?;
        let ret_code = ret
            .msg_seg_head
            .as_ref()
            .and_then(|seg| seg.ret_code)
            .unwrap_or_default();
        debug!(
            error_code = ret.error_code.unwrap_or_default(),
            ret_code, "highway block result"
        );
        match ret.error_code.unwrap_or_default() {
            0 => Ok(()),
            error_code => Err(anyhow::anyhow!(
                "highway block upload failed error code {}",
                error_code
            )),
        }
    }

    fn build_head(
        &self,
        command_id: u32,
        block: &Block,
        ext_info: Option<Bytes>,
    ) -> anyhow::Result<Bytes> {
        let seq = self.new_sequence();
        let head = DataHighwayHead {
            version: Some(1),
            uin: Some(self.session.uin().to_string()),
            command: Some("PicUp.DataUp".to_string()),
            seq: Some(seq),
            retry_times: Some(0),
            app_id: Some(self.app_info.app_id as u32),
            data_flag: Some(16),
            command_id: Some(command_id),
            ..Default::default()
        };
        let seg_head = SegHead {
            service_id: Some(0),
            filesize: Some(block.file_size as u64),
            data_offset: Some(block.offset as u64),
            data_length: Some(block.data.len() as u32),
            service_ticket: Some(
                self.ticket
                    .load()
                    .as_ref()
                    .as_ref()
                    .map(|t| t.0.clone())
                    .ok_or_else(|| anyhow::anyhow!("ticket empty"))?,
            ),
            md5: Some(Bytes::copy_from_slice(block.md5.as_slice())),
            file_md5: Some(Bytes::copy_from_slice(block.file_md5.as_slice())),
            cache_addr: Some(0),
            cache_port: Some(0),
            ..Default::default()
        };
        let login_head = LoginSigHead {
            uint32_login_sig_type: Some(8),
            bytes_login_sig: Some(self.session.wlogin_sigs.load().a2.clone()),
            app_id: Some(self.app_info.app_id as u32),
        };
        let highway_head = ReqDataHighwayHead {
            msg_base_head: Some(head),
            msg_seg_head: Some(seg_head),
            bytes_req_extend_info: ext_info,
            timestamp: Some(0),
            msg_login_sig_head: Some(login_head),
        };
        Ok(highway_head.encode_to_vec().into())
    }
}
