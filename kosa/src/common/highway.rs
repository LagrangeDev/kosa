use std::{
    io::SeekFrom,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{TryStreamExt, stream};
use jiff::{Timestamp, ToSpan};
use kosa_proto::service::v2::{
    DataHighwayHead, LoginSigHead, ReqDataHighwayHead, RespDataHighwayHead, SegHead,
};
use md5::{Digest, Md5};
use prost::Message;
use reqwest::{
    Client, Url,
    header::{ACCEPT_ENCODING, HeaderMap, HeaderValue, USER_AGENT},
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
const MAX_UPLOAD_CONCURRENCY: usize = 5;

struct Block {
    offset: usize,
    file_size: usize,
    md5: [u8; 16],
    file_md5: [u8; 16],
    data: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct HighWayContext {
    http_client: Client,
    service: Arc<ServiceContext>,

    session: Arc<Session>,
    app_info: Arc<AppInfo>,

    sequence: AtomicU32,
    ticket: ArcSwap<Option<(Bytes, Timestamp)>>,
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
        let ticket = (resp.sig_session, Timestamp::now());
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
        data_stream: &mut R,
        file_size: usize,
        file_md5: [u8; 16],
        ext_info: Option<Bytes>,
    ) -> anyhow::Result<()> {
        let ticket = self.ticket.load();
        if ticket
            .as_ref()
            .as_ref()
            .is_none_or(|t| Timestamp::now() >= t.1 + 12.hours())
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

        data_stream.seek(SeekFrom::Start(0)).await?;

        let blocks = stream::try_unfold(
            (data_stream, 0usize),
            move |(data_stream, offset)| async move {
                if offset == file_size {
                    return Ok::<_, anyhow::Error>(None);
                }

                let block_size = BLOCK_SIZE.min(file_size - offset);
                let mut data = vec![0; block_size];
                data_stream.read_exact(&mut data).await.with_context(|| {
                    format!(
                        "highway block read failed: command_id={command_id}, offset={offset}, block_size={block_size}, file_size={file_size}"
                    )
                })?;

                Ok(Some(((offset, data), (data_stream, offset + block_size))))
            },
        );

        blocks
            .try_for_each_concurrent(MAX_UPLOAD_CONCURRENCY, |(offset, data)| {
                let url = url.clone();
                let ext_info = ext_info.clone();
                async move {
                    let block_size = data.len();
                    let block = Block {
                        offset,
                        file_size,
                        md5: *Md5::digest(&data).as_ref(),
                        file_md5,
                        data,
                    };

                    self.upload_block(url, command_id, block, ext_info)
                        .await
                        .with_context(|| {
                            format!(
                                "highway block upload failed: command_id={command_id}, offset={offset}, block_size={block_size}, file_size={file_size}"
                            )
                        })
                }
            })
            .await?;
        Ok(())
    }

    #[tracing::instrument(
        skip_all,
        fields(
            command_id,
            sequence = tracing::field::Empty,
            offset = block.offset,
            block_size = block.data.len(),
            file_size = block.file_size,
        ),
        err
    )]
    async fn upload_block(
        &self,
        server: Url,
        command_id: u32,
        block: Block,
        ext_info: Option<Bytes>,
    ) -> anyhow::Result<()> {
        let sequence = self.new_sequence();
        tracing::Span::current().record("sequence", sequence);
        debug!("highway block upload started");
        let head = self.build_head(command_id, sequence, &block, ext_info)?;
        let body_len = 1 + 1 + 4 + 4 + head.len() + block.data.len();
        let mut body = BytesMut::with_capacity(body_len);
        body.put_u8(0x28);
        body.put_u32(head.len() as u32);
        body.put_u32(block.data.len() as u32);
        body.put_slice(head.as_ref());
        body.put_slice(&block.data);
        body.put_u8(0x29);
        drop(block);

        let body = body.freeze();

        let resp = self.http_client.post(server).body(body).send().await?;

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
        sequence: u32,
        block: &Block,
        ext_info: Option<Bytes>,
    ) -> anyhow::Result<Bytes> {
        let head = DataHighwayHead {
            version: Some(1),
            uin: Some(self.session.uin().to_string()),
            command: Some("PicUp.DataUp".to_string()),
            seq: Some(sequence),
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
