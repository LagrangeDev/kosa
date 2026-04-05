use bytes::Bytes;
use kosa_proto::service::highway::v2::{FileInfo, IndexNode, MsgInfo};
use prost::Message;

pub fn extract_info(pb: Bytes) -> anyhow::Result<(MsgInfo, IndexNode, FileInfo)> {
    let msg_info = MsgInfo::decode(pb)?;
    let index_node = msg_info
        .msg_info_body
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Missing msg_info_body"))?
        .index
        .ok_or_else(|| anyhow::anyhow!("Message info index0 is empty"))?;
    let file_info = index_node
        .info
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Message info is empty"))?;
    Ok((msg_info, index_node, file_info))
}

#[macro_export]
macro_rules! try_parse_hash {
    ($val:expr) => {
        try_parse_hash!($val, "parse hash error")
    };
    ($val:expr, $msg:expr) => {
        hex::decode($val)?
            .try_into()
            .map_err(|e| anyhow::anyhow!("{}, raw data {:?}", $msg, e))
    };
}
