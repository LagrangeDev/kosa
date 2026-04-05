use kosa_proto::service::highway::v2::Ntv2RichMediaResp;

pub(crate) fn parse_download_url(download_resp: Ntv2RichMediaResp) -> anyhow::Result<String> {
    let download = download_resp
        .download
        .ok_or_else(|| anyhow::anyhow!("download is empty"))?;

    let download_info = download
        .info
        .as_ref() // 如果后面还要用 download，这里用引用
        .ok_or_else(|| anyhow::anyhow!("download info is empty"))?;
    Ok(format!(
        "https://{domain}{path}{param}",
        domain = download_info.domain(),
        path = download_info.url_path(),
        param = download.r_key_param()
    ))
}

#[macro_export]
macro_rules! extract_index_node {
    ($val:expr) => {
        extract_index_node!($val, 0)
    };
    ($val:expr, $index:expr) => {
        $val.msg_info
            .msg_info_body
            .get($index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Missing msg_info_body at index {}", $index))?
            .index
            .ok_or_else(|| anyhow::anyhow!("Message info index is empty"))?
    };
}
