use bytes::Bytes;
use kosa_proto::service::v2::Oidb;
use prost::Message;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("oidb error (code: {code}): {message}")]
pub struct OidbError {
    pub code: u32,
    pub message: String,
}

pub(crate) fn encode(command: u32, service: u32, reserved: u32, req: Bytes) -> Bytes {
    let oidb = Oidb {
        command: Some(command),
        service: Some(service),
        body: Some(req),
        reserved: Some(reserved),
        ..Default::default()
    };
    oidb.encode_to_vec().into()
}

pub(crate) fn decode(data: Bytes) -> anyhow::Result<Bytes> {
    let oidb = Oidb::decode(data)?;
    if oidb.result.unwrap_or_default() != 0 {
        anyhow::bail!(OidbError {
            code: oidb.result.unwrap_or_default(),
            message: oidb.message.unwrap_or_default(),
        })
    };
    Ok(oidb.body.unwrap_or_default())
}
