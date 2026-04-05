use bytes::{Buf, Bytes};

use crate::utils::binary::Reader;

pub fn get_silk_duration(data: Bytes) -> anyhow::Result<f32> {
    let mut data = data.clone();
    if data.starts_with(&[0x02]) {
        data.advance(1)
    }
    let mut reader = Reader::new(data);
    let buf = reader.read_bytes(6)?;

    if buf.starts_with(b"#!AMR\n") {
        Ok(reader.remain() as f32 / 1607.0)
    } else if buf.starts_with(b"#!SILK") {
        let ver = reader.read_bytes(3)?;
        if !ver.starts_with(b"_V3") {
            return Err(anyhow::anyhow!(
                "unsupported silk version: {}",
                String::from_utf8_lossy(&ver)
            ));
        };
        let mut data = reader.bytes();

        let mut blks = 0;

        loop {
            let length = data.try_get_u16_le()?;
            if length == 0xffff || data.remaining() < length as usize {
                break;
            }
            blks += 1;
            data.advance(length as usize);
            if data.remaining() < 2 {
                break;
            }
        }
        Ok(blks as f32 * 0.02)
    } else {
        Err(anyhow::anyhow!("unknown audio type"))
    }
}
