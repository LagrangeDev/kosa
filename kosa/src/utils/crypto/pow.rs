use std::ops::{Add, Sub};

use bytes::Bytes;
use chrono::Local;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::utils::binary::{Prefix, Reader, ReaderError, Writer};

#[derive(Debug, Error)]
pub enum PowError {
    #[error(transparent)]
    Binary(#[from] ReaderError),

    #[error("calculating PoW cost too much time, maybe something wrong")]
    TooMuchTime,

    #[error("only support SHA256 PoW")]
    UnsupportedHash,
}

pub fn generate_tlv547(tlv546: &[u8]) -> Result<Bytes, PowError> {
    let mut reader = Reader::new(Bytes::copy_from_slice(tlv546));

    let version = reader.read_u8()?;
    let r#type = reader.read_u8()?;
    let hash_type = reader.read_u8()?;
    let _ok_byte = reader.read_u8()?;
    let max_index = reader.read_u16()?;
    let reserved = reader.read_bytes(2)?;

    let src = reader.read_bytes_with_prefix(Prefix::U16, false)?;
    let tgt = reader.read_bytes_with_prefix(Prefix::U16, false)?;
    let cpy = reader.read_bytes_with_prefix(Prefix::U16, false)?;

    let dst: Vec<u8>;
    let elapsed: i32;
    let ok: bool;
    let mut cnt: i32 = 0;

    let mut input_num = BigInt::from_bytes_be(Sign::Plus, src.as_ref());

    if tgt.len() == 32 {
        let start = Local::now();
        let mut hash = Sha256::digest(input_num.to_bytes_be().1).to_vec();

        while tgt.as_ref() != hash.as_slice() {
            input_num += 1;
            hash = Sha256::digest(input_num.to_bytes_be().1).to_vec();
            cnt += 1;

            if cnt > 6000000 {
                return Err(PowError::TooMuchTime);
            };
        }

        ok = true;
        dst = input_num.to_bytes_be().1;
        elapsed = Local::now().sub(start).num_seconds() as i32;
    } else {
        return Err(PowError::UnsupportedHash);
    }

    let mut writer = Writer::with_capacity(0x200);
    writer
        .write_u8(version)
        .write_u8(r#type)
        .write_u8(hash_type)
        .write_u8(if ok { 1 } else { 0 })
        .write_u16(max_index)
        .write_bytes(reserved.as_ref())
        .write_bytes_with_prefix(Prefix::U16, false, src.as_ref())
        .write_bytes_with_prefix(Prefix::U16, false, tgt.as_ref())
        .write_bytes_with_prefix(Prefix::U16, false, cpy.as_ref())
        .write_bytes_with_prefix(Prefix::U16, false, dst.as_slice())
        .write_i32(elapsed)
        .write_i32(cnt);
    let data = writer.to_bytes();
    Ok(data)
}

pub fn generate_tlv548() -> Result<Bytes, PowError> {
    let mut src: [u8; 128] = rand::random();
    src[0] = 21;

    let src_num = BigInt::from_bytes_be(Sign::Plus, &src);
    const CNT: i32 = 100;
    let dst_num = src_num.add(BigInt::from(CNT));
    let dst = dst_num.to_bytes_be().1;
    let tgt = Sha256::digest(&dst).to_vec();

    let mut tlv546_writer = Writer::with_capacity(0x200);
    tlv546_writer
        .write_u8(1)
        .write_u8(2)
        .write_u8(1)
        .write_u8(2)
        .write_u16(10)
        .write_bytes([0x00, 0x00])
        .write_bytes_with_prefix(Prefix::U16, false, src.as_slice())
        .write_bytes_with_prefix(Prefix::U16, false, tgt.as_slice());

    let cpy_data = Bytes::copy_from_slice(tlv546_writer.bytes());
    tlv546_writer.write_bytes_with_prefix(Prefix::U16, false, cpy_data.as_ref());

    generate_tlv547(tlv546_writer.bytes())
}
