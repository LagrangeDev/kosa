use bytes::{Buf, Bytes, TryGetError};
use thiserror::Error;

use crate::utils::binary::Prefix;

#[derive(Error, Debug)]
pub enum ReaderError {
    #[error("{0}")]
    NotEnoughBytes(#[from] TryGetError),
}

pub struct Reader {
    buffer: Bytes,
}

impl Reader {
    pub fn new(data: Bytes) -> Self {
        Self { buffer: data }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn remain(&self) -> usize {
        self.buffer.remaining()
    }

    pub fn bytes(&self) -> Bytes {
        self.buffer.clone()
    }

    pub fn read_u8(&mut self) -> Result<u8, ReaderError> {
        Ok(self.buffer.try_get_u8()?)
    }

    pub fn read_i8(&mut self) -> Result<i8, ReaderError> {
        Ok(self.buffer.try_get_i8()?)
    }

    pub fn read_u16(&mut self) -> Result<u16, ReaderError> {
        Ok(self.buffer.try_get_u16()?)
    }

    pub fn read_i16(&mut self) -> Result<i16, ReaderError> {
        Ok(self.buffer.try_get_i16()?)
    }

    pub fn read_u32(&mut self) -> Result<u32, ReaderError> {
        Ok(self.buffer.try_get_u32()?)
    }

    pub fn read_i32(&mut self) -> Result<i32, ReaderError> {
        Ok(self.buffer.try_get_i32()?)
    }

    pub fn read_u64(&mut self) -> Result<u64, ReaderError> {
        Ok(self.buffer.try_get_u64()?)
    }

    pub fn read_i64(&mut self) -> Result<i64, ReaderError> {
        Ok(self.buffer.try_get_i64()?)
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<Bytes, ReaderError> {
        if len > self.buffer.remaining() {
            return Err(TryGetError {
                requested: len,
                available: self.buffer.remaining(),
            }
            .into());
        }
        Ok(self.buffer.split_to(len))
    }

    pub fn skip(&mut self, len: usize) -> Result<(), ReaderError> {
        if len > self.buffer.remaining() {
            return Err(TryGetError {
                requested: len,
                available: self.buffer.remaining(),
            }
            .into());
        }
        self.buffer.advance(len);
        Ok(())
    }

    pub fn read_bytes_with_prefix(
        &mut self,
        prefix: Prefix,
        include_prefix: bool,
    ) -> Result<Bytes, ReaderError> {
        let mut length = match prefix {
            Prefix::U8 => self.read_u8()? as usize,
            Prefix::U16 => self.read_u16()? as usize,
            Prefix::U32 => self.read_u32()? as usize,
        };
        if include_prefix {
            length -= prefix.size();
        };
        self.read_bytes(length)
    }

    pub fn read_string_with_prefix(
        &mut self,
        prefix: Prefix,
        include_prefix: bool,
    ) -> Result<String, ReaderError> {
        Ok(String::from_utf8_lossy(
            self.read_bytes_with_prefix(prefix, include_prefix)?
                .as_ref(),
        )
        .to_string())
    }
}
